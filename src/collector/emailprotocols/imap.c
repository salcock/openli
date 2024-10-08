/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * OpenLI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * OpenLI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#define _GNU_SOURCE
#include <string.h>
#include <assert.h>
#include <regex.h>
#include <b64/cdecode.h>
#include <b64/cencode.h>
#include <zlib.h>

#include "email_worker.h"
#include "logger.h"

#define DECOMPRESS_BUFSIZE 65536

enum {
    OPENLI_IMAP_COMMAND_NONE = 0,
    OPENLI_IMAP_COMMAND_SERVREADY,
    OPENLI_IMAP_COMMAND_REPLY,
    OPENLI_IMAP_COMMAND_REPLY_ONGOING,
    OPENLI_IMAP_COMMAND_BYE,
    OPENLI_IMAP_COMMAND_GENERIC,
    OPENLI_IMAP_COMMAND_PREAUTH,
    OPENLI_IMAP_COMMAND_AUTH,
    OPENLI_IMAP_COMMAND_LOGOUT,
    OPENLI_IMAP_COMMAND_LOGIN,
    OPENLI_IMAP_COMMAND_IDLE,
    OPENLI_IMAP_COMMAND_APPEND,
    OPENLI_IMAP_COMMAND_ID,
    OPENLI_IMAP_COMMAND_COMPRESS,
};

typedef struct imap_cc_index {

    int cc_start;
    int cc_end;
    uint8_t dir;

} imap_cc_index_t;

typedef struct imap_comm {
    uint8_t *commbuffer;
    int commbufsize;
    int commbufused;

    char *imap_command;
    char *tag;
    char *imap_reply;
    char *params;

    imap_cc_index_t *ccs;
    int cc_used;
    int cc_alloc;

    int reply_start;
    int reply_end;
} imap_command_t;

struct compress_state {
    uint8_t *inbuffer;
    uint32_t inbufsize;
    uint32_t inwriteoffset;
    uint32_t inreadoffset;

    uint8_t *outbuffer;
    uint32_t outbufsize;
    uint32_t outreadoffset;

    z_stream stream;
};


typedef struct imapsession {

    uint8_t *contbuffer;
    size_t contbufsize;
    size_t contbufused;
    size_t contbufread;

    uint8_t *deflatebuffer;
    size_t deflatebufsize;
    size_t deflatebufused;
    size_t deflatebufread;

    imap_cc_index_t *deflate_ccs;
    int deflate_ccs_size;
    int deflate_ccs_current;

    imap_command_t *commands;
    int commands_size;

    char *auth_tag;
    char *mailbox;
    char *mail_sender;

    size_t reply_start;
    size_t next_comm_start;
    uint8_t next_command_type;
    char *next_comm_tag;
    char *next_command_name;
    char *next_command_params;

    int append_command_index;
    int idle_command_index;
    int auth_command_index;
    int auth_token_index;
    size_t auth_read_from;
    openli_email_auth_type_t auth_type;

    struct compress_state decompress_server;
    struct compress_state decompress_client;

} imap_session_t;

static void init_imap_command(imap_command_t *comm) {
    comm->commbuffer = calloc(4096, sizeof(uint8_t));
    comm->commbufsize = 4096;
    comm->commbufused = 0;
    comm->tag = NULL;
    comm->imap_reply = NULL;
    comm->imap_command = NULL;
    comm->params = NULL;

    comm->reply_start = 0;
    comm->reply_end = 0;

    comm->ccs = calloc(8, sizeof(imap_cc_index_t));
    comm->cc_used = 0;
    comm->cc_alloc = 8;
};

static inline int extend_command_buffer(imap_command_t *comm, int required) {
    while (comm->commbufsize - comm->commbufused <= required + 1) {
        comm->commbuffer = realloc(comm->commbuffer, comm->commbufsize + 4096);
        if (comm->commbuffer == NULL) {
            return -1;
        }
        comm->commbufsize += 4096;
    }
    return 0;
}

static void add_cc_to_imap_command(imap_command_t *comm, int start_ind,
        int end_ind, uint8_t dir) {

    /* dir 1 == from client (COMMAND), dir 0 == from server (RESPONSE) */
    if (comm->cc_alloc == comm->cc_used) {
        comm->ccs = realloc(comm->ccs,
            (comm->cc_alloc + 8) * sizeof(imap_cc_index_t));
        comm->cc_alloc += 8;
    }

    comm->ccs[comm->cc_used].cc_start = start_ind;
    comm->ccs[comm->cc_used].cc_end = end_ind;
    comm->ccs[comm->cc_used].dir = dir;

    comm->cc_used ++;

}

static int update_deflate_ccs(imap_session_t *imapsess, int start, int end,
        uint8_t sender) {

    imap_cc_index_t *ind;

    if (sender == OPENLI_EMAIL_PACKET_SENDER_UNKNOWN) {
        logger(LOG_INFO, "OpenLI: error -- deflated IMAP content has not been tagged with a usable direction.");
        return -1;
    }

    while (imapsess->deflate_ccs_size <= imapsess->deflate_ccs_current) {
        imapsess->deflate_ccs = realloc(imapsess->deflate_ccs,
                (imapsess->deflate_ccs_size + 5) * sizeof(imap_cc_index_t));
        imapsess->deflate_ccs_size += 5;
    }

    ind = &(imapsess->deflate_ccs[imapsess->deflate_ccs_current]);
    ind->cc_start = start;
    ind->cc_end = end;
    if (sender == OPENLI_EMAIL_PACKET_SENDER_SERVER) {
        ind->dir = 0;
    } else {
        ind->dir = 1;
    }

    imapsess->deflate_ccs_current ++;
    return 0;
}

static int extract_imap_email_sender(emailsession_t *sess,
        imap_session_t *imapsess, imap_command_t *comm) {

    int r = 0;
    char *extracted = NULL;
    char *safecopy;
    int copylen;
    char *search = (char *)(comm->commbuffer + comm->reply_start);
    char *end = (char *)(comm->commbuffer + comm->reply_end);

    copylen = (end - search) + 1;
    safecopy = calloc(sizeof(char), copylen);
    memcpy(safecopy, search, (end - search));

    r = extract_email_sender_from_body(safecopy, &extracted);

    if (r == 0 || extracted == NULL) {
        free(safecopy);
        return r;
    }

    imapsess->mail_sender = extracted;
    add_email_participant(sess, imapsess->mail_sender, 1);
    free(safecopy);

    return r;
}

static int complete_imap_append(openli_email_worker_t *state,
        emailsession_t *sess, imap_session_t *imapsess, imap_command_t *comm) {

    if (imapsess->mailbox == NULL) {
        return 1;
    }

    if (strcmp(comm->imap_reply, "OK") == 0) {
        extract_imap_email_sender(sess, imapsess, comm);
        if (imapsess->mail_sender) {
            generate_email_upload_success_iri(state, sess, imapsess->mailbox);
        }
    } else {
        generate_email_upload_failure_iri(state, sess, imapsess->mailbox);
    }

    if (imapsess->mail_sender) {
        clear_email_sender(sess);
        /* the memory is freed inside clear_email_sender()... */
        imapsess->mail_sender = NULL;
    }

    return 1;

}

static int complete_imap_fetch(openli_email_worker_t *state,
        emailsession_t *sess, imap_session_t *imapsess, imap_command_t *comm) {

    /* TODO Figure out what is actually being fetched so we can decide if this
     * is a full or partial download?
     */

    if (imapsess->mailbox == NULL) {
        return 1;
    }

    /* For now, every example I've seen for IMAP is classed as a partial
     * download and the ETSI standards are not specific on what would
     * qualify for a complete download in IMAP (maybe a "RFC822" fetch?
     * or BODY[]? )
     */

    if (strcmp(comm->imap_reply, "OK") == 0) {
        extract_imap_email_sender(sess, imapsess, comm);
        if (imapsess->mail_sender) {
            generate_email_partial_download_success_iri(state, sess,
                    imapsess->mailbox);
        }
    } else {
        generate_email_partial_download_failure_iri(state, sess,
                imapsess->mailbox);
    }

    if (imapsess->mail_sender) {
        clear_email_sender(sess);
        /* the memory is freed inside clear_email_sender()... */
        imapsess->mail_sender = NULL;
    }

    return 1;

}

static int complete_imap_authentication(openli_email_worker_t *state,
        emailsession_t *sess, imap_session_t *imapsess) {

    imap_command_t *comm;

    comm = &(imapsess->commands[imapsess->auth_command_index]);

    if (strcmp(comm->imap_reply, "OK") == 0) {
        sess->currstate = OPENLI_IMAP_STATE_AUTHENTICATED;
        /* generate login success iri */

        generate_email_login_success_iri(state, sess, imapsess->mailbox);
    } else {
        sess->currstate = OPENLI_IMAP_STATE_PRE_AUTH;

        /* generate login failure iri */
        generate_email_login_failure_iri(state, sess, imapsess->mailbox);
    }

    return 1;
}

static int generate_ccs_from_imap_command(openli_email_worker_t *state,
        emailsession_t *sess, imap_session_t *imapsess,
        imap_command_t *comm, time_t timestamp) {

    int i, len;
    uint8_t dir;

    for (i = 0; i < comm->cc_used; i++) {
        len = comm->ccs[i].cc_end - comm->ccs[i].cc_start;

        if (comm->ccs[i].dir == 1) {
            dir = ETSI_DIR_FROM_TARGET;
        } else {
            dir = ETSI_DIR_TO_TARGET;
        }

        generate_email_cc_from_imap_payload(state, sess,
                comm->commbuffer + comm->ccs[i].cc_start, len, timestamp, dir,
                0);
    }

    if (imapsess->deflate_ccs) {
        for (i = 0; i < imapsess->deflate_ccs_current; i++) {
            len = imapsess->deflate_ccs[i].cc_end -
                    imapsess->deflate_ccs[i].cc_start;
            if (len == 0) {
                continue;
            }
            if (imapsess->deflate_ccs[i].dir == 1) {
                dir = ETSI_DIR_FROM_TARGET;
            } else {
                dir = ETSI_DIR_TO_TARGET;
            }

            generate_email_cc_from_imap_payload(state, sess,
                    imapsess->deflatebuffer + imapsess->deflate_ccs[i].cc_start,
                    len, timestamp, dir, 1);
        }
        imapsess->deflate_ccs_current = 0;
    }

    return 1;
}

static int update_saved_login_command(imap_session_t *sess, int pwordindex,
        const char *sesskey) {

    int replacelen;
    imap_command_t *comm = NULL;
    uint8_t *ptr;
    const char *replacement = "XXX\r\n";

    if (sess->auth_command_index == -1) {
        logger(LOG_INFO, "OpenLI: %s missing IMAP auth command index?", sesskey);
        return -1;
    }
    comm = &(sess->commands[sess->auth_command_index]);

    if (strcmp(comm->tag, sess->auth_tag) != 0) {
        logger(LOG_INFO, "OpenLI: %s IMAP login command tags are mismatched? %s vs %s", sesskey, sess->auth_tag, comm->tag);
        return -1;
    }

    if (strcmp(comm->imap_command, "LOGIN") != 0) {
        logger(LOG_INFO, "OpenLI: %s unexpected type for saved IMAP login command: %d", sesskey, comm->imap_command);
        return -1;
    }

    if (pwordindex >= comm->commbufused) {
        logger(LOG_INFO, "OpenLI: cannot find original password token for IMAP login command %s, session %s\n", sess->auth_tag, sesskey);
        return -1;
    }
    ptr = comm->commbuffer + pwordindex;

    replacelen = strlen(replacement);
    memcpy(ptr, replacement, replacelen);
    ptr += replacelen;

    comm->commbufused = ptr - comm->commbuffer;
    comm->reply_start = comm->commbufused;
    memset(ptr, 0, comm->commbufsize - comm->commbufused);

    comm->ccs[comm->cc_used - 1].cc_end = comm->commbufused;
    return 1;

}

static int update_saved_auth_command(imap_session_t *sess, char *replace,
        const char *origtoken, const char *sesskey) {

    int replacelen;
    imap_command_t *comm = NULL;
    char *ptr;

    if (sess->auth_command_index == -1) {
        logger(LOG_INFO, "OpenLI: %s missing IMAP auth command index?", sesskey);
        return -1;
    }
    comm = &(sess->commands[sess->auth_command_index]);

    if (strcmp(comm->tag, sess->auth_tag) != 0) {
        logger(LOG_INFO, "OpenLI: %s IMAP auth command tags are mismatched? %s vs %s", sesskey, sess->auth_tag, comm->tag);
        return -1;
    }

    if (strcasecmp(comm->imap_command, "AUTHENTICATE") != 0) {
        logger(LOG_INFO, "OpenLI: %s unexpected type for saved IMAP auth command: %s", sesskey, comm->imap_command);
        return -1;
    }

    ptr = strstr((const char *)comm->commbuffer, origtoken);
    if (!ptr) {
        logger(LOG_INFO, "OpenLI: cannot find original auth token for IMAP auth command %s, session %s\n", sess->auth_tag, sesskey);
        return -1;
    }

    replacelen = strlen(replace);
    memcpy(ptr, replace, replacelen);
    ptr += replacelen;

    comm->commbufused = ((uint8_t *)ptr - comm->commbuffer);
    comm->reply_start = comm->commbufused;
    memset(ptr, 0, comm->commbufsize - comm->commbufused);

    comm->ccs[comm->cc_used - 1].cc_end = comm->commbufused;

    return 1;

}

static int save_imap_command(imap_session_t *sess) {

    int i, index;
    int comm_start;

    imap_command_t *comm = NULL;

    for (i = 0; i < sess->commands_size; i++) {
        if (sess->commands[i].imap_command == NULL) {
            comm = &(sess->commands[i]);
            index = i;
            break;
        }
    }

    if (comm == NULL) {
        sess->commands = realloc(sess->commands,
                (sess->commands_size + 5) * sizeof(imap_command_t));
        for (i = sess->commands_size; i < sess->commands_size + 5; i++) {
            init_imap_command(&(sess->commands[i]));
        }
        comm = &(sess->commands[sess->commands_size]);
        index = sess->commands_size;
        sess->commands_size += 5;
    }

    if (extend_command_buffer(comm, sess->contbufread - sess->next_comm_start)
            < 0) {
        return -1;
    }

    comm_start = comm->commbufused;
    memcpy(comm->commbuffer + comm->commbufused,
            sess->contbuffer + sess->next_comm_start,
            sess->contbufread - sess->next_comm_start);
    comm->commbufused += (sess->contbufread - sess->next_comm_start);

    comm->commbuffer[comm->commbufused] = '\0';

    add_cc_to_imap_command(comm, comm_start, comm->commbufused, 1);

    comm->reply_start = comm->commbufused;
    comm->reply_end = 0;
    comm->imap_command = sess->next_command_name;
    comm->params = sess->next_command_params;
    comm->tag = sess->next_comm_tag;


    sess->next_comm_tag = NULL;
    sess->next_command_name = NULL;
    sess->next_command_params = NULL;

    return index;
}

static int decode_login_command(emailsession_t *sess,
        imap_session_t *imapsess) {

    char *loginmsg;
    int msglen;
    char *lineend = NULL;
    char *saveptr;
    char *tag = NULL;
    char *comm = NULL;
    char *username = NULL;
    char *pword = NULL;

    msglen = imapsess->contbufread - imapsess->auth_read_from;
    loginmsg = calloc(msglen + 1, sizeof(uint8_t));

    memcpy(loginmsg, imapsess->contbuffer + imapsess->auth_read_from,
            msglen);

    lineend = strstr(loginmsg, "\r\n");
    if (lineend == NULL) {
        return 0;
    }

    tag = strtok_r(loginmsg, " ", &saveptr);
    if (!tag) {
        logger(LOG_INFO, "OpenLI: unable to derive tag from IMAP LOGIN command");
        goto loginparsefail;
    }

    comm = strtok_r(NULL, " ", &saveptr);
    if (!comm) {
        logger(LOG_INFO, "OpenLI: unable to derive command from IMAP LOGIN command");
        goto loginparsefail;
    }

    username = strtok_r(NULL,  " ", &saveptr);

    if (!username) {
        logger(LOG_INFO, "OpenLI: unable to derive username from IMAP LOGIN command");
        return -1;
    }

    pword = strtok_r(NULL,  " \r\n", &saveptr);

    if (!pword) {
        logger(LOG_INFO, "OpenLI: unable to derive password from IMAP LOGIN command");
        return -1;
    }

    if (*username == '"') {
        /* mailbox is enclosed in quotes that we need to strip */
        char *endquote = strchrnul(username + 1, '"');
        imapsess->mailbox = strndup(username + 1, endquote - (username + 1));
    } else {
        imapsess->mailbox = strdup(username);
    }

    add_email_participant(sess, imapsess->mailbox, 0);

    /* replace password with masked credentials */
    if (sess->mask_credentials) {
        update_saved_login_command(imapsess, pword - loginmsg, sess->key);
    }
    free(loginmsg);
    imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
    imapsess->next_comm_start = 0;
    imapsess->reply_start = 0;

    sess->currstate = OPENLI_IMAP_STATE_AUTH_REPLY;
    return 1;

loginparsefail:
    sess->currstate = OPENLI_IMAP_STATE_IGNORING;
    free(loginmsg);
    return -1;

}

static int decode_plain_auth_content(char *authmsg, imap_session_t *imapsess,
        emailsession_t *sess) {

    char decoded[2048];
    char reencoded[2048];
    char *ptr;
    int cnt, r;
    char *crlf;
    base64_decodestate s;

    if (*authmsg == '\0') {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
        sess->currstate = OPENLI_IMAP_STATE_AUTHENTICATING;
        return 0;
    }

    crlf = strstr(authmsg, "\r\n");
    if (crlf == NULL) {
        return 0;
    }

    /* auth plain can be split across two messages with a
     * "+" from the server in between :( */

    if (*authmsg == '+') {
        /* Client has not yet sent the auth token, so this line is
         * the server indicating that it is waiting for the token.
         * Skip the "+" line and remain in auth command state until
         * the token arrives.
         */

        imapsess->auth_read_from += ((crlf - authmsg) + 2);
        sess->server_octets += ((crlf - authmsg) + 2);
        return 0;
    }

    base64_init_decodestate(&s);
    cnt = base64_decode_block(authmsg, strlen(authmsg), decoded, &s);
    if (cnt == 0) {
        return 0;
    }
    decoded[cnt] = '\0';

    if (decoded[0] == '\0') {
        ptr = decoded + 1;
    } else {
        ptr = decoded;
    }
    /* username and password are also inside 'decoded', each term is
     * separated by null bytes (e.g. <mailbox> \0 <username> \0 <password>)
     */
    imapsess->mailbox = strdup(ptr);

    /* add "mailbox" as a recipient for this session */
    add_email_participant(sess, imapsess->mailbox, 0);

    /* replace encoded credentials, if requested by the user */
    if (sess->mask_credentials) {
        mask_plainauth_creds(imapsess->mailbox, reencoded);
        /* replace saved imap command with re-encoded auth token */
        r = update_saved_auth_command(imapsess, reencoded, authmsg, sess->key);
        if (r < 0) {
            return r;
        }

        sess->client_octets += strlen(reencoded);
    } else {
        sess->client_octets += strlen(authmsg);
    }

    sess->currstate = OPENLI_IMAP_STATE_AUTH_REPLY;
    return 1;
}

static inline char *clone_authentication_message(imap_session_t *imapsess) {

    char *authmsg;
    int msglen;

    msglen = imapsess->contbufread - imapsess->auth_read_from;
    authmsg = calloc(msglen + 1, sizeof(uint8_t));

    memcpy(authmsg, imapsess->contbuffer + imapsess->auth_read_from,
            msglen);
    return authmsg;
}

static int decode_authentication_command(emailsession_t *sess,
        imap_session_t *imapsess) {

    char *authmsg;
    int r;

    while (1) {
        /* There's no readable content in the buffer */
        if (imapsess->auth_read_from >= imapsess->contbufused) {
            imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
            imapsess->next_comm_start = 0;
            imapsess->reply_start = 0;
            return 0;
        }

        authmsg = clone_authentication_message(imapsess);

        if (imapsess->auth_type == OPENLI_EMAIL_AUTH_NONE) {
            r = get_email_authentication_type(authmsg, sess->key,
                    &(imapsess->auth_type), 1);
            if (r > 0) {
                imapsess->auth_read_from += r;
                sess->client_octets += r;
            }
            free(authmsg);
            if (r < 0) {
                sess->currstate = OPENLI_IMAP_STATE_IGNORING;
            }
            if (r <= 0) {
                break;
            }
            continue;
        }

        if (imapsess->auth_type == OPENLI_EMAIL_AUTH_PLAIN) {
            r = decode_plain_auth_content(authmsg, imapsess, sess);
            imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
            imapsess->next_comm_start = 0;
            imapsess->reply_start = 0;
            free(authmsg);
            return r;
        } else if (imapsess->auth_type == OPENLI_EMAIL_AUTH_LOGIN) {
            /* Let read_imap_while_auth_state() parse all future
             * content until we exit the AUTHENTICATING state
             */
            imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
            imapsess->next_comm_start = 0;
            imapsess->reply_start = 0;
            free(authmsg);
            return 1;
        } else if (imapsess->auth_type == OPENLI_EMAIL_AUTH_GSSAPI) {
            /* Let read_imap_while_auth_state() parse all future
             * content until we exit the AUTHENTICATING state
             */
            sess->currstate = OPENLI_IMAP_STATE_AUTHENTICATING;
            imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
            imapsess->next_comm_start = 0;
            imapsess->reply_start = 0;
            free(authmsg);
            return 1;
        } else {
            free(authmsg);
            return -1;
        }
    }

    return 1;
}

static int save_imap_reply(imap_session_t *sess, imap_command_t **comm) {

    int i;
    int comm_start;

    *comm = NULL;

    for (i = 0; i < sess->commands_size; i++) {
        if (sess->commands[i].tag == NULL) {
            continue;
        }
        if (strcmp(sess->commands[i].tag, sess->next_comm_tag) == 0) {
            (*comm) = &(sess->commands[i]);
            break;
        }
    }

    if (*comm == NULL) {
        free(sess->next_comm_tag);
        free(sess->next_command_name);
        if (sess->next_command_params) {
            free(sess->next_command_params);
        }
        sess->next_comm_tag = NULL;
        sess->next_command_name = NULL;
        sess->next_command_params = NULL;
        return 0;
    }

    if (extend_command_buffer(*comm, sess->contbufread - sess->reply_start)
            < 0) {
        return -1;
    }

    comm_start = (*comm)->commbufused;
    memcpy((*comm)->commbuffer + (*comm)->commbufused,
            sess->contbuffer + sess->reply_start,
            sess->contbufread - sess->reply_start);
    (*comm)->commbufused += (sess->contbufread - sess->reply_start);

    add_cc_to_imap_command((*comm), comm_start, (*comm)->commbufused, 0);

    (*comm)->commbuffer[(*comm)->commbufused] = '\0';
    (*comm)->reply_end = (*comm)->commbufused;
    (*comm)->imap_reply = sess->next_command_name;

    free(sess->next_comm_tag);
    if (sess->next_command_params) {
        free(sess->next_command_params);
    }
    sess->next_comm_tag = NULL;
    sess->next_command_name = NULL;
    sess->next_command_params = NULL;
    return 1;
}

static void reset_imap_saved_command(imap_command_t *comm) {

    comm->commbufused = 0;
    comm->reply_start = 0;
    comm->reply_end = 0;
    comm->cc_used = 0;

    if (comm->tag) {
        free(comm->tag);
        comm->tag = NULL;
    }
    if (comm->imap_command) {
        free(comm->imap_command);
        comm->imap_command = NULL;
    }
    if (comm->params) {
        free(comm->params);
        comm->params = NULL;
    }
    if (comm->imap_reply) {
        free(comm->imap_reply);
        comm->imap_reply = NULL;
    }
}

void free_imap_session_state(void *imapstate) {
    imap_session_t *imapsess;
    int i;

    if (imapstate == NULL) {
        return;
    }
    imapsess = (imap_session_t *)imapstate;

    for (i = 0; i < imapsess->commands_size; i++) {
        if (imapsess->commands[i].commbuffer) {
            free(imapsess->commands[i].commbuffer);
        }
        if (imapsess->commands[i].tag) {
            free(imapsess->commands[i].tag);
        }
        if (imapsess->commands[i].imap_command) {
            free(imapsess->commands[i].imap_command);
        }
        if (imapsess->commands[i].params) {
            free(imapsess->commands[i].params);
        }
        if (imapsess->commands[i].imap_reply) {
            free(imapsess->commands[i].imap_reply);
        }
        if (imapsess->commands[i].ccs) {
            free(imapsess->commands[i].ccs);
        }
    }

    if (imapsess->next_comm_tag) {
        free(imapsess->next_comm_tag);
    }
    if (imapsess->next_command_name) {
        free(imapsess->next_command_name);
    }
    if (imapsess->next_command_params) {
        free(imapsess->next_command_params);
    }

    if (imapsess->auth_tag) {
        free(imapsess->auth_tag);
    }

    /* Don't free 'mailbox' or 'mail_sender', as these are owned by the
     * participant list for the overall email session.
     */

    if (imapsess->decompress_server.outbuffer) {
        free(imapsess->decompress_server.outbuffer);
        inflateEnd(&(imapsess->decompress_server.stream));
    }
    if (imapsess->decompress_client.outbuffer) {
        free(imapsess->decompress_client.outbuffer);
        inflateEnd(&(imapsess->decompress_client.stream));
    }
    if (imapsess->decompress_server.inbuffer) {
        free(imapsess->decompress_server.inbuffer);
    }
    if (imapsess->decompress_client.inbuffer) {
        free(imapsess->decompress_client.inbuffer);
    }

    if (imapsess->deflate_ccs) {
        free(imapsess->deflate_ccs);
    }

    if (imapsess->deflatebuffer) {
        free(imapsess->deflatebuffer);
    }

    free(imapsess->commands);
    free(imapsess->contbuffer);
    free(imapsess);
}

static int _append_content_to_imap_buffer(imap_session_t *imapsess,
        uint8_t *content, uint32_t length) {
    /* +1 to account for a null terminator */
    while (imapsess->contbufsize - imapsess->contbufused <= length + 1) {
        imapsess->contbuffer = realloc(imapsess->contbuffer,
                imapsess->contbufsize + 4096);
        if (imapsess->contbuffer == NULL) {
            return -1;
        }
        imapsess->contbufsize += 4096;
    }

    memcpy(imapsess->contbuffer + imapsess->contbufused, content, length);
    imapsess->contbufused += length;
    imapsess->contbuffer[imapsess->contbufused] = '\0';

    return 0;
}

static void reset_decompress_state(imap_session_t *imapsess) {

    if (imapsess->deflatebuffer) {
        free(imapsess->deflatebuffer);
    }
    imapsess->deflatebufsize = 0;
    imapsess->deflatebufused = 0;

    if (imapsess->deflate_ccs) {
        free(imapsess->deflate_ccs);
    }
    imapsess->deflate_ccs = NULL;
    imapsess->deflate_ccs_size = 0;
    imapsess->deflate_ccs_current = 0;

    if (imapsess->decompress_server.outbuffer) {
        free(imapsess->decompress_server.outbuffer);
        imapsess->decompress_server.outbuffer = NULL;
        inflateEnd(&(imapsess->decompress_server.stream));
    }
    if (imapsess->decompress_client.outbuffer) {
        free(imapsess->decompress_client.outbuffer);
        imapsess->decompress_client.outbuffer = NULL;
        inflateEnd(&(imapsess->decompress_client.stream));
    }
    if (imapsess->decompress_server.inbuffer) {
        free(imapsess->decompress_server.inbuffer);
        imapsess->decompress_server.inbuffer = NULL;
    }
    if (imapsess->decompress_client.inbuffer) {
        free(imapsess->decompress_client.inbuffer);
        imapsess->decompress_client.inbuffer = NULL;
    }
}

static int _append_content_to_deflate_buffer(imap_session_t *imapsess,
        uint8_t *content, uint32_t length, uint8_t sender) {
    /* +1 to account for a null terminator */
    int start = imapsess->deflatebufused;
    int end = 0;

    while (imapsess->deflatebuffer == NULL ||
            imapsess->deflatebufsize - imapsess->deflatebufused <= length + 1) {
        imapsess->deflatebuffer = realloc(imapsess->deflatebuffer,
                imapsess->deflatebufsize + 4096);
        if (imapsess->deflatebuffer == NULL) {
            return -1;
        }
        imapsess->deflatebufsize += 4096;
    }

    memcpy(imapsess->deflatebuffer + imapsess->deflatebufused, content, length);
    imapsess->deflatebufused += length;
    imapsess->deflatebuffer[imapsess->deflatebufused] = '\0';

    end = imapsess->deflatebufused;

    if (update_deflate_ccs(imapsess, start, end, sender) < 0) {
        return -1;
    }

    return 0;
}

static int append_compressed_content_to_imap_buffer(imap_session_t *imapsess,
        openli_email_captured_t *cap) {

    int status;
    struct compress_state *cs = NULL;

    if (cap->pkt_sender == OPENLI_EMAIL_PACKET_SENDER_CLIENT) {
        cs = &(imapsess->decompress_client);
    } else if (cap->pkt_sender == OPENLI_EMAIL_PACKET_SENDER_SERVER) {
        cs = &(imapsess->decompress_server);
    } else {
        logger(LOG_INFO, "OpenLI: cannot decompress IMAP content without knowing which endpoint sent it -- ignoring");
        return -1;
    }

    if (cs->inbuffer == NULL) {
        cs->inbuffer = calloc(DECOMPRESS_BUFSIZE, sizeof(uint8_t));
        cs->inbufsize = DECOMPRESS_BUFSIZE;
        if (cs->inbuffer == NULL) {
            logger(LOG_INFO, "OpenLI: no memory available for append_compressed_content_to_imap_buffer");
            return -1;
        }
    }

    if (cs->outbuffer == NULL) {
        cs->outbuffer = calloc(DECOMPRESS_BUFSIZE, sizeof(uint8_t));
        cs->outbufsize = DECOMPRESS_BUFSIZE;

        if (cs->outbuffer == NULL) {
            logger(LOG_INFO, "OpenLI: no memory available for append_compressed_content_to_imap_buffer");
            return -1;
        }

        cs->stream.zalloc = Z_NULL;
        cs->stream.zfree = Z_NULL;
        cs->stream.opaque = Z_NULL;
        cs->stream.avail_in = 0;
        cs->stream.next_in = Z_NULL;

        if (inflateInit2(&cs->stream, -MAX_WBITS) != Z_OK) {
            logger(LOG_INFO, "OpenLI: inflateInit() failed inside append_compressed_content_to_imap_buffer");
            return -1;
        }
    }

    while (cap->msg_length >= cs->inbufsize - cs->inwriteoffset) {
        cs->inbuffer = realloc(cs->inbuffer,
                cs->inbufsize + DECOMPRESS_BUFSIZE);
        cs->inbufsize += DECOMPRESS_BUFSIZE;
    }

    memcpy(cs->inbuffer + cs->inwriteoffset, cap->content, cap->msg_length);
    cs->inwriteoffset += cap->msg_length;

    cs->stream.next_in = cs->inbuffer + cs->inreadoffset;
    cs->stream.avail_in = cs->inwriteoffset - cs->inreadoffset;

    do {
        if (cs->stream.avail_in == 0) {
            break;
        }

        cs->stream.next_out = cs->outbuffer + cs->outreadoffset;
        cs->stream.avail_out = cs->outbufsize - cs->outreadoffset;

        status = inflate(&cs->stream, Z_NO_FLUSH);
        switch(status) {
            case Z_NEED_DICT:
                logger(LOG_INFO, "OpenLI: Z_NEED_DICT returned by inflate() within append_compressed_content_to_imap_buffer");
                return -1;
            case Z_STREAM_ERROR:
                logger(LOG_INFO, "OpenLI: Z_STREAM_ERROR returned by inflate() within append_compressed_content_to_imap_buffer");
                return -1;
            case Z_DATA_ERROR:
                logger(LOG_INFO, "OpenLI: Z_DATA_ERROR returned by inflate() within append_compressed_content_to_imap_buffer: %s", zError(status));
                return -1;
            case Z_MEM_ERROR:
                logger(LOG_INFO, "OpenLI: Z_MEM_ERROR returned by inflate() within append_compressed_content_to_imap_buffer");
                return -1;
        }

        if (_append_content_to_imap_buffer(imapsess,
            cs->outbuffer + cs->outreadoffset,
            (cs->outbufsize - cs->outreadoffset) - cs->stream.avail_out) < 0) {
            return -1;
        }

        cs->outreadoffset +=
                ((cs->outbufsize - cs->outreadoffset) - cs->stream.avail_out);

        /* maximum distance back is 32K, so only shuffle off previous
         * decompressed output once it is more than 32KB away from
         * where we are decompressing right now.
         */
        if (cs->outreadoffset > cs->outbufsize / 2) {
            memmove(cs->outbuffer, cs->outbuffer + cs->outreadoffset,
                    cs->outbufsize - cs->outreadoffset);
            cs->outreadoffset = 0;
        }


    } while (status == Z_OK);

    cs->inreadoffset +=
            ((cs->inwriteoffset - cs->inreadoffset) - cs->stream.avail_in);
    if (cs->inwriteoffset > cs->inbufsize / 2) {
        memmove(cs->inbuffer, cs->inbuffer + cs->inreadoffset,
                cs->inwriteoffset - cs->inreadoffset);
        cs->inwriteoffset -= cs->inreadoffset;
        cs->inreadoffset = 0;
    }

    return 0;
}

static int append_content_to_imap_buffer(imap_session_t *imapsess,
        openli_email_captured_t *cap) {

    return _append_content_to_imap_buffer(imapsess, cap->content,
            cap->msg_length);
}


#define ADVANCE_ID_PTR \
        ptr = strchr(ptr, '"'); \
        if (ptr == NULL) { \
            break; \
        } \
        ptr ++; \
        if (*ptr == '\r' || *ptr == '\0') { \
            break; \
        }


static int parse_id_command(emailsession_t *sess, imap_session_t *imapsess) {
    char *ptr;
    char *comm_str = (char *)(imapsess->contbuffer + imapsess->next_comm_start);

    char *field_start, *field_end, *val_start, *val_end;
    char field_str[2048];
    char val_str[2048];

    char *server_ip, *server_port, *client_ip, *client_port;
    int ret = 0;

    ptr = strchr(comm_str, '(');
    if (!ptr) {
        return 0;
    }

    /* ID commands can contain custom field that specify the "real" server
     * and client IPs and ports for an IMAP session, i.e. in cases where
     * the IMAP session has been delivered to our collector via a proxy
     * IMAP server.
     *
     * In that situation, we want to replace the server and client addresses
     * that we saved from the original packet captures with the addresses
     * described in the ID content.
     */

    ptr ++;
    field_start = field_end = val_start = val_end = NULL;
    server_ip = client_ip = server_port = client_port = NULL;

    while (1) {
        if (*ptr == ')' || *ptr == '\r' || *ptr == '\0') {
            break;
        }

        ADVANCE_ID_PTR
        field_start = ptr;

        ADVANCE_ID_PTR
        field_end = ptr - 1;

        if (strncmp(ptr, " NIL", 4) == 0) {
            val_start = ptr + 1;
            val_end = ptr + 4;
            ptr += 4;
        } else {
            ADVANCE_ID_PTR
            val_start = ptr;
            ADVANCE_ID_PTR
            val_end = ptr - 1;
        }

        memset(field_str, 0, 2048);
        memcpy(field_str, field_start, field_end - field_start);
        memset(val_str, 0, 2048);
        memcpy(val_str, val_start, val_end - val_start);
        field_start = field_end = val_start = val_end = NULL;

        if (strcmp(field_str, "x-originating-ip") == 0) {
            client_ip = strdup(val_str);
        } else if (strcmp(field_str, "x-originating-port") == 0) {
            client_port = strdup(val_str);
        } else if (strcmp(field_str, "x-connected-ip") == 0) {
            server_ip = strdup(val_str);
        } else if (strcmp(field_str, "x-connected-port") == 0) {
            server_port = strdup(val_str);
        }

    }

    if (field_start || field_end || val_start || val_end) {
        ret = 0;
    } else {
        ret = 1;
    }

    if (server_ip && server_port) {
        replace_email_session_serveraddr(sess, server_ip, server_port);
    }

    if (client_ip && client_port) {
        replace_email_session_clientaddr(sess, client_ip, client_port);
    }

    if (server_ip) { free(server_ip); }
    if (client_ip) { free(client_ip); }
    if (server_port) { free(server_port); }
    if (client_port) { free(client_port); }

    return ret;
}

static int find_next_crlf(imap_session_t *sess, size_t start_index) {
    int regres;
    uint8_t *found = NULL;
    uint8_t *openparent = NULL;
    uint8_t *closeparent = NULL;
    uint8_t *curly = NULL;
    regmatch_t matches[1];
    regex_t regex;
    int nests = 0;
    size_t rem;

    if (regcomp(&regex, "\\{[0-9]+\\}", REG_EXTENDED) != 0) {
        logger(LOG_INFO, "OpenLI: failed to compile regex pattern for matching curly braces in IMAP content?");
        return -1;
    }

    if (sess->contbufused > start_index) {
        rem = sess->contbufused - start_index;
    } else {
        return 0;
    }

    sess->contbuffer[sess->contbufused] = '\0';
    while (1) {
        assert(nests >= 0);
        if (nests == 0) {
            openparent = (uint8_t *)memmem(sess->contbuffer + start_index, rem,
                    "(", 1);
            found = (uint8_t *)memmem(sess->contbuffer + start_index, rem,
                "\r\n", 2);

            /* No open parenthesis, just need to check if we have \r\n */
            if (openparent == NULL) {
                break;
            }

            if (found && found < openparent) {
                /* There is an open parenthesis, but it is after the next
                 * \r\n so process the line break first.
                 */
                break;
            }

            /* Open parenthesis: we cannot look for \r\n until we've seen
             * the matching close parenthesis.
             */
            nests ++;
            start_index = (openparent - sess->contbuffer) + 1;

        } else {
            openparent = (uint8_t *)memmem(sess->contbuffer + start_index, rem,
                    "(", 1);
            closeparent = (uint8_t *)memmem(sess->contbuffer + start_index, rem,
                    ")", 1);

            regres = regexec(&regex,
                    (const char *)sess->contbuffer + start_index, 1, matches,
                    0);
            if (regres == 0) {
                curly = sess->contbuffer + start_index + matches[0].rm_so;
            } else {
                curly = NULL;
            }

            found = NULL;
            if (openparent != NULL &&
                    (closeparent == NULL || openparent < closeparent) &&
                    (curly == NULL || openparent < curly)) {
                /* Next interesting token is another nested open parenthesis,
                 * so add another layer of nesting */

                nests ++;
                start_index = (openparent - sess->contbuffer) + 1;
            } else if (curly != NULL &&
                    (closeparent == NULL || curly < closeparent)
                    && (openparent == NULL || curly < openparent)) {
                /* curly braces indicate a section containing some sort
                 * of body content, and contain the length of the body
                 * inside the braces. We want to skip over the entire
                 * body and not try to parse it, because there could be
                 * parentheses and curly braces in there that will mess
                 * us up (especially if they're not balanced!).
                 */
                char *endptr = NULL;
                unsigned long toskip;
                toskip = strtoul((char *)(curly + 1), &endptr, 10);

                if (toskip >= rem) {
                    /* The whole section is not here yet, so we can't
                     * skip it until it arrives */
                    found = NULL;
                    break;
                }

                start_index = (((uint8_t *)endptr + toskip)
                        - sess->contbuffer) + 1;

            } else if (closeparent != NULL &&
                    (openparent == NULL || closeparent < openparent) &&
                    (curly == NULL || closeparent < curly)) {
                /* A close parenthesis means that our innermost nested
                 * parentheses are now balanced.
                 */
                nests --;
                start_index = (closeparent - sess->contbuffer) + 1;
            } else {
                /* None of the above tokens are present, so we must need
                 * more data to finish parsing...
                 */

                /* Nothing to do, just make sure found remains NULL */
                found = NULL;
                break;
            }
        }

        /* Always update remaining before looping again! */
        rem = sess->contbufused - start_index;
    }

    regfree(&regex);
    if (found) {
        /* +2 because we have to move past the \r\n, naturally */
        sess->contbufread = (found - sess->contbuffer) + 2;
        return 1;
    }
    return 0;
}

static int find_command_end(emailsession_t *sess, imap_session_t *imapsess) {
    int r, ind;

    r = find_next_crlf(imapsess, imapsess->next_comm_start);
    if (r == 0) {
        return 0;
    }

    ind = save_imap_command(imapsess);
    if (ind < 0) {
        return ind;
    }

    if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_AUTH) {
        sess->currstate = OPENLI_IMAP_STATE_AUTHENTICATING;
        imapsess->auth_command_index = ind;

        r = decode_authentication_command(sess, imapsess);
        return r;
        /* Don't count client octets just yet, since we could be rewriting
         * the auth tokens shortly...
         */

    } else if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_LOGIN) {

        sess->currstate = OPENLI_IMAP_STATE_AUTHENTICATING;
        imapsess->auth_command_index = ind;

        return decode_login_command(sess, imapsess);

    } else {
        sess->client_octets += (imapsess->contbufread - imapsess->next_comm_start);

    }

    /* if command was ID, update session endpoint details using
     * command content */

    if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_ID) {
        parse_id_command(sess, imapsess);
    }

    if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_LOGOUT) {
        sess->currstate = OPENLI_IMAP_STATE_LOGOUT;
    } else if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_IDLE) {
        sess->currstate = OPENLI_IMAP_STATE_IDLING;
        imapsess->idle_command_index = ind;
    } else if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_APPEND) {
        sess->currstate = OPENLI_IMAP_STATE_APPENDING;
        imapsess->append_command_index = ind;
    }

    imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
    imapsess->next_comm_start = 0;
    imapsess->reply_start = 0;

    return 1;
}

static int find_reply_end(openli_email_worker_t *state,
        emailsession_t *sess, imap_session_t *imapsess, time_t timestamp) {
    int r;
    imap_command_t *comm;

    r = find_next_crlf(imapsess, imapsess->next_comm_start);
    if (r == 0) {
        return 0;
    }
    sess->server_octets += (imapsess->contbufread - imapsess->next_comm_start);

    if ((r = save_imap_reply(imapsess, &comm)) < 0) {
        return r;
    }

    imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
    imapsess->next_comm_start = 0;
    imapsess->reply_start = 0;

    if (comm == NULL) {
        return r;
    }

    if (comm->imap_command == NULL) {
        reset_imap_saved_command(comm);
        return r;
    }

    if (strcasecmp(comm->imap_command, "LOGOUT") == 0) {
        sess->currstate = OPENLI_IMAP_STATE_SESSION_OVER;
        sess->event_time = timestamp;
        generate_email_logoff_iri(state, sess);
        generate_ccs_from_imap_command(state, sess, imapsess, comm, timestamp);
        return 0;
    } else if (strcasecmp(comm->imap_command, "AUTHENTICATE") == 0 ||
            strcasecmp(comm->imap_command, "LOGIN") == 0) {
        sess->login_time = timestamp;
        complete_imap_authentication(state, sess, imapsess);
    } else if (strcasecmp(comm->imap_command, "FETCH") == 0 ||
            strcasecmp(comm->imap_command, "UID FETCH") == 0) {

        sess->event_time = timestamp;
        complete_imap_fetch(state, sess, imapsess, comm);

    } else if (strcasecmp(comm->imap_command, "APPEND") == 0) {
        sess->event_time = timestamp;
        complete_imap_append(state, sess, imapsess, comm);
    } else if (strcasecmp(comm->imap_command, "COMPRESS") == 0) {
        /* force CCs to be generated before setting compressed state,
         * otherwise we will fail to emit the CCs for the COMPRESS
         * command itself.
         */
        generate_ccs_from_imap_command(state, sess, imapsess, comm, timestamp);
        reset_imap_saved_command(comm);
        reset_decompress_state(imapsess);
        sess->compressed = 1;
        return r;
    }

    generate_ccs_from_imap_command(state, sess, imapsess, comm, timestamp);
    reset_imap_saved_command(comm);
    return r;
}

static int find_partial_reply_end(emailsession_t *sess,
        imap_session_t *imapsess) {
    int r;

    r = find_next_crlf(imapsess, imapsess->next_comm_start);
    if (r == 0) {
        return 0;
    }
    sess->server_octets += (imapsess->contbufread - imapsess->next_comm_start);

    imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
    imapsess->next_comm_start = 0;

    return 1;
}


static int find_server_ready_end(imap_session_t *imapsess) {

    int r;

    r = find_next_crlf(imapsess, imapsess->next_comm_start);
    if (r == 0) {
        return 0;
    }

    return 1;
}

static int find_server_ready(imap_session_t *imapsess) {

    uint8_t *found = NULL;

    if (imapsess->contbufused - imapsess->contbufread < 5) {
        return 0;
    }

    found = (uint8_t *)strcasestr(
            (const char *)(imapsess->contbuffer + imapsess->contbufread),
                    "* OK ");
    if (found != NULL) {
        imapsess->next_comm_start = (found - imapsess->contbuffer);
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_SERVREADY;
        return 1;
    }
    return 0;
}

static inline int is_tagged_reply(char *msgcontent, char *searchtag) {

    char reply_cmp[2048];

    snprintf(reply_cmp, 2048, "%s OK ", searchtag);
    if (strncmp(msgcontent, reply_cmp, strlen(reply_cmp)) == 0) {
        return 1;
    }
    snprintf(reply_cmp, 2048, "%s NO ", searchtag);
    if (strncmp(msgcontent, reply_cmp, strlen(reply_cmp)) == 0) {
        return 1;
    }
    snprintf(reply_cmp, 2048, "%s BAD ", searchtag);
    if (strncmp(msgcontent, reply_cmp, strlen(reply_cmp)) == 0) {
        return 1;
    }
    return 0;
}

static int read_imap_while_appending_state(emailsession_t *sess,
        imap_session_t *imapsess) {

    char *msgstart, *firstchar;
    char *crlf = NULL;
    char *appendtag;
    imap_command_t *comm;
    int comm_start, pluslen, cc_len;
    int cc_dir = 1;

    /* XXX need some more test cases for APPEND */

    /* We have a loop here because we want to try and keep all of
     * the appended content that is in the same observed packet/message
     * in a single CC -- this loop allows us to do that easily without
     * having to maintain state outside of the scope of this function.
     */
    cc_len = 0;
    comm = &(imapsess->commands[imapsess->append_command_index]);
    appendtag = comm->tag;
    comm_start = comm->commbufused;
    firstchar = (char *)(imapsess->contbuffer + imapsess->contbufread);

    while (imapsess->contbufread < imapsess->contbufused) {
        msgstart = (char *)(imapsess->contbuffer + imapsess->contbufread);
        /* First step, find the next \r\n so we're only working with a
         * complete message */
        crlf = strstr(msgstart, "\r\n");
        if (crlf == NULL) {
            return 0;
        }

        pluslen = (crlf - msgstart) + 2;

        /* Is this the server reply to the APPEND command? */
            /* If yes, rewind to the start of the reply tag so our normal
             * processing can be applied when we return...
             */
        /* Ideally, we would use the byte count from the APPEND command to
         * keep track of when the append is over, but that is an
         * annoying amount of parsing to deal with...
         */
        if (is_tagged_reply(msgstart, appendtag)) {
            sess->currstate = OPENLI_IMAP_STATE_AUTHENTICATED;
            return 1;
        }

        if (extend_command_buffer(comm, pluslen) < 0) {
            return -1;
        }
        memcpy(comm->commbuffer + comm->commbufused, msgstart, pluslen);
        comm->commbufused += pluslen;
        comm->commbuffer[comm->commbufused] = '\0';

        /* Does this begin with a '+'? This is from the server */
        if (*firstchar == '+' && msgstart == firstchar) {
            sess->server_octets += pluslen;
            cc_dir = 0;
        } else {
            /* Otherwise, this is message content from the client */
            sess->client_octets += pluslen;
        }

        /* Advance read pointer to the next line */
        cc_len += pluslen;
        imapsess->contbufread += pluslen;
    }

    if (cc_len > 0) {
        add_cc_to_imap_command(comm, comm_start, comm_start + cc_len, cc_dir);
    }

    return 0;
}

static int read_imap_while_auth_state(emailsession_t *sess,
        imap_session_t *imapsess) {

    /* Our goal here is to just consume any unconventional exchanges
     * between client and server that might be occurring during
     * authentication (e.g. challenges, responses for GSSAPI, etc.).
     */

    char *msgstart = (char *)(imapsess->contbuffer + imapsess->contbufread);
    char *tmp = NULL, *crlf = NULL;
    char *authtag;
    imap_command_t *comm;
    int comm_start, pluslen;

    /* XXX need some test cases for AUTHENTICATE */

    if (imapsess->contbufread >= imapsess->contbufused) {
        return 0;
    }

    /* First step, find the next \r\n so we're only working with a
     * complete message */
    crlf = strstr(msgstart, "\r\n");
    if (crlf == NULL) {
        return 0;
    }

    pluslen = (crlf - msgstart) + 2;
    tmp = calloc((crlf - msgstart) + 1, sizeof(char));
    memcpy(tmp, msgstart, crlf - msgstart);

    comm = &(imapsess->commands[imapsess->auth_command_index]);
    authtag = comm->tag;

    /* Is this the server reply to the AUTH command? */
        /* If yes, rewind to the start of the reply tag so our normal
         * processing can be applied when we return...
         */
    if (is_tagged_reply(tmp, authtag)) {
        free(tmp);
        if (imapsess->auth_type == OPENLI_EMAIL_AUTH_PLAIN) {
            int r = 0;
            char *authmsg;
            /* Bit wasteful to be constantly strduping here XXX */
            while (r == 0) {
                authmsg = clone_authentication_message(imapsess);
                if (*authmsg == '\0') {
                    /* This is bad, we somehow decoded the whole plain
                     * auth content and didn't find what we were looking
                     * for...
                     */
                    logger(LOG_INFO, "OpenLI: failed to decode plain auth content for IMAP session: %s", sess->key);
                    r = 1;
                } else {
                    r = decode_plain_auth_content(authmsg, imapsess, sess);
                }
                free(authmsg);
            }
            return r;
        }
        sess->currstate = OPENLI_IMAP_STATE_AUTH_REPLY;
        return 1;
    }

    if (extend_command_buffer(comm, pluslen) < 0) {
        return -1;
    }
    comm_start = comm->commbufused;
    memcpy(comm->commbuffer + comm->commbufused, msgstart, pluslen);
    comm->commbufused += pluslen;
    comm->commbuffer[comm->commbufused] = '\0';

    /* We'll update the byte counts for plain auth later on when we decode the
     * entire auth message
     */
    /* Does this begin with a '+'? This is from the server */
    if (*tmp == '+') {
        if (imapsess->auth_type != OPENLI_EMAIL_AUTH_PLAIN) {
            sess->server_octets += pluslen;
        }
        add_cc_to_imap_command(comm, comm_start, comm_start + pluslen, 0);
    } else {
        /* Otherwise, this is message content from the client */
        if (imapsess->auth_type != OPENLI_EMAIL_AUTH_PLAIN) {
            sess->client_octets += pluslen;
        }
        add_cc_to_imap_command(comm, comm_start, comm_start + pluslen, 1);
    }

    /* Advance read pointer to the next line */
    imapsess->contbufread += pluslen;
    free(tmp);
    return 1;
}

static int read_imap_while_idle_state(emailsession_t *sess,
        imap_session_t *imapsess) {

    uint8_t *msgstart = imapsess->contbuffer + imapsess->contbufread;
    imap_command_t *comm;
    uint8_t *found = NULL;
    int idle_server_length = 0;
    int comm_start;

    comm = &(imapsess->commands[imapsess->idle_command_index]);

    /* check for "+ " -- server response to the idle command*/

    if (imapsess->reply_start == 0) {
        found = (uint8_t *)strstr((const char *)msgstart, "+ ");
        if (!found) {
            return 0;
        }

        imapsess->reply_start = found - imapsess->contbuffer;
    }

    /* all untagged messages are updates from the server
     * add them to our reply */

    /* check for "DONE\r\n" -- client message to end idling state */
    /*      make sure we add everything from reply_start to the start
     *      of "DONE" as a separate server->client CC, then add the
     *      "DONE" as a client->server CC.
     */
    found = (uint8_t *)strstr((const char *)msgstart, "\r\nDONE\r\n");
    if (!found) {
        return 0;
    }

    idle_server_length = (found + 2 - imapsess->contbuffer) -
            imapsess->reply_start;

    imapsess->contbufread = (found - imapsess->contbuffer) + 8;

    if (extend_command_buffer(comm, idle_server_length + 6) < 0) {
        return -1;
    }

    comm_start = comm->commbufused;
    memcpy(comm->commbuffer + comm->commbufused,
            imapsess->contbuffer + imapsess->reply_start,
            idle_server_length + 6);
    comm->commbufused += (idle_server_length + 6);
    comm->commbuffer[comm->commbufused] = '\0';

    add_cc_to_imap_command(comm, comm_start,
            comm_start + idle_server_length, 0);
    add_cc_to_imap_command(comm, comm_start + idle_server_length,
            comm_start + idle_server_length + 6, 1);

    sess->server_octets += idle_server_length;
    sess->client_octets += 6;

    imapsess->reply_start = 0;
    sess->currstate = OPENLI_IMAP_STATE_AUTHENTICATED;

    return 1;
}

static char *get_uid_command(char *command, uint8_t *buffer) {

    char *new_comm = NULL;
    int old_len = strlen(command);
    uint8_t *nextspace, *crlf;

    /* XXX requires testing with a pcap containing UID commands! */

    /* The next character in our buffer should be a space, but if it
     * isn't (i.e. it is a \r), then just return the command as is so we
     * can try to handle this weirdness nicely.
     */
    if (*buffer != ' ') {
        return command;
    }

    nextspace = (uint8_t *)strchr((const char *)(buffer + 1), ' ');
    crlf = (uint8_t *)strstr((const char *)(buffer + 1), "\r\n");

    if (!nextspace && !crlf) {
        return command;
    }

    if (nextspace == NULL || (crlf && crlf < nextspace)) {
        nextspace = crlf;
    }

    if (nextspace < buffer) {
        return command;
    }

    new_comm = calloc(old_len + (nextspace - buffer) + 1, sizeof(char));
    memcpy(new_comm, command, old_len);
    memcpy(new_comm + old_len, buffer, (nextspace - buffer));

    free(command);
    return new_comm;
}

static int find_next_imap_message(openli_email_worker_t *state,
        emailsession_t *sess, imap_session_t *imapsess) {

    char *tag;
    char *comm_resp;
    char *comm_extra = NULL;
    uint8_t *spacefound = NULL;
    uint8_t *spacefound2 = NULL;
    uint8_t *crlffound = NULL;
    uint8_t *msgstart = imapsess->contbuffer + imapsess->contbufread;

    if (sess->currstate == OPENLI_IMAP_STATE_AUTHENTICATING) {
        /* Handle various auth response behaviours, as per RFC9051 */
        return read_imap_while_auth_state(sess, imapsess);
    }

    if (sess->currstate == OPENLI_IMAP_STATE_IDLING) {
        return read_imap_while_idle_state(sess, imapsess);
    }

    if (sess->currstate == OPENLI_IMAP_STATE_APPENDING) {
        return read_imap_while_appending_state(sess, imapsess);
    }

    spacefound = (uint8_t *)strchr((const char *)msgstart, ' ');
    if (!spacefound) {
        return 0;
    }

    tag = calloc((spacefound - msgstart) + 1, sizeof(char));
    memcpy(tag, msgstart, spacefound - msgstart);
    tag[spacefound - msgstart] = '\0';

    /* Most commands are "<tag> <type> <extra context>\r\n", but some
     * have no extra context and are just "<tag> <type>\r\n".
     * Therefore if we see a \r\n BEFORE the next space, we want to
     * treat that as our string boundary.
     */
    spacefound2 = (uint8_t *)strchr((const char *)(spacefound + 1), ' ');
    crlffound = (uint8_t *)strstr((const char *)(spacefound + 1), "\r\n");

    if (!spacefound2 && !crlffound) {
        free(tag);
        return 0;
    }

    if (spacefound2 == NULL || (crlffound != NULL &&
                crlffound <= spacefound2)) {
        spacefound2 = crlffound;
    } else if (crlffound && spacefound2 && crlffound > spacefound2) {
        comm_extra = calloc((crlffound - spacefound2), sizeof(char));
        memcpy(comm_extra, spacefound2 + 1, (crlffound - spacefound2) - 1);
        comm_extra[crlffound - spacefound2 - 1] = '\0';
    }

    comm_resp = calloc((spacefound2 - spacefound), sizeof(char));
    memcpy(comm_resp, spacefound + 1, (spacefound2 - spacefound) - 1);
    comm_resp[spacefound2 - spacefound - 1] = '\0';

    if (strcmp(tag, "*") == 0) {
        if (strcasecmp(comm_resp, "BYE") == 0 &&
                sess->currstate != OPENLI_IMAP_STATE_LOGOUT) {

            /* server is doing an immediate shutdown */

            /* TODO dump CCs for any incomplete commands (including the
             *      sudden BYE)?
             */
            sess->currstate = OPENLI_IMAP_STATE_SESSION_OVER;
            generate_email_logoff_iri(state, sess);
            free(tag);
            free(comm_resp);
            if (comm_extra) {
                free(comm_extra);
            }
            return 0;

        } else if (strcasecmp(comm_resp, "PREAUTH") == 0) {
            //imapsess->next_command_type = OPENLI_IMAP_COMMAND_PREAUTH;
        } else {
            /* a partial reply to a command, more to come... */
            imapsess->next_command_type = OPENLI_IMAP_COMMAND_REPLY_ONGOING;
            free(comm_resp);
            if (comm_extra) {
                free(comm_extra);
            }
            comm_resp = NULL;
            comm_extra = NULL;

            if (imapsess->reply_start == 0) {
                imapsess->reply_start = msgstart - imapsess->contbuffer;
            }
        }
    } else if (strcasecmp(comm_resp, "OK") == 0 ||
            strcasecmp(comm_resp, "NO") == 0 ||
            strcasecmp(comm_resp, "BAD") == 0) {

        /* this is a reply that completes the response to a command */
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_REPLY;
        if (imapsess->reply_start == 0) {
            imapsess->reply_start = msgstart - imapsess->contbuffer;
        }
    } else if (strcasecmp(comm_resp, "ID") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_ID;
    } else if (strcasecmp(comm_resp, "COMPRESS") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_COMPRESS;
    } else if (strcasecmp(comm_resp, "UID") == 0) {
        comm_resp = get_uid_command(comm_resp, spacefound2);
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_GENERIC;
    } else if (strcasecmp(comm_resp, "IDLE") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_IDLE;
    } else if (strcasecmp(comm_resp, "APPEND") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_APPEND;
    } else if (strcasecmp(comm_resp, "LOGOUT") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_LOGOUT;
    } else if (strcasecmp(comm_resp, "LOGIN") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_LOGIN;
        imapsess->auth_read_from = msgstart - imapsess->contbuffer;
        if (imapsess->auth_tag) {
            free(imapsess->auth_tag);
        }
        imapsess->auth_tag = strdup(tag);
        sess->currstate = OPENLI_IMAP_STATE_AUTH_STARTED;
    } else if (strcasecmp(comm_resp, "AUTHENTICATE") == 0) {
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_AUTH;
        if (imapsess->auth_tag) {
            free(imapsess->auth_tag);
        }
        imapsess->auth_tag = strdup(tag);
        imapsess->auth_read_from = msgstart - imapsess->contbuffer;
        sess->currstate = OPENLI_IMAP_STATE_AUTH_STARTED;
    } else {
        /* just a regular IMAP command that requires no special treatment */
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_GENERIC;
    }

    if (imapsess->next_comm_tag) {
        free(imapsess->next_comm_tag);
    }
    imapsess->next_comm_tag = tag;

    if (imapsess->next_command_name) {
        free(imapsess->next_command_name);
    }

    if (imapsess->next_command_params) {
        free(imapsess->next_command_params);
    }
    imapsess->next_command_params = comm_extra;

    imapsess->next_command_name = comm_resp;
    imapsess->next_comm_start = msgstart - imapsess->contbuffer;

    return 1;
}

static int process_next_imap_state(openli_email_worker_t *state,
        emailsession_t *sess, imap_session_t *imapsess, time_t timestamp) {

    int r;

    if (sess->currstate == OPENLI_IMAP_STATE_INIT) {
        r = find_server_ready(imapsess);
        if (r == 1) {
            sess->currstate = OPENLI_IMAP_STATE_SERVER_READY;
        }
    }

    if (sess->currstate == OPENLI_IMAP_STATE_SERVER_READY) {
        r = find_server_ready_end(imapsess);
        if (r == 1) {
            sess->currstate = OPENLI_IMAP_STATE_PRE_AUTH;
            sess->server_octets +=
                    (imapsess->contbufread - imapsess->next_comm_start);
            imapsess->next_comm_start = 0;
            imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
        }
        return r;
    }

    if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_NONE) {
        r = find_next_imap_message(state, sess, imapsess);
        return r;
    } else if (imapsess->next_command_type == OPENLI_IMAP_COMMAND_REPLY) {
        r = find_reply_end(state, sess, imapsess, timestamp);

        return r;
    } else if (imapsess->next_command_type ==
            OPENLI_IMAP_COMMAND_REPLY_ONGOING) {
        r = find_partial_reply_end(sess, imapsess);
        return r;
    } else {
        r = find_command_end(sess, imapsess);
        return r;
    }

    return 0;
}

int update_imap_session_by_ingestion(openli_email_worker_t *state,
        emailsession_t *sess, openli_email_captured_t *cap) {

    imap_session_t *imapsess;
    int r, i;

    if (sess->proto_state == NULL) {
        imapsess = calloc(1, sizeof(imap_session_t));
        imapsess->contbuffer = calloc(1024, sizeof(uint8_t));
        imapsess->deflatebuffer = NULL;
        imapsess->contbufused = 0;
        imapsess->deflatebufused = 0;
        imapsess->contbufread = 0;
        imapsess->deflatebufread = 0;
        imapsess->contbufsize = 1024;
        imapsess->deflatebufsize = 0;
        imapsess->commands = calloc(5, sizeof(imap_command_t));
        imapsess->commands_size = 5;
        imapsess->next_command_type = OPENLI_IMAP_COMMAND_NONE;
        imapsess->idle_command_index = -1;
        imapsess->auth_command_index = -1;

        imapsess->decompress_server.inbuffer = NULL;
        imapsess->decompress_server.inbufsize = 0;
        imapsess->decompress_server.inwriteoffset = 0;
        imapsess->decompress_server.inreadoffset = 0;
        imapsess->decompress_server.outbuffer = NULL;
        imapsess->decompress_server.outbufsize = 0;
        imapsess->decompress_server.outreadoffset = 0;

        imapsess->deflate_ccs = NULL;
        imapsess->deflate_ccs_size = 0;
        imapsess->deflate_ccs_current = 0;

        for (i = 0; i < imapsess->commands_size; i++) {
            init_imap_command(&(imapsess->commands[i]));
        }

        sess->proto_state = (void *)imapsess;
    } else {
        imapsess = (imap_session_t *)sess->proto_state;
    }

    if (sess->currstate == OPENLI_IMAP_STATE_IGNORING) {
        return 0;
    }

    if (sess->compressed) {
        if (append_compressed_content_to_imap_buffer(imapsess, cap) < 0) {
            logger(LOG_INFO, "OpenLI: Failed to append compressed IMAP message content to session buffer for %s", sess->key);
            return -1;
        }

        if (_append_content_to_deflate_buffer(imapsess, cap->content,
                cap->msg_length, cap->pkt_sender) < 0) {
            logger(LOG_INFO, "OpenLI: Failed to save compressed IMAP message content for session %s", sess->key);
            return -1;
        }

    } else if (append_content_to_imap_buffer(imapsess, cap) < 0) {
        logger(LOG_INFO, "OpenLI: Failed to append IMAP message content to session buffer for %s", sess->key);
        return -1;
    }

    while (1) {
        if ((r = process_next_imap_state(state, sess, imapsess,
                cap->timestamp)) <= 0) {
            break;
        }
        if (sess->currstate == OPENLI_IMAP_STATE_IGNORING) {
            break;
        }
    }

    if (sess->currstate == OPENLI_IMAP_STATE_SESSION_OVER) {
        return 1;
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
