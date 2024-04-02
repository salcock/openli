/*
 *
 * Copyright (c) 2018-2022 The University of Waikato, Hamilton, New Zealand.
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

#include "email_worker.h"
#include "logger.h"
#include "Judy.h"

enum {
    SMTP_COMMAND_TYPE_NOT_SET = 0,
    SMTP_COMMAND_TYPE_EHLO,
    SMTP_COMMAND_TYPE_MAIL_FROM,
    SMTP_COMMAND_TYPE_RCPT_TO,
    SMTP_COMMAND_TYPE_DATA,
    SMTP_COMMAND_TYPE_DATA_CONTENT,
    SMTP_COMMAND_TYPE_QUIT,
    SMTP_COMMAND_TYPE_RSET,
    SMTP_COMMAND_TYPE_AUTH,
    SMTP_COMMAND_TYPE_STARTTLS,
    SMTP_COMMAND_TYPE_OTHER,
};

enum {
    SMTP_AUTH_METHOD_NONE = 0,
    SMTP_AUTH_METHOD_PLAIN,
    SMTP_AUTH_METHOD_LOGIN,
    SMTP_AUTH_METHOD_CRAMMD5,
    SMTP_AUTH_METHOD_XOAUTH,
    SMTP_AUTH_METHOD_NTLM,
    SMTP_AUTH_METHOD_GSSAPI
};

typedef struct smtp_comm {
    uint8_t command_type;
    uint64_t timestamp;
    uint16_t reply_code;

    int command_index;
    int command_start;
    int reply_start;
    int reply_end;
} smtp_command_t;

typedef struct smtp_cc_list {
    smtp_command_t *commands;
    int commands_size;
    int curr_command;
    int last_unsent;
} smtp_cc_list_t;


typedef struct smtp_participant {
    smtp_cc_list_t ccs;
    uint8_t active;
    uint64_t last_mail_from;
} smtp_participant_t;

typedef struct smtpsession {
    char *messageid;

    uint8_t *contbuffer;
    int contbufsize;
    int contbufused;
    int contbufread;
    int command_start;
    int reply_start;
    uint16_t reply_code;

    int next_command_index;

    uint8_t saved_state;

    smtp_cc_list_t preambles;

    smtp_command_t last_mail_from;
    smtp_command_t last_quit;
    uint16_t last_ehlo_reply_code;

    Pvoid_t senders;
    Pvoid_t recipients;

    uint8_t authenticated;
    uint8_t auth_method;
    char *auth_creds;

    uint8_t ignore;
    smtp_participant_t *activesender;

} smtp_session_t;

void free_smtp_session_state(openli_email_worker_t *state,
        emailsession_t *sess, void *smtpstate) {

    PWord_t pval;
    Word_t res;
    uint8_t index[1024];
    smtp_participant_t *part;

    smtp_session_t *smtpsess;
    if (smtpstate == NULL) {
        return;
    }
    smtpsess = (smtp_session_t *)smtpstate;

    index[0] = '\0';
    JSLF(pval, smtpsess->senders, index);
    while (pval != NULL) {
        part = (smtp_participant_t *)(*pval);
        if (part->ccs.commands) {
            free(part->ccs.commands);
        }
        free(part);
        JSLN(pval, smtpsess->senders, index);
    }
    JSLFA(res, smtpsess->senders);

    index[0] = '\0';
    JSLF(pval, smtpsess->recipients, index);
    while (pval != NULL) {
        part = (smtp_participant_t *)(*pval);
        if (part->ccs.commands) {
            free(part->ccs.commands);
        }
        free(part);
        JSLN(pval, smtpsess->recipients, index);
    }
    JSLFA(res, smtpsess->recipients);

    if (smtpsess->preambles.commands) {
        free(smtpsess->preambles.commands);
    }

    if (smtpsess->auth_creds) {
        free(smtpsess->auth_creds);
    }

    free(smtpsess->contbuffer);
    free(smtpsess);

}

static void set_all_smtp_participants_inactive(smtp_session_t *smtpsess) {

    PWord_t pval;
    uint8_t index[1024];
    smtp_participant_t *part;

    index[0] = '\0';
    JSLF(pval, smtpsess->senders, index);
    while (pval != NULL) {
        part = (smtp_participant_t *)(*pval);
        if (!smtpsess->authenticated) {
            part->active = 0;
        }
        part->ccs.curr_command = 0;
        part->ccs.last_unsent = 0;
        JSLN(pval, smtpsess->senders, index);
    }

    index[0] = '\0';
    JSLF(pval, smtpsess->recipients, index);
    while (pval != NULL) {
        part = (smtp_participant_t *)(*pval);
        part->active = 0;
        part->ccs.curr_command = 0;
        part->ccs.last_unsent = 0;
        JSLN(pval, smtpsess->recipients, index);
    }
    if (!smtpsess->authenticated) {
        smtpsess->activesender = NULL;
    }
}

static int generate_smtp_ccs_from_saved(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess,
        smtp_cc_list_t *ccs, const char *participant, uint8_t is_sender) {

    int i;
    uint8_t dir;

    for (i = ccs->last_unsent; i < ccs->curr_command; i++) {
        smtp_command_t *comm = &(ccs->commands[i]);
        generate_email_cc_from_smtp_payload(state, sess,
                smtpsess->contbuffer + comm->command_start,
                comm->reply_start - comm->command_start,
                comm->timestamp, participant,
                is_sender ? ETSI_DIR_FROM_TARGET : ETSI_DIR_TO_TARGET,
                comm->command_index);
        generate_email_cc_from_smtp_payload(state, sess,
                smtpsess->contbuffer + comm->reply_start,
                comm->reply_end - comm->reply_start,
                comm->timestamp, participant,
                is_sender ? ETSI_DIR_TO_TARGET : ETSI_DIR_FROM_TARGET,
                comm->command_index);
        /* generate CCs in the case where the TARGET_ID matches an active
         * intercept
         */

        /* make sure that we only generate each CC once for an intercept
         * with a matching TARGET_ID, so don't repeat the check if/when
         * we are subsequently called for each mail recipient.
         */
        if (!is_sender) {
            continue;
        }

        /* also ignore if the TARGET_ID is an exact match of the sender
         * address, as the CCs generated just previously will suffice
         */
        if (sess->ingest_target_id == NULL || strcmp(sess->ingest_target_id,
                participant) == 0) {
            continue;
        }

        /* direction outbound == the target is sending the email, i.e.
         * commands come from the target, replies are to the target */
        if (sess->ingest_direction == OPENLI_EMAIL_DIRECTION_OUTBOUND) {
            dir = ETSI_DIR_FROM_TARGET;
        } else if (sess->ingest_direction == OPENLI_EMAIL_DIRECTION_INBOUND) {
            dir = ETSI_DIR_TO_TARGET;
        } else {
            continue;
        }
        generate_email_cc_from_smtp_payload(state, sess,
                smtpsess->contbuffer + comm->command_start,
                comm->reply_start - comm->command_start,
                comm->timestamp, sess->ingest_target_id, dir,
                comm->command_index);

        /* direction inbound == the target is receiving the email, i.e.
         * commands are sent "to" the target, replies are "from" the target */
        if (sess->ingest_direction == OPENLI_EMAIL_DIRECTION_OUTBOUND) {
            dir = ETSI_DIR_TO_TARGET;
        } else {
            dir = ETSI_DIR_FROM_TARGET;
        }
        generate_email_cc_from_smtp_payload(state, sess,
                smtpsess->contbuffer + comm->reply_start,
                comm->reply_end - comm->reply_start,
                comm->timestamp, sess->ingest_target_id, dir,
                comm->command_index);

    }

    ccs->last_unsent = ccs->curr_command;
    return 0;
}

static int copy_smtp_command(smtp_cc_list_t *ccs, smtp_command_t *cmd) {

    smtp_command_t *copy;

    while (ccs->commands_size <= ccs->curr_command) {
        ccs->commands = realloc(ccs->commands,
                (ccs->commands_size + 10) * sizeof(smtp_command_t));
        if (ccs->commands == NULL) {
            return -1;
        }
        ccs->commands_size += 10;
    }
    copy = &(ccs->commands[ccs->curr_command]);
    copy->command_type = cmd->command_type;
    copy->command_start = cmd->command_start;
    copy->reply_start = cmd->reply_start;
    copy->reply_end = cmd->reply_end;
    copy->reply_code = cmd->reply_code;
    copy->timestamp = cmd->timestamp;
    copy->command_index = cmd->command_index;

    ccs->curr_command ++;
}

static int add_new_smtp_command(smtp_cc_list_t *ccs,
        int command_start, uint8_t command_type, int command_index) {

    int ind = ccs->curr_command;
    smtp_command_t *cmd;

    while (ccs->commands_size <= ccs->curr_command) {
        ccs->commands = realloc(ccs->commands,
                (ccs->commands_size + 10) * sizeof(smtp_command_t));
        if (ccs->commands == NULL) {
            return -1;
        }
        ccs->commands_size += 10;
    }

    cmd = &(ccs->commands[ind]);
    memset(cmd, 0, sizeof(smtp_command_t));
    cmd->command_type = command_type;
    cmd->command_start = command_start;
    cmd->command_index = command_index;
    return 0;

}

static int add_new_smtp_reply(smtp_cc_list_t *ccs,
        int reply_start, int reply_end, uint16_t reply_code,
        uint64_t timestamp) {

    int ind = ccs->curr_command;
    smtp_command_t *cmd = &(ccs->commands[ind]);

    cmd->reply_start = reply_start;
    cmd->reply_end = reply_end;
    cmd->reply_code = reply_code;
    cmd->timestamp = timestamp;

    ccs->curr_command ++;
    return 0;
}

static int append_content_to_smtp_buffer(smtp_session_t *smtpsess,
        openli_email_captured_t *cap, emailsession_t *sess) {

    /* "16" is just a bit of extra buffer space to account for
     * special cases where we need to insert missing "DATA" commands
     * into the application data stream.
     */
    while (smtpsess->contbufsize - smtpsess->contbufused <=
            cap->msg_length + 16) {
        smtpsess->contbuffer = realloc(smtpsess->contbuffer,
                smtpsess->contbufsize + 4096);
        if (smtpsess->contbuffer == NULL) {
            return -1;
        }

        smtpsess->contbufsize += 4096;
    }

    /* Special case -- some ingested data sources skip the DATA
     * command, so we're going to try and squeeze that in ourselves
     * whenever we see content beginning with the "354 " response.
     */
    if (sess->currstate == OPENLI_SMTP_STATE_RCPT_TO_OVER &&
            memcmp(cap->content, (const void *)"354 ", 4) == 0) {
        memcpy(smtpsess->contbuffer + smtpsess->contbufused,
                "DATA\r\n", 6);
        smtpsess->contbufused += 6;
    }

    memcpy(smtpsess->contbuffer + smtpsess->contbufused,
            cap->content, cap->msg_length);
    smtpsess->contbufused += cap->msg_length;
    smtpsess->contbuffer[smtpsess->contbufused] = '\0';

    return 0;
}

static char *extract_smtp_participant(openli_email_worker_t *state,
        emailsession_t *sess,
        smtp_session_t *smtpstate, int contoffset, int contend) {

    char *addr, *addrstart, *addrend;
    const char *search = (const char *)(smtpstate->contbuffer + contoffset);

    addrstart = strchr(search, '<');
    if (addrstart == NULL) {
        return NULL;
    }

    addrend = strchr(search, '>');
    if (addrend == NULL) {
        return NULL;
    }

    if (addrstart >= (char *)(smtpstate->contbuffer + contend)) {
        return NULL;
    }

    if (addrend >= (char *)(smtpstate->contbuffer + contend)) {
        return NULL;
    }


    addr = strndup(addrstart + 1, addrend - addrstart - 1);

    add_email_participant(state, sess, addr,
            (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM_OVER));
    return addr;

}

static int find_next_crlf(smtp_session_t *sess, int start_index) {

    int rem;
    uint8_t *found;

    rem = sess->contbufused - start_index;

    found = (uint8_t *)memmem(sess->contbuffer + start_index, rem, "\r\n", 2);

    if (found) {
        sess->contbufread = (found - sess->contbuffer) + 2;
        return 1;
    }
    return 0;
}

static int find_smtp_reply_code(smtp_session_t *sess, uint16_t *storage) {

    int res;
    regex_t lastreply;
    regmatch_t pmatch[1];
    const char *search;

    if (regcomp(&lastreply, "[[:digit:]][[:digit:]][[:digit:]] ", 0) != 0) {
        return -1;
    }

    search = (const char *)(sess->contbuffer + sess->contbufread);

    res = regexec(&lastreply, search, 1, pmatch, 0);
    if (res != 0) {
        regfree(&lastreply);
        return 0;
    }

    if (storage) {
        (*storage) = strtoul(search + pmatch[0].rm_so, NULL, 10);
    }
    regfree(&lastreply);
    return find_next_crlf(sess, sess->contbufread + pmatch[0].rm_so);
}

static int find_ehlo_end(smtp_session_t *sess) {
    return find_next_crlf(sess, sess->command_start);
}

static int find_auth_end(smtp_session_t *sess) {
    return find_next_crlf(sess, sess->command_start);
}

static int find_auth_creds_end(smtp_session_t *sess) {
    return find_next_crlf(sess, sess->command_start);
}

static int find_mail_from_end(smtp_session_t *sess) {
    return find_next_crlf(sess, sess->command_start);
}

static int find_rcpt_to_end(smtp_session_t *sess) {
    return find_next_crlf(sess, sess->command_start);
}

static int find_other_command_end(smtp_session_t *sess) {
    return find_next_crlf(sess, sess->command_start);
}

static int find_data_init_reply_code(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->reply_code));
}

static int find_data_final_reply_code(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->reply_code));
}

static int find_reset_reply_code(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->reply_code));
}

static int find_auth_reply_code(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->reply_code));
}

static int find_quit_reply_code(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->reply_code));
}

static int find_ehlo_response_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->reply_code));
}

static int find_mail_from_reply_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->last_mail_from.reply_code));
}

static int find_rcpt_to_reply_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->reply_code));
}

static int find_other_command_reply_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->reply_code));
}

static int find_starttls_reply_end(smtp_session_t *sess) {
    return find_smtp_reply_code(sess, &(sess->reply_code));
}

static int find_command_by_name(smtp_session_t *sess, const char *name,
        uint8_t autoskip) {

    uint8_t *found = NULL;
    uint8_t *nextcrlf;

    /* strip any leading newlines that might have snuck in somehow... */
    while (*(sess->contbuffer + sess->contbufread) == '\r' &&
            *(sess->contbuffer + sess->contbufread + 1) == '\n') {
        sess->contbufread += 2;
    }

    if (sess->contbufused - sess->contbufread < strlen(name)) {
        return 0;
    }

    nextcrlf = (uint8_t *)strcasestr(
            (const char *)(sess->contbuffer + sess->contbufread),
            "\r\n");

    if (!nextcrlf) {
        return 0;
    }

    found = (uint8_t *)strcasestr(
            (const char *)(sess->contbuffer + sess->contbufread), name);
    if (found == NULL) {
        return 0;
    }

    /* There is some other command or reply before the one we want, so we need
     * to process that first...
     */
    if (nextcrlf < found) {
        return 0;
    }

    sess->command_start = found - sess->contbuffer;

    /* Skip past command automatically */
    if (autoskip) {
        sess->contbufread = sess->command_start + strlen(name);
    }
    return 1;
}

static int find_other_command(smtp_session_t *sess, emailsession_t *emailsess) {
    /* XXX are there other commands that we should add here? */

    /* Include other "normal" commands in here, because if a user
     * issues a command out of order or at the wrong time (e.g.
     * RCPT TO before MAIL FROM), we still need to be able to parse
     * the command and the error response from the server.
     */

    if (find_command_by_name(sess, "RCPT TO:", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "MAIL FROM:", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "DATA", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "AUTH ", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "STARTTLS", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "NOOP", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "VRFY ", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "HELP", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "EXPN ", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "TURN", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "ATRN", 0)) {
        return 1;
    }

    /* TODO BDAT should be treated as a send/receive event and
     * therefore generate IRIs
     */
    if (find_command_by_name(sess, "BDAT", 0)) {
        return 1;
    }

    if (find_command_by_name(sess, "SIZE ", 0)) {
        return 1;
    }

    uint32_t saved = sess->contbufread;
    if (find_next_crlf(sess, sess->contbufread)) {
        /* We didn't find a valid command, so maybe this is just some
         * garbage that will hopefully be rejected by the server.
         */
        sess->command_start = saved;
        sess->saved_state = emailsess->currstate;
        sess->reply_start = sess->contbufread;
        emailsess->client_octets += (sess->reply_start - sess->command_start);
        emailsess->currstate = OPENLI_SMTP_STATE_OTHER_COMMAND_REPLY;
        return 0;
    }

    return 0;
}

static int find_starttls(smtp_session_t *sess) {
    return find_command_by_name(sess, "STARTTLS\r\n", 1);
}

static int find_auth(smtp_session_t *sess) {
    return find_command_by_name(sess, "AUTH ", 0);
}

static int find_data_start(smtp_session_t *sess) {
    return find_command_by_name(sess, "DATA\r\n", 1);
}

static int find_reset_command(smtp_session_t *sess) {
    return find_command_by_name(sess, "RSET\r\n", 1);
}

static int find_quit_command(smtp_session_t *sess) {
    return find_command_by_name(sess, "QUIT\r\n", 1);
}

static int find_mail_from(smtp_session_t *sess) {
    return find_command_by_name(sess, "MAIL FROM:", 0);
}

static int find_rcpt_to(smtp_session_t *sess) {
    return find_command_by_name(sess, "RCPT TO:", 0);
}

static int find_data_content_ending(smtp_session_t *sess) {
    const char *search = (const char *)(sess->contbuffer + sess->contbufread);
    uint8_t *found = NULL;

    /* An "empty" mail message is ".\r\n" -- edge case, but let's try to
     * handle it regardless.
     */
    if (strncmp(search, ".\r\n", 3) == 0) {
        sess->contbufread += 3;
        return 1;
    }

    found = (uint8_t *)strstr(search, "\r\n.\r\n");
    if (found != NULL) {
        sess->contbufread = (found - sess->contbuffer) + 5;
        return 1;
    }

    return 0;
}


static int find_ehlo_start(emailsession_t *mailsess, smtp_session_t *sess) {
    uint8_t *found = NULL, *reversefound = NULL;
    const char *search;

    if (sess->contbufused - sess->contbufread < 5) {
        return 0;
    }
    search = (const char *)(sess->contbuffer + sess->contbufread);

    found = (uint8_t *)strcasestr(search, "EHLO ");
    reversefound = (uint8_t *)strcasestr(search, "HELO ");

    /* In theory, we can have multiple EHLOs (e.g. when STARTTLS is used),
     * so don't reset the EHLO start pointer if we haven't transitioned past
     * the EHLO OVER state.
     */
    if (found != NULL || reversefound != NULL) {
        uint8_t *f = found ? found : reversefound;

        if (mailsess->currstate != OPENLI_SMTP_STATE_EHLO_OVER) {
            sess->command_start = f - sess->contbuffer;

            /* Reset the preamble command list, just in case */
            sess->preambles.curr_command = 0;
            sess->preambles.last_unsent = 0;

            add_new_smtp_command(&(sess->preambles), sess->command_start,
                    SMTP_COMMAND_TYPE_EHLO, sess->next_command_index);
            sess->next_command_index ++;
        }
        return 1;
    }

    return 0;
}

static int save_latest_command(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp,
        uint8_t command_type, uint8_t publish_now, uint8_t sender_only) {

    PWord_t pval;
    char index[1024];
    smtp_participant_t *recipient;
    smtp_cc_list_t *cclist;

    if (smtpsess->activesender == NULL) {
        cclist = &(smtpsess->preambles);
    } else {
        cclist = &(smtpsess->activesender->ccs);
    }

    sess->server_octets += (smtpsess->contbufread - smtpsess->reply_start);
    add_new_smtp_command(cclist,
            smtpsess->command_start, command_type,
            smtpsess->next_command_index);
    add_new_smtp_reply(cclist, smtpsess->reply_start,
            smtpsess->contbufread, smtpsess->reply_code, timestamp);

    if (smtpsess->activesender == NULL) {
        smtpsess->next_command_index ++;
        return 1;
    }

    if (publish_now) {
        generate_smtp_ccs_from_saved(state, sess, smtpsess,
                &(smtpsess->activesender->ccs), sess->sender.emailaddr, 1);
    }

    if (sender_only) {
        smtpsess->next_command_index ++;
        return 1;
    }

    index[0] = '\0';
    JSLF(pval, smtpsess->recipients, index);
    while (pval) {
        recipient = (smtp_participant_t *)(*pval);
        if (recipient->active) {
            add_new_smtp_command(&(recipient->ccs), smtpsess->command_start,
                    command_type, smtpsess->next_command_index);
            add_new_smtp_reply(&(recipient->ccs), smtpsess->reply_start,
                    smtpsess->contbufread, smtpsess->reply_code, timestamp);
            if (publish_now) {
                generate_smtp_ccs_from_saved(state, sess, smtpsess,
                        &(recipient->ccs), index, 0);
            }
        }
        JSLN(pval, smtpsess->recipients, index);
    }
    smtpsess->next_command_index ++;
    return 1;
}

static int process_auth_message(smtp_session_t *smtpsess) {

    char *ptr, *token, *end;
    char *copy = calloc((smtpsess->contbufused - smtpsess->command_start) + 1,
            sizeof(char));
    int i = 0;

    memcpy(copy, smtpsess->contbuffer + smtpsess->command_start,
            smtpsess->contbufused - smtpsess->command_start);

    if (smtpsess->contbufused - smtpsess->command_start <= 5) {
        return -1;
    }

    ptr = copy + 5;
    end = (char *)memmem(ptr, strlen(ptr), "\r\n", 2);

    token = strtok(ptr, " \t\r\n");
    while (token && token < end) {
        if (i == 0) {
            /* this token should describe the auth type */
            /* TODO support other auth types */
            if (strcasecmp(token, "plain") == 0) {
                smtpsess->auth_method = SMTP_AUTH_METHOD_PLAIN;
            } else if (strcasecmp(token, "login") == 0) {
                smtpsess->auth_method = SMTP_AUTH_METHOD_LOGIN;
            } else if (strcasecmp(token, "cram-md5") == 0) {
                smtpsess->auth_method = SMTP_AUTH_METHOD_CRAMMD5;
            }
        } else {
            if (smtpsess->auth_method == SMTP_AUTH_METHOD_PLAIN) {
                if (smtpsess->auth_creds) {
                    free(smtpsess->auth_creds);
                }
                smtpsess->auth_creds = strdup(token);
            }
        }

        i++;
        token = strtok(NULL, " \t\r\n");
    }

    free(copy);
    return 0;
}

static int other_command_reply(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp) {

    /* Emit CCs for the command, but only if the sender is the intercept
     * target. We probably don't care about weird SMTP behaviour if the
     * recipient is the target so ignore other commands in that case.
     */
    if (smtpsess->activesender) {
        save_latest_command(state, sess, smtpsess, timestamp,
                SMTP_COMMAND_TYPE_OTHER, 1, 1);
    }
    sess->currstate = smtpsess->saved_state;
    return 1;
}

static int rcpt_to_reply(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp) {

    int r, i;
    PWord_t pval;
    smtp_participant_t *recipient;
    int found = 0;
    char *address;

    if (smtpsess->reply_code == 250) {

        sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_OVER;

        /* extract recipient info from rcpt to content */
        address = extract_smtp_participant(state, sess, smtpsess,
                    smtpsess->command_start, smtpsess->contbufread);
        if (address == NULL) {
            return -1;
        }
        JSLG(pval, smtpsess->recipients, (unsigned char *)address);
        if (pval == NULL) {
            recipient = calloc(1, sizeof(smtp_participant_t));
            recipient->ccs.commands = calloc(10, sizeof(smtp_command_t));
            recipient->ccs.commands_size = 10;
            recipient->ccs.curr_command = 0;
            recipient->ccs.last_unsent = 0;
            recipient->active = 0;
            recipient->last_mail_from = 0;

            JSLI(pval, smtpsess->recipients, address);
            *pval = (Word_t)recipient;

        } else {
            recipient = (smtp_participant_t *)(*pval);
        }

        if (recipient->active == 0) {
            for (i = 0; i < smtpsess->preambles.curr_command; i++) {
                copy_smtp_command(&(recipient->ccs), &(smtpsess->preambles.commands[i]));
            }
            recipient->active = 1;
        }

        if (recipient->last_mail_from < smtpsess->last_mail_from.timestamp) {
            copy_smtp_command(&(recipient->ccs), &(smtpsess->last_mail_from));
        }

        //generate_email_login_success_iri(state, sess, address);
        save_latest_command(state, sess, smtpsess, timestamp,
                SMTP_COMMAND_TYPE_RCPT_TO, 0, 0);
    } else {
        sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM_OVER;
    }

    return 1;
}

static void activate_latest_sender(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp,
        smtp_participant_t **sender) {

    PWord_t pval;
    char index[1024];
    smtp_participant_t *s, *r;
    int found = 0;

    index[0] = '\0';
    JSLF(pval, smtpsess->senders, index);
    while (pval) {
        s = (smtp_participant_t *)(*pval);
        if (strcmp(index, sess->sender.emailaddr) == 0) {
            found = 1;
            *sender = s;

        } else if (s->active == 1 && sess->login_sent) {
            /* If we have sent a login IRI and the MAIL FROM
             * address has now changed, send a logoff IRI to indicate
             * that this session is no longer being used by the
             * previous address (remember, the new address may
             * not be a target so we cannot rely on a login event
             * IRI for the new address being seen by the LEA).
             */
            s->active = 0;
            sess->event_time = timestamp;
            generate_email_logoff_iri_for_user(state, sess, index);
        }

        if (s != smtpsess->activesender) {
            s->ccs.curr_command = 0;
            s->last_mail_from = 0;
        }
        JSLN(pval, smtpsess->senders, index);
    }

    index[0] = '\0';
    JSLF(pval, smtpsess->recipients, index);
    while (pval) {
        r = (smtp_participant_t *)(*pval);
        r->active = 0;
        JSLN(pval, smtpsess->recipients, index);
    }

    if (!found) {
        s = calloc(1, sizeof(smtp_participant_t));
        s->ccs.commands = calloc(10, sizeof(smtp_command_t));
        s->ccs.commands_size = 10;
        s->ccs.curr_command = 0;
        s->active = 0;
        s->last_mail_from = 0;

        JSLI(pval, smtpsess->senders, sess->sender.emailaddr);
        *pval = (Word_t)s;
        *sender = s;
    }
}

static int forwarding_header_check(openli_email_worker_t *state,
        emailsession_t *sess, char *header) {

    string_set_t *s, *tmp;
    char *val;

    EMAIL_DEBUG(state,
            "Email worker %d: entering forwarding_header_check() for %s",
            state->emailid, sess->key);

    HASH_ITER(hh, *(state->email_forwarding_headers), s, tmp) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking if header %s matches the configured header %s",
                state->emailid, header, s->term);

        if (strncmp(header, s->term, s->termlen) != 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: does not match at all",
                    state->emailid);
            continue;
        }
        val = header + s->termlen;
        if (*val == ':') {
            EMAIL_DEBUG(state,
                    "Email worker %d: match found -- getting sender address from header",
                    state->emailid);
            /* this email was automatically forwarded */
            val ++;
            /* skip extraneous spaces... */
            while (*val == ' ') {
                val ++;
            }
            EMAIL_DEBUG(state,
                    "Email worker %d: skipped extraneous whitespace",
                    state->emailid);
            if (*val != '\0') {
                /* we now have the "real" sender of this forward */
                EMAIL_DEBUG(state,
                        "Email worker %d: setting %s as the sender",
                        state->emailid, val);
                add_email_participant(state, sess, strdup(val), 1);
                return 1;
            } else {
                EMAIL_DEBUG(state,
                        "Email worker %d: sender address is missing?",
                        state->emailid, val);
            }

        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: partial match, but have to skip",
                    state->emailid);
        }
    }
    EMAIL_DEBUG(state,
            "Email worker %d: finished in forwarding_header_check()",
            state->emailid);
    return 0;
}

static int parse_mail_content(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess) {

    char *next, *copy, *start, *header, *hdrwrite, *val;
    int len, ret = 0;

    EMAIL_DEBUG(state,
            "Email worker %d: entering parse_mail_content() for %s",
            state->emailid, sess->key);

    if (*(state->email_forwarding_headers) == NULL) {
        EMAIL_DEBUG(state,
                "Email worker %d: no forwarding headers configured, so don't bother",
                state->emailid);
        return 0;
    }

    /* Only pay attention to forwarding headers on mail that we
     * are sending, not mail that is being received by our SMTP
     * server
     */
    if (sess->ingest_direction != OPENLI_EMAIL_DIRECTION_OUTBOUND) {
        EMAIL_DEBUG(state,
                "Email worker %d: %s is an inbound session, ignoring",
                state->emailid, sess->key);
        return 0;
    }

    EMAIL_DEBUG(state,
            "Email worker %d: copying DATA content for %s so we can tokenise",
            state->emailid, sess->key);
    len = smtpsess->reply_start - smtpsess->command_start;

    copy = calloc(sizeof(char), len + 1);
    header = calloc(sizeof(char), len + 1);
    memcpy(copy, smtpsess->contbuffer + smtpsess->command_start, len);

    start = copy;
    hdrwrite = header;

    EMAIL_DEBUG(state,
            "Email worker %d: copy complete, time to look for interesting headers",
            state->emailid);
    pthread_rwlock_rdlock(state->glob_config_mutex);

    while ((next = strstr(start, "\r\n")) != NULL) {

        if (next == start) {
            /* empty line, headers are over */
            EMAIL_DEBUG(state,
                    "Email worker %d: empty line -- no more headers after this one",
                    state->emailid);
            forwarding_header_check(state, sess, header);
            break;
        }

        if (*start != ' ' && *start != '\t') {
            if (header != hdrwrite) {

                EMAIL_DEBUG(state,
                        "Email worker %d: got a complete header",
                        state->emailid);

                if (forwarding_header_check(state, sess, header)) {
                    ret = 1;
                    EMAIL_DEBUG(state,
                            "Email worker %d: header was a match!",
                            state->emailid);
                    break;
                } else {
                    EMAIL_DEBUG(state,
                            "Email worker %d: header was not a match",
                            state->emailid);
                }

                memset(header, 0, len + 1);
            } else {
                EMAIL_DEBUG(state,
                        "Email worker %d: have to wait for first header to complete",
                        state->emailid);
            }
            hdrwrite = header;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: line begins with whitespace, so is a continuation of previous header",
                    state->emailid);
        }

        EMAIL_DEBUG(state,
                "Email worker %d: storing the next header line...",
                state->emailid);
        memcpy(hdrwrite, start, next - start);
        hdrwrite += (next - start);
        start = next + 2;
    }

    pthread_rwlock_unlock(state->glob_config_mutex);
    EMAIL_DEBUG(state,
            "Email worker %d: finished parsing headers",
            state->emailid);

    free(header);
    free(copy);
    EMAIL_DEBUG(state,
            "Email worker %d: tidied up local copies, parse_mail_content() is over",
            state->emailid);
    return ret;
}

static void data_content_over(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp) {

    PWord_t pval;
    char index[1024];
    smtp_participant_t *recipient;
    smtp_participant_t *sender = NULL;
    int i;

    EMAIL_DEBUG(state,
            "Email worker %d: processing reply after end of DATA content",
            state->emailid);

    if (smtpsess->reply_code == 250) {
        sess->currstate = OPENLI_SMTP_STATE_DATA_OVER;
        sess->event_time = timestamp;
        EMAIL_DEBUG(state,
                "Email worker %d: reply was 250 -- check for forwarding behaviour",
                state->emailid);
        if (parse_mail_content(state, sess, smtpsess) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: mail was forwarded by %s, setting them as the sender",
                    state->emailid, sess->sender.emailaddr);
            activate_latest_sender(state, sess, smtpsess, timestamp, &sender);

            EMAIL_DEBUG(state,
                    "Email worker %d: checking which CCs we need to keep for this sender",
                    state->emailid);
            if (smtpsess->activesender && smtpsess->activesender != sender) {
                EMAIL_DEBUG(state,
                        "Email worker %d: copy CCs that we have saved under the old 'activesender'",
                        state->emailid);
                for (i = smtpsess->activesender->ccs.last_unsent;
                        i < smtpsess->activesender->ccs.curr_command; i++) {
                    copy_smtp_command(&(sender->ccs),
                            &(smtpsess->activesender->ccs.commands[i]));
                }
                EMAIL_DEBUG(state,
                        "Email worker %d: copy completed",
                        state->emailid);
                smtpsess->activesender->ccs.curr_command = 0;
                smtpsess->activesender->last_mail_from = 0;
            } else {
                EMAIL_DEBUG(state,
                        "Email worker %d: copy the usual preamble CCs",
                        state->emailid);
                for (i = 0; i < smtpsess->preambles.curr_command; i++) {
                    copy_smtp_command(&(sender->ccs),
                            &(smtpsess->preambles.commands[i]));
                }
            }

            smtpsess->activesender = sender;
            sender->active = 1;
            sess->login_sent = 0;
            EMAIL_DEBUG(state,
                    "Email worker %d: updated sender to match forwarding header in mail body",
                    state->emailid);
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: no forwarding headers detected",
                    state->emailid);
        }

        /* generate email send CC and IRI */
        EMAIL_DEBUG(state,
                "Email worker %d: generating email-send IRIs if required",
                state->emailid);
        generate_email_send_iri(state, sess);
        EMAIL_DEBUG(state,
                "Email worker %d: generating email-receive IRIs if required",
                state->emailid);
        generate_email_receive_iri(state, sess);
    } else {
        EMAIL_DEBUG(state,
                "Email worker %d: DATA content received reply code %u, returning to RCPT TO OVER state",
                state->emailid, smtpsess->reply_code);
        sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_OVER;
    }

    EMAIL_DEBUG(state,
            "Email worker %d: Saving SMTP payloads for DATA_CONTENT CCs for %s:%s -- content",
            state->emailid, sess->key, sess->sender.emailaddr);

    /* Email is sent, produce CCs for all participants who are targets */
    add_new_smtp_command(&(smtpsess->activesender->ccs),
            smtpsess->command_start, SMTP_COMMAND_TYPE_DATA_CONTENT,
            smtpsess->next_command_index);
    EMAIL_DEBUG(state,
            "Email worker %d: Saving SMTP payloads for DATA_CONTENT CCs for sender -- reply",
            state->emailid);
    add_new_smtp_reply(&(smtpsess->activesender->ccs), smtpsess->reply_start,
            smtpsess->contbufread, smtpsess->reply_code, timestamp);

    EMAIL_DEBUG(state,
            "Email worker %d: Generating DATA_CONTENT CCs for sender",
            state->emailid);
    generate_smtp_ccs_from_saved(state, sess, smtpsess,
            &(smtpsess->activesender->ccs), sess->sender.emailaddr, 1);

    EMAIL_DEBUG(state,
            "Email worker %d: Now tackling recipients",
            state->emailid);
    index[0] = '\0';
    JSLF(pval, smtpsess->recipients, index);
    while (pval) {
        recipient = (smtp_participant_t *)(*pval);

        EMAIL_DEBUG(state,
                "Email worker %d: recipient %s:%s",
            state->emailid, sess->key, index);

        if (recipient->active == 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: recipient %s is inactive, skipping",
                    state->emailid, index);
            JSLN(pval, smtpsess->recipients, index);
            continue;
        }

        EMAIL_DEBUG(state,
                "Email worker %d: Saving SMTP payload for DATA Content -- content",
                state->emailid);
        add_new_smtp_command(&(recipient->ccs), smtpsess->command_start,
                SMTP_COMMAND_TYPE_DATA_CONTENT, smtpsess->next_command_index);
        EMAIL_DEBUG(state,
                "Email worker %d: Saving SMTP payload for DATA Content -- reply",
                state->emailid);
        add_new_smtp_reply(&(recipient->ccs), smtpsess->reply_start,
                smtpsess->contbufread, smtpsess->reply_code, timestamp);

        EMAIL_DEBUG(state,
                "Email worker %d: Generating DATA content CCs",
                state->emailid);
        generate_smtp_ccs_from_saved(state, sess, smtpsess,
                &(recipient->ccs), index, 0);
        JSLN(pval, smtpsess->recipients, index);
    }
    smtpsess->next_command_index ++;
    EMAIL_DEBUG(state,
            "Email worker %d: All recipients done, data_content_over() complete",
            state->emailid);

}

static int set_sender_using_mail_from(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp,
        smtp_participant_t **sender) {

    EMAIL_DEBUG(state,
            "Email worker %d: entering set_sender_using_mail_from()",
            state->emailid);
    if (extract_smtp_participant(state, sess, smtpsess,
                smtpsess->last_mail_from.command_start,
                smtpsess->contbufread) == NULL) {
        EMAIL_DEBUG(state,
                "Email worker %d: failed to extract participant",
                state->emailid);
        return -1;
    }

    EMAIL_DEBUG(state,
            "Email worker %d: extracted sender as %s, now to activate",
            state->emailid, sess->sender.emailaddr);
    activate_latest_sender(state, sess, smtpsess, timestamp, sender);
    EMAIL_DEBUG(state,
            "Email worker %d: set_sender_using_mail_from() completed",
            state->emailid);
    return 1;
}

static int mail_from_reply(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp) {

    int i;
    smtp_participant_t *sender = NULL;

    EMAIL_DEBUG(state,
            "Email worker %d: processing MAIL FROM reply from server",
            state->emailid);

    smtpsess->last_mail_from.reply_end = smtpsess->contbufread;
    smtpsess->last_mail_from.timestamp = timestamp;

    if (smtpsess->last_mail_from.reply_code == 250) {
        EMAIL_DEBUG(state,
                "Email worker %d: seen 250 reply code, changing state to MAIL FROM OVER",
                state->emailid);
        sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM_OVER;

        if (smtpsess->authenticated == 0) {
            /* No authentication, so we have to rely on MAIL FROM to
             * identify the sender (even though it could be spoofed)
             */
            EMAIL_DEBUG(state,
                    "Email worker %d: setting sender for session %s based on MAIL FROM address",
                    state->emailid, sess->key);
            if (set_sender_using_mail_from(state, sess, smtpsess,
                    timestamp, &sender) < 0) {
                return -1;
            }
            sess->login_time = timestamp;
        }

        EMAIL_DEBUG(state,
                "Email worker %d: clearing participant list",
                state->emailid);

        clear_email_participant_list(state, sess);
        if (smtpsess->last_ehlo_reply_code >= 200 &&
                smtpsess->last_ehlo_reply_code < 300) {

            EMAIL_DEBUG(state,
                    "Email worker %d: last EHLO reply was positive",
                    state->emailid);
            if (smtpsess->authenticated == 0 && sender && sender->active == 0) {
                /* this is either a new sender or a previously
                 * inactive one, so we should send a login success IRI */
                EMAIL_DEBUG(state,
                        "Email worker %d: triggering creation of login success IRIs for MAIL FROM sender %s",
                        state->emailid);
                generate_email_login_success_iri(state, sess,
                        sess->sender.emailaddr);
                sess->login_sent = 1;
                sender->active = 1;

                /* Add the latest preamble CCs for this sender.
                 * NOTE: a single intercept can have multiple targets, and
                 * we don't want to send the same EHLO twice for that
                 * intercept just because the sender has changed to a different
                 * target address. This will be handled by the CC generation
                 * methods.
                 */
                EMAIL_DEBUG(state,
                        "Email worker %d: copying preamble CCs for MAIL FROM sender",
                        state->emailid);
                for (i = 0; i < smtpsess->preambles.curr_command; i++) {
                    copy_smtp_command(&(sender->ccs),
                            &(smtpsess->preambles.commands[i]));
                }
                EMAIL_DEBUG(state,
                        "Email worker %d: copy successful",
                        state->emailid);
                smtpsess->activesender = sender;
            } else {
                EMAIL_DEBUG(state,
                        "Email worker %d: MAIL FROM sender does not require a login IRI for session %s",
                        state->emailid, sess->key);
                sender = smtpsess->activesender;
            }

            if (sender == NULL) {
                logger(LOG_INFO, "OpenLI: warning -- SMTP session %s appears to have no valid sender, ignoring session", sess->key);
                smtpsess->ignore = 1;
                return 0;
            }

            /* Generate the CCs for the MAIL FROM command */
            copy_smtp_command(&(sender->ccs), &(smtpsess->last_mail_from));

            EMAIL_DEBUG(state,
                    "Email worker %d: saving MAIL FROM CCs for session %s",
                    state->emailid, sess->key);
            /* Send the CCs */
            /*
            generate_smtp_ccs_from_saved(state, sess, smtpsess,
                    &(sender->ccs), sess->sender.emailaddr, 1);
            */
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: MAIL FROM for session %s after failed EHLO, ignoring",
                    state->emailid, sess->key);
        }
    } else {
        sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
        EMAIL_DEBUG(state,
                "Email worker %d: MAIL FROM for session %s got a reply code of %u, ignoring",
                state->emailid, sess->key, smtpsess->last_mail_from.reply_code);
    }
    EMAIL_DEBUG(state,
            "Email worker %d: MAIL FROM reply processing complete",
            state->emailid);
    return 1;
}

static int process_auth_credentials(smtp_session_t *smtpsess) {

    char *copy, *ptr, *token;

    EMAIL_DEBUG(state,
            "Email worker %d: processing extracted authentication credentials (method=%d)",
            state->emailid, smtpsess->auth_method);

    copy = calloc((smtpsess->contbufused - smtpsess->command_start) + 1,
            sizeof(char));

    memcpy(copy, smtpsess->contbuffer + smtpsess->command_start,
            smtpsess->contbufused - smtpsess->command_start);

    ptr = copy;
    EMAIL_DEBUG(state,
            "Email worker %d: copied credentials to local buffer",
            state->emailid);
    EMAIL_DEBUG(state,
            "Email worker %d: looking for whitespace for end of credentials",
            state->emailid);
    token = strtok(ptr, " \t\r\n");

    if (!token) {
        EMAIL_DEBUG(state,
                "Email worker %d: no whitespace found",
                state->emailid);
        free(copy);
        return -1;
    }

    if (smtpsess->auth_method == SMTP_AUTH_METHOD_PLAIN ||
            smtpsess->auth_method == SMTP_AUTH_METHOD_CRAMMD5) {
        EMAIL_DEBUG(state,
                "Email worker %d: copying token into smtpsess->auth_creds",
                state->emailid);
        if (smtpsess->auth_creds) {
            free(smtpsess->auth_creds);
        }
        smtpsess->auth_creds = strdup(token);
    } else if (smtpsess->auth_method == SMTP_AUTH_METHOD_LOGIN) {
        /* username should be sent first, password will be the following
         * client message */
        if (smtpsess->auth_creds == NULL) {
            EMAIL_DEBUG(state,
                    "Email worker %d: copying username token into smtpsess->auth_creds",
                    state->emailid);
            smtpsess->auth_creds = strdup(token);
        }
    }
    EMAIL_DEBUG(state,
            "Email worker %d: freeing local copy of auth credentials",
            state->emailid);
    free(copy);
    EMAIL_DEBUG(state,
            "Email worker %d: process_auth_credentials completed",
            state->emailid);

    return 1;
}

static int extract_sender_from_auth_creds(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess,
        const char *defaultdomain, char **sendername, uint8_t authed) {

    base64_decodestate s;
    char decoded[2048];
    int cnt, newlen;
    char *ptr = NULL;
    char *sender = NULL;

    if (smtpsess->auth_creds == NULL) {
        return 0;
    }

    EMAIL_DEBUG(state,
            "Email worker %d: parsing authentication credentials (method=%d)",
            state->emailid, smtpsess->auth_method);

    if (smtpsess->auth_method == SMTP_AUTH_METHOD_LOGIN ||
            smtpsess->auth_method == SMTP_AUTH_METHOD_PLAIN ||
            smtpsess->auth_method == SMTP_AUTH_METHOD_CRAMMD5) {

        base64_init_decodestate(&s);
        cnt = base64_decode_block(smtpsess->auth_creds,
                strlen(smtpsess->auth_creds), decoded, &s);
        if (cnt == 0) {
            return 0;
        }
        decoded[cnt] = '\0';
        ptr = decoded;
        EMAIL_DEBUG(state,
                "Email worker %d: base64 decoded successfully",
                state->emailid);
    }

    if (smtpsess->auth_method == SMTP_AUTH_METHOD_LOGIN) {
        EMAIL_DEBUG(state,
                "Email worker %d: parsing LOGIN authentication",
                state->emailid);
        /* should just be a username */
        if (strchr(ptr, '@') == NULL) {
            /* no domain in the username, add our default one */
            EMAIL_DEBUG(state,
                    "Email worker %d: no domain present",
                    state->emailid);
            newlen = strlen(ptr) + strlen(defaultdomain) + 2;
            sender = calloc(newlen, sizeof(char));
            snprintf(sender, newlen, "%s@%s", ptr, defaultdomain);
        } else {
            sender = strdup(ptr);
        }
        EMAIL_DEBUG(state, "Email worker %d: LOGIN, sender is %s",
                state->emailid, sender);
    } else if (smtpsess->auth_method == SMTP_AUTH_METHOD_PLAIN) {
        /* format is [authzid] \0 authcid \0 password
         *
         * we want authcid, but also need to be careful about the
         * case where authzid is not present.
         */
        EMAIL_DEBUG(state,
                "Email worker %d: parsing PLAIN authentication",
                state->emailid);
        ptr += strlen(ptr) + 1;
        if (strchr(ptr, '@') == NULL) {
            /* no domain in the authcid, add our default one */
            EMAIL_DEBUG(state,
                    "Email worker %d: no domain present",
                    state->emailid);
            newlen = strlen(ptr) + strlen(defaultdomain) + 2;
            sender = calloc(newlen, sizeof(char));
            snprintf(sender, newlen, "%s@%s", ptr, defaultdomain);
        } else {
            sender = strdup(ptr);
        }
        EMAIL_DEBUG(state, "Email worker %d: PLAIN, sender is %s",
                state->emailid, sender);
    } else if (smtpsess->auth_method == SMTP_AUTH_METHOD_CRAMMD5) {
        /* format is username <space> digest */
        EMAIL_DEBUG(state,
                "Email worker %d: parsing CRAMMD5 authentication",
                state->emailid);
        char *token = strtok(ptr, " \t\r\n");
        if (token == NULL) {
            return -1;
        }
        if (strchr(token, '@') == NULL) {
            EMAIL_DEBUG(state,
                    "Email worker %d: no domain present",
                    state->emailid);
            newlen = strlen(token) + strlen(defaultdomain) + 2;
            sender = calloc(newlen, sizeof(char));
            snprintf(sender, newlen, "%s@%s", token, defaultdomain);
        } else {
            sender = strdup(token);
        }
        EMAIL_DEBUG(state, "Email worker %d: CRAMMD5, sender is %s",
                state->emailid, sender);
    }

    if (sender) {
        *sendername = sender;
        if (authed) {
            EMAIL_DEBUG(state, "Email worker %d: adding sender as participant",
                    state->emailid);
            add_email_participant(state, sess, sender, 1);
        }
        EMAIL_DEBUG(state,
                "Email worker %d: authentication credentials parsed successfully",
                state->emailid);
        return 1;
    } else {
        EMAIL_DEBUG(state,
                "Email worker %d: unsupported authentication method",
                state->emailid);
        return 0;
    }

}

static int authenticate_success(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp) {

    int r, i;
    smtp_participant_t *sender = NULL;
    char *sendername = NULL;
    const char *defaultdomain;

    pthread_rwlock_rdlock(state->glob_config_mutex);
    if (state->defaultdomain) {
        defaultdomain = (const char *)(*(state->defaultdomain));
    } else {
        defaultdomain = "example.org";
    }

    EMAIL_DEBUG(state,
            "Email worker %d: extracting auth credentials following auth failure -- default domain is %s",
            state->emailid, defaultdomain);
    r = extract_sender_from_auth_creds(state, sess, smtpsess, defaultdomain,
            &sendername, 1);
    pthread_rwlock_unlock(state->glob_config_mutex);

    if (r <= 0) {
        return r;
    }

    EMAIL_DEBUG(state,
            "Email worker %d: activating new sender", state->emailid);

    activate_latest_sender(state, sess, smtpsess, timestamp, &sender);
    smtpsess->activesender = sender;
    smtpsess->authenticated = 1;
    sess->login_time = timestamp;

    /* send login IRI and any pending CCs */

    /* Note: 0 is the value defined in the ETSI spec for "validated", so
     * this is CORRECT
     */
    EMAIL_DEBUG(state,
            "Email worker %d: generating login success IRI for %s",
            state->emailid, sendername);
    sess->sender_validated_etsivalue = 0;
    generate_email_login_success_iri(state, sess, sess->sender.emailaddr);
    sess->login_sent = 1;
    sender->active = 1;

    EMAIL_DEBUG(state,
            "Email worker %d: copying %d preambles into sender->ccs",
            state->emailid, smtpsess->preambles.curr_command);
    for (i = 0; i < smtpsess->preambles.curr_command; i++) {
        copy_smtp_command(&(sender->ccs),
                &(smtpsess->preambles.commands[i]));
    }

    EMAIL_DEBUG(state,
            "Email worker %d: sending CCs following authentication success",
            state->emailid);
    /* Send the CCs */
    generate_smtp_ccs_from_saved(state, sess, smtpsess,
                    &(sender->ccs), sess->sender.emailaddr, 1);
    return 1;
}

static int authenticate_failure(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp) {

    char *sendername = NULL;
    int r, i;
    const char *defaultdomain = NULL;

    pthread_rwlock_rdlock(state->glob_config_mutex);
    if (state->defaultdomain) {
        defaultdomain = (const char *)(*(state->defaultdomain));
    } else {
        defaultdomain = "example.org";
    }
    EMAIL_DEBUG(state,
            "Email worker %d: extracting auth credentials following auth failure -- default domain is %s",
            state->emailid, defaultdomain);

    r = extract_sender_from_auth_creds(state, sess, smtpsess, defaultdomain,
            &sendername, 0);
    pthread_rwlock_unlock(state->glob_config_mutex);
    if (r <= 0) {
        return r;
    }

    EMAIL_DEBUG(state,
            "Email worker %d: generating login failure IRI for %s",
            state->emailid, sendername);
    generate_email_login_failure_iri(state, sess, sendername);

    EMAIL_DEBUG(state,
            "Email worker %d: sending CCs for authentication failure event",
            state->emailid);
    /* Send the CCs */
    generate_smtp_ccs_from_saved(state, sess, smtpsess,
                    &(smtpsess->preambles), sendername, 1);

    return 1;
}


static int process_next_smtp_state(openli_email_worker_t *state,
        emailsession_t *sess, smtp_session_t *smtpsess, uint64_t timestamp) {
    int r;

    /* TODO consider adding state parsing for AUTH, STARTTLS, VRFY, EXPN
     * and any other SMTP commands that exist -- it will only really
     * matter for octet counting reasons and I doubt the LEAs care that
     * much, but something to bear in mind...
     */

    EMAIL_DEBUG(state, "Email worker %d: entering process_next_smtp_state",
            state->emailid);

    if (sess->currstate != OPENLI_SMTP_STATE_DATA_CONTENT) {
        EMAIL_DEBUG(state, "Email worker %d: checking for QUIT",
                state->emailid);
        if ((r = find_quit_command(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_QUIT;
            sess->client_octets += 6;
            smtpsess->reply_start = smtpsess->contbufread;
            EMAIL_DEBUG(state, "Email worker %d: setting session state to QUIT",
                    state->emailid);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: no QUIT command was found",
                    state->emailid);
        }
    }

    if (sess->currstate != OPENLI_SMTP_STATE_DATA_CONTENT) {
        EMAIL_DEBUG(state, "Email worker %d: checking for RSET",
                state->emailid);
        if ((r = find_reset_command(smtpsess)) == 1) {
            smtpsess->saved_state = sess->currstate;
            sess->currstate = OPENLI_SMTP_STATE_RESET;
            sess->client_octets += 6;
            smtpsess->reply_start = smtpsess->contbufread;
            EMAIL_DEBUG(state, "Email worker %d: setting session state to RSET",
                    state->emailid);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: no RSET command was found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_INIT ||
            sess->currstate == OPENLI_SMTP_STATE_EHLO_OVER) {
        EMAIL_DEBUG(state, "Email worker %d: checking for EHLO",
                state->emailid);
        if ((r = find_ehlo_start(sess, smtpsess)) == 1) {
            EMAIL_DEBUG(state, "Email worker %d: setting session state to EHLO",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_EHLO;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: no EHLO command was found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_EHLO) {
        EMAIL_DEBUG(state,
                "Email worker %d: looking for the end of the EHLO command",
                state->emailid);
        if ((r = find_ehlo_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found the end of the EHLO command",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_EHLO_RESPONSE;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->command_start);
            smtpsess->reply_start = smtpsess->contbufread;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: still waiting for the end of the EHLO command",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_EHLO_RESPONSE) {
        EMAIL_DEBUG(state,
                "Email worker %d: looking for the reply to an EHLO",
                state->emailid);

        if ((r = find_ehlo_response_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found a complete reply -- %u",
                    state->emailid, smtpsess->reply_code);
            sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
            sess->server_octets +=
                    (smtpsess->contbufread - smtpsess->reply_start);

            add_new_smtp_reply(&(smtpsess->preambles), smtpsess->reply_start,
                    smtpsess->contbufread, smtpsess->reply_code, timestamp);
            smtpsess->last_ehlo_reply_code = smtpsess->reply_code;
            EMAIL_DEBUG(state,
                    "Email worker %d: moving into EHLO OVER state",
                    state->emailid);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: no complete reply to EHLO found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_EHLO_OVER) {
        EMAIL_DEBUG(state,
                "Email worker %d: looking for next command in EHLO OVER state",
                state->emailid);
        if ((r = find_mail_from(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found a MAIL FROM command",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM;
            smtpsess->last_mail_from.command_type = SMTP_COMMAND_TYPE_MAIL_FROM;
            smtpsess->last_mail_from.command_start = smtpsess->contbufread;
            smtpsess->last_mail_from.command_index =
                    smtpsess->next_command_index;
            smtpsess->next_command_index ++;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        }
        if ((r = find_auth(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found a AUTH command",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_AUTH;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        }
        if ((r = find_starttls(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found a STARTTLS command",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_STARTTLS;
            sess->client_octets += 10;
            smtpsess->reply_start = smtpsess->contbufread;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        }
        if ((r = find_other_command(smtpsess, sess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found an unexpected command",
                    state->emailid);
            smtpsess->saved_state = sess->currstate;
            sess->currstate = OPENLI_SMTP_STATE_OTHER_COMMAND;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: no useful command has been found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_AUTH) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for end of an AUTH command",
                state->emailid);
        if ((r = find_auth_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of AUTH command found",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_AUTH_REPLY;
            smtpsess->reply_start = smtpsess->contbufread;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->command_start);
            if (process_auth_message(smtpsess) < 0) {
                EMAIL_DEBUG(state,
                        "Email worker %d: error in process_auth_message while in process_next_smtp_state",
                        state->emailid);
                return -1;
            }
            EMAIL_DEBUG(state,
                    "Email worker %d: AUTH command processed successfully",
                    state->emailid);
            add_new_smtp_command(&(smtpsess->preambles),
                    smtpsess->command_start,SMTP_COMMAND_TYPE_AUTH,
                    smtpsess->next_command_index);
            smtpsess->next_command_index ++;
            EMAIL_DEBUG(state,
                    "Email worker %d: moving into AUTH REPLY state",
                    state->emailid);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: AUTH command is not yet complete",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_AUTH_REPLY) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for reply to an AUTH command",
                state->emailid);
        if ((r = find_auth_reply_code(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: reply code found -- %u",
                    state->emailid, smtpsess->reply_code);

            add_new_smtp_reply(&(smtpsess->preambles), smtpsess->reply_start,
                    smtpsess->contbufread, smtpsess->reply_code, timestamp);
            if (smtpsess->reply_code == 334) {
                sess->currstate = OPENLI_SMTP_STATE_AUTH_CREDS;
            } else if (smtpsess->reply_code == 235) {
                if (authenticate_success(state, sess, smtpsess,
                            timestamp) < 0) {
                    EMAIL_DEBUG(state,
                            "Email worker %d: error in authenticate_success while in process_next_smtp_state",
                            state->emailid);
                    return -1;
                }
                EMAIL_DEBUG(state,
                        "Email worker %d: authentication successful",
                        state->emailid);
                sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
            } else if (smtpsess->reply_code == 535) {
                if (authenticate_failure(state, sess, smtpsess, timestamp) < 0)
                {
                    EMAIL_DEBUG(state,
                            "Email worker %d: error in authenticate_failure while in process_next_smtp_state",
                            state->emailid);
                    return -1;
                }
                EMAIL_DEBUG(state,
                        "Email worker %d: authentication failed",
                        state->emailid);
                sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
            }
            sess->server_octets += (smtpsess->contbufread -
                    smtpsess->reply_start);
            smtpsess->command_start = smtpsess->contbufread;
            EMAIL_DEBUG(state,
                    "Email worker %d: authentication reply processed successfully",
                    state->emailid);
            return 1;

        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: unable to find reply code for AUTH",
                    state->emailid);
        }

    }

    if (sess->currstate == OPENLI_SMTP_STATE_AUTH_CREDS) {
        EMAIL_DEBUG(state,
                "Email worker %d: looking for end of AUTH credentials",
                state->emailid);
        if ((r = find_auth_creds_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of AUTH credentials has been found",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_AUTH_REPLY;
            smtpsess->reply_start = smtpsess->contbufread;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->command_start);
            if (process_auth_credentials(smtpsess) < 0) {
                EMAIL_DEBUG(state,
                        "Email worker %d: error while processing AUTH credentials in process_next_smtp_state",
                        state->emailid);
                return -1;
            }
            EMAIL_DEBUG(state,
                    "Email worker %d: processed AUTH credentials successfully",
                    state->emailid);
            add_new_smtp_command(&(smtpsess->preambles),
                    smtpsess->command_start, SMTP_COMMAND_TYPE_AUTH,
                    smtpsess->next_command_index);
            EMAIL_DEBUG(state,
                    "Email worker %d: AUTH command processing completed",
                    state->emailid);
            smtpsess->next_command_index ++;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of AUTH credentials not found",
                    state->emailid);
        }
    }


    if (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for end of a MAIL FROM command",
                state->emailid);
        if ((r = find_mail_from_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of MAIL FROM command found",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM_REPLY;
            smtpsess->last_mail_from.reply_start = smtpsess->contbufread;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->command_start);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of MAIL FROM command was not found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM_REPLY) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for reply to a MAIL FROM command",
                state->emailid);
        if ((r = find_mail_from_reply_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found a MAIL FROM reply code -- %u",
                    state->emailid, smtpsess->reply_code);
            return mail_from_reply(state, sess, smtpsess, timestamp);
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: no reply code found for MAIL FROM",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_MAIL_FROM_OVER) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for a command following a completed MAIL FROM",
                state->emailid);
        if ((r = find_rcpt_to(smtpsess)) == 1) {
            sess->currstate = OPENLI_SMTP_STATE_RCPT_TO;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        }
        if ((r = find_other_command(smtpsess, sess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found an unexpected command",
                    state->emailid);
            smtpsess->saved_state = sess->currstate;
            sess->currstate = OPENLI_SMTP_STATE_OTHER_COMMAND;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: no post-MAIL FROM command found",
                    state->emailid);
        }

    }

    if (sess->currstate == OPENLI_SMTP_STATE_OTHER_COMMAND) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for end of 'other' command",
                state->emailid);
        if ((r = find_other_command_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of other command found",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_OTHER_COMMAND_REPLY;
            smtpsess->reply_start = smtpsess->contbufread;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->command_start);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of other command NOT found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_OTHER_COMMAND_REPLY) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for end of reply to 'other' command",
                state->emailid);
        if ((r = find_other_command_reply_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of reply to other command found",
                    state->emailid);
            return other_command_reply(state, sess, smtpsess, timestamp);
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of reply to other command NOT found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RCPT_TO) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for end of RCPT TO command",
                state->emailid);
        if ((r = find_rcpt_to_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of RCPT TO command found",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_REPLY;
            smtpsess->reply_start = smtpsess->contbufread;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->command_start);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of RCPT TO command NOT found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RCPT_TO_REPLY) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for end of RCPT TO reply",
                state->emailid);
        if ((r = find_rcpt_to_reply_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of RCPT TO reply found: %u",
                    state->emailid, smtpsess->reply_code);

            return rcpt_to_reply(state, sess, smtpsess, timestamp);
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: end of RCPT TO reply NOT found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RCPT_TO_OVER) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for command after RCPT TO completed",
                state->emailid);
        if ((r = find_rcpt_to(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found another RCPT TO",
                    state->emailid);
                sess->currstate = OPENLI_SMTP_STATE_RCPT_TO;
            /* Need to restart the loop to handle RCPT_TO state again */
            return 1;
        } else if ((r = find_data_start(smtpsess)) == 1) {

            EMAIL_DEBUG(state,
                    "Email worker %d: found a DATA command",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_DATA_INIT_REPLY;
            sess->client_octets += 6;
            smtpsess->reply_start = smtpsess->contbufread;
            return 1;
        } else if ((r = find_mail_from(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found a MAIL FROM",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM;
            smtpsess->last_mail_from.command_type = SMTP_COMMAND_TYPE_MAIL_FROM;
            smtpsess->last_mail_from.command_start = smtpsess->contbufread;
            smtpsess->last_mail_from.command_index =
                    smtpsess->next_command_index;
            smtpsess->next_command_index ++;
            return 1;
        } else if ((r = find_other_command(smtpsess, sess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found an unexpected command",
                    state->emailid);
            smtpsess->saved_state = sess->currstate;
            sess->currstate = OPENLI_SMTP_STATE_OTHER_COMMAND;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: did not find anything useful",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_DATA_INIT_REPLY) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for initial reply to DATA",
                state->emailid);
        if ((r = find_data_init_reply_code(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found reply code %u",
                    state->emailid, smtpsess->reply_code);
            if (smtpsess->reply_code == 354) {
                sess->currstate = OPENLI_SMTP_STATE_DATA_CONTENT;
            } else {
                sess->currstate = OPENLI_SMTP_STATE_RCPT_TO_OVER;
            }

            save_latest_command(state, sess, smtpsess, timestamp,
                    SMTP_COMMAND_TYPE_DATA, 0, 0);
            EMAIL_DEBUG(state,
                    "Email worker %d: saved DATA command successfully",
                    state->emailid);
            smtpsess->command_start = smtpsess->contbufread;
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: initial reply to DATA is not present",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_DATA_CONTENT) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for end of DATA content",
                state->emailid);
        if ((r = find_data_content_ending(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: reached end of content",
                    state->emailid, smtpsess->reply_code);
            sess->currstate = OPENLI_SMTP_STATE_DATA_FINAL_REPLY;
            smtpsess->reply_start = smtpsess->contbufread;
            sess->client_octets +=
                    (smtpsess->contbufread - smtpsess->command_start);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: still more DATA content to come",
                    state->emailid, smtpsess->reply_code);
        }

    }

    if (sess->currstate == OPENLI_SMTP_STATE_DATA_FINAL_REPLY) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for final reply code in DATA state",
                state->emailid);
        if ((r = find_data_final_reply_code(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found reply code %u",
                    state->emailid, smtpsess->reply_code);
            data_content_over(state, sess, smtpsess, timestamp);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: No reply code found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_DATA_OVER) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for follow up command in DATA OVER state",
                state->emailid);
        if ((r = find_mail_from(smtpsess)) == 1) {
            /* client is re-using the session to send another email? */
            EMAIL_DEBUG(state,
                    "Email worker %d: MAIL FROM found",
                    state->emailid);
            sess->currstate = OPENLI_SMTP_STATE_MAIL_FROM;
            smtpsess->last_mail_from.command_type = SMTP_COMMAND_TYPE_MAIL_FROM;
            smtpsess->last_mail_from.command_start = smtpsess->contbufread;
            smtpsess->last_mail_from.command_index =
                    smtpsess->next_command_index;
            smtpsess->next_command_index ++;
            return 1;
        } else if ((r = find_other_command(smtpsess, sess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: Unexpected command found, moving to OTHER COMMAND state",
                    state->emailid);
            smtpsess->saved_state = sess->currstate;
            sess->currstate = OPENLI_SMTP_STATE_OTHER_COMMAND;
            return 1;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: No follow up command found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_STARTTLS) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for STARTTLS reply code",
                state->emailid);
        if ((r = find_starttls_reply_end(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: found reply code %u",
                    state->emailid, smtpsess->reply_code);

            sess->server_octets +=
                    (smtpsess->contbufread - smtpsess->reply_start);
            if (smtpsess->reply_code == 220) {
                /* Session is now encrypted... */
                logger(LOG_INFO,
                        "OpenLI: SMTP session '%s' is encrypted, cannot intercept",
                        sess->key);
                smtpsess->ignore = 1;
                return 0;
            }
            /* May as well include the STARTTLS attempt in the preamble
             * CCs
             */
            EMAIL_DEBUG(state,
                    "Email worker %d: STARTTLS failed, session is not encrypted",
                    state->emailid);
            add_new_smtp_command(&(smtpsess->preambles),
                    smtpsess->command_start, SMTP_COMMAND_TYPE_STARTTLS,
                    smtpsess->next_command_index);
            EMAIL_DEBUG(state,
                    "Email worker %d: STARTTLS add_new_smtp_command complete",
                    state->emailid);
            add_new_smtp_reply(&(smtpsess->preambles),
                    smtpsess->reply_start, smtpsess->contbufread,
                    smtpsess->reply_code, timestamp);
            EMAIL_DEBUG(state,
                    "Email worker %d: STARTTLS add_new_smtp_reply complete",
                    state->emailid);
            smtpsess->next_command_index ++;
            sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
            EMAIL_DEBUG(state,
                    "Email worker %d: STARTTLS complete, moving to EHLO OVER state",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_RESET) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for RSET reply code",
                state->emailid);
        if ((r = find_reset_reply_code(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: RSET reply code detected -- %u",
                    state->emailid, smtpsess->reply_code);
            if (smtpsess->saved_state == OPENLI_SMTP_STATE_INIT ||
                    smtpsess->saved_state == OPENLI_SMTP_STATE_EHLO_OVER ||
                    smtpsess->saved_state == OPENLI_SMTP_STATE_DATA_OVER) {
                EMAIL_DEBUG(state,
                        "Email worker %d: saved state is %u, reset to INIT",
                        state->emailid, smtpsess->saved_state);
                sess->currstate = smtpsess->saved_state;
                smtpsess->saved_state = OPENLI_SMTP_STATE_INIT;
            } else {
                EMAIL_DEBUG(state,
                        "Email worker %d: saved state is %u, reset to EHLO OVER",
                        state->emailid, smtpsess->saved_state);
                sess->currstate = OPENLI_SMTP_STATE_EHLO_OVER;
                smtpsess->saved_state = OPENLI_SMTP_STATE_INIT;

            }
            if (sess->currstate != OPENLI_SMTP_STATE_DATA_OVER) {
                EMAIL_DEBUG(state,
                        "Email worker %d: clearing participant list",
                        state->emailid);
                clear_email_participant_list(state, sess);
                set_all_smtp_participants_inactive(smtpsess);
            } else {
                EMAIL_DEBUG(state,
                        "Email worker %d: no need to clear participant list",
                        state->emailid);
            }

            save_latest_command(state, sess, smtpsess, timestamp,
                    SMTP_COMMAND_TYPE_RSET, 1, 0);
            EMAIL_DEBUG(state,
                    "Email worker %d: finished updating for RSET reply code",
                    state->emailid);
            return 1;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: RSET reply code not found",
                    state->emailid);
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_QUIT) {
        EMAIL_DEBUG(state,
                "Email worker %d: checking for QUIT reply code",
                state->emailid);
        if ((r = find_quit_reply_code(smtpsess)) == 1) {
            EMAIL_DEBUG(state,
                    "Email worker %d: QUIT reply code detected -- %u",
                    state->emailid, smtpsess->reply_code);
            sess->currstate = OPENLI_SMTP_STATE_QUIT_REPLY;
            sess->event_time = timestamp;
            if (sess->login_sent) {
                EMAIL_DEBUG(state,
                        "Email worker %d: generating logoff event",
                        state->emailid);
                generate_email_logoff_iri(state, sess);
            } else {
                EMAIL_DEBUG(state,
                        "Email worker %d: NOT generating logoff event",
                        state->emailid);
            }

            save_latest_command(state, sess, smtpsess, timestamp,
                    SMTP_COMMAND_TYPE_QUIT, 1, 0);
            EMAIL_DEBUG(state,
                    "Email worker %d: finished updating for QUIT reply code",
                    state->emailid);
            return 0;
        } else if (r < 0) {
            EMAIL_DEBUG(state,
                    "Email worker %d: error while in process_next_smtp_state",
                    state->emailid);
            return r;
        } else {
            EMAIL_DEBUG(state,
                    "Email worker %d: QUIT reply code not found",
                    state->emailid);
        }

    }

    EMAIL_DEBUG(state,
            "Email worker %d: reached end of process_next_smtp_state",
            state->emailid);
    return 0;
}

int update_smtp_session_by_ingestion(openli_email_worker_t *state,
        emailsession_t *sess, openli_email_captured_t *cap) {
    smtp_session_t *smtpsess;
    int r;

    EMAIL_DEBUG(state, "Email worker %d: updating SMTP session %s",
            state->emailid, sess->key);

    if (sess->proto_state == NULL) {
        smtpsess = calloc(1, sizeof(smtp_session_t));
        smtpsess->messageid = NULL;
        smtpsess->contbuffer = calloc(1024, sizeof(uint8_t));
        smtpsess->contbufused = 0;
        smtpsess->contbufread = 0;
        smtpsess->contbufsize = 1024;

        smtpsess->preambles.commands = calloc(10, sizeof(smtp_command_t));
        smtpsess->preambles.commands_size = 10;
        smtpsess->preambles.curr_command = 0;

        smtpsess->senders = (Pvoid_t)NULL;
        smtpsess->recipients = (Pvoid_t)NULL;

        smtpsess->auth_method = SMTP_AUTH_METHOD_NONE;
        smtpsess->auth_creds = NULL;
        smtpsess->authenticated = 0;
        smtpsess->ignore = 0;

        smtpsess->next_command_index = 0;

        sess->proto_state = (void *)smtpsess;
        /* Note: 1 is the value defined in the ETSI spec for "not validated", so
         * this is CORRECT
         */
        sess->sender_validated_etsivalue = 1;
        EMAIL_DEBUG(state,
                "Email worker %d: session is new, initializing SMTP state",
                state->emailid);
    } else {
        smtpsess = (smtp_session_t *)sess->proto_state;
    }

    if (smtpsess->ignore) {
        EMAIL_DEBUG(state, "Email worker %d: ignore flag is set for session",
                state->emailid);
    }

    if (cap->content == NULL) {
        EMAIL_DEBUG(state, "Email worker %d: no content in provided message",
                state->emailid);
    }

    if (cap->content != NULL && smtpsess->ignore == 0) {

        EMAIL_DEBUG(state, "Email worker %d: appending content to SMTP buffer",
                state->emailid);
        if (append_content_to_smtp_buffer(smtpsess, cap, sess) < 0) {
            logger(LOG_INFO, "OpenLI: Failed to append SMTP message content to session buffer for %s", sess->key);
            return -1;
        }

        EMAIL_DEBUG(state, "Email worker %d: processing buffer contents",
                state->emailid);
        while (1) {
            if ((r = process_next_smtp_state(state, sess, smtpsess,
                    cap->timestamp)) <= 0) {
                break;
            }
        }
    }

    if (sess->currstate == OPENLI_SMTP_STATE_QUIT_REPLY) {
        EMAIL_DEBUG(state, "Email worker %d: SMTP session has ended via QUIT",
                state->emailid);
        return 1;
    }

    EMAIL_DEBUG(state, "Email worker %d: SMTP state update completed",
            state->emailid);
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
