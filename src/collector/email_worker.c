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

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <amqp_tcp_socket.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "util.h"
#include "logger.h"
#include "collector_base.h"
#include "collector_publish.h"
#include "email_worker.h"
#include "netcomms.h"
#include "intercept.h"
#include "timed_intercept.h"
#include "collector.h"

static inline const char *email_type_to_string(openli_email_type_t t) {
    if (t == OPENLI_EMAIL_TYPE_POP3) {
        return "POP3";
    }
    if (t == OPENLI_EMAIL_TYPE_SMTP) {
        return "SMTP";
    }
    if (t == OPENLI_EMAIL_TYPE_IMAP) {
        return "IMAP";
    }
    return "UNKNOWN";
}

static struct sockaddr_storage *construct_sockaddr(char *ip, char *port,
        int *family) {

    struct sockaddr_storage *saddr;
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(ip, port, &hints, &res);
    if (err != 0) {
        logger(LOG_INFO, "OpenLI: error in email worker thread converting %s:%s into a socket address: %s", ip, port, strerror(errno));
        return NULL;
    }

    if (!res) {
        logger(LOG_INFO, "OpenLI: email worker thread was unable to convert %s:%s into a valid socket address?", ip, port);
        return NULL;
    }

    /* Just use the first result -- there should only be one anyway... */

    if (family) {
        *family = res->ai_family;
    }
    saddr = calloc(1, sizeof(struct sockaddr_storage));
    memcpy(saddr, res->ai_addr, res->ai_addrlen);

    char host[256];
    char serv[256];

    getnameinfo((struct sockaddr *)saddr, sizeof(struct sockaddr_storage),
            host, 256, serv, 256, NI_NUMERICHOST | NI_NUMERICSERV);

    freeaddrinfo(res);
    return saddr;
}

void replace_email_session_serveraddr(emailsession_t *sess,
        char *server_ip, char *server_port) {

    if (sess->serveraddr) {
        free(sess->serveraddr);
    }

    sess->serveraddr = construct_sockaddr(server_ip, server_port,
            &(sess->ai_family));

}

void replace_email_session_clientaddr(emailsession_t *sess,
        char *client_ip, char *client_port) {

    if (sess->clientaddr) {
        free(sess->clientaddr);
    }

    sess->clientaddr = construct_sockaddr(client_ip, client_port, NULL);

}

static openli_email_captured_t *convert_packet_to_email_captured(
        libtrace_packet_t *pkt, uint8_t emailtype) {

    char space[256];
    int spacelen = 256;
    char ip_a[INET6_ADDRSTRLEN];
    char ip_b[INET6_ADDRSTRLEN];
    char portstr[16];
    libtrace_tcp_t *tcp;
    uint32_t rem;
    uint8_t proto;
    void *posttcp;

    uint16_t src_port, dest_port, rem_port, host_port;
    openli_email_captured_t *cap = NULL;

    src_port = trace_get_source_port(pkt);
    dest_port = trace_get_destination_port(pkt);

    if (src_port == 0 || dest_port == 0) {
        return NULL;
    }

    tcp = (libtrace_tcp_t *)(trace_get_transport(pkt, &proto, &rem));
    if (tcp == NULL || proto != TRACE_IPPROTO_TCP || rem == 0) {
        return NULL;
    }

    posttcp = trace_get_payload_from_tcp(tcp, &rem);

    /* Ensure that bi-directional flows return the same session ID by
     * always putting the IP and port for the endpoint with the smallest of
     * the two ports first...
     */

    if (src_port < dest_port) {
        if (trace_get_source_address_string(pkt, ip_a, INET6_ADDRSTRLEN)
                == NULL) {
            return NULL;
        }
        if (trace_get_destination_address_string(pkt, ip_b, INET6_ADDRSTRLEN)
                == NULL) {
            return NULL;
        }

        rem_port = dest_port;
        host_port = src_port;
    } else {
        if (trace_get_source_address_string(pkt, ip_b, INET6_ADDRSTRLEN)
                == NULL) {
            return NULL;
        }
        if (trace_get_destination_address_string(pkt, ip_a, INET6_ADDRSTRLEN)
                == NULL) {
            return NULL;
        }
        host_port = dest_port;
        rem_port = src_port;
    }

    snprintf(space, spacelen, "%s-%s-%u-%u", ip_a, ip_b, host_port,
            rem_port);

    cap = calloc(1, sizeof(openli_email_captured_t));
    if (emailtype == OPENLI_UPDATE_SMTP) {
        cap->type = OPENLI_EMAIL_TYPE_SMTP;
    } else if (emailtype == OPENLI_UPDATE_IMAP) {
        cap->type = OPENLI_EMAIL_TYPE_IMAP;
    } else if (emailtype == OPENLI_UPDATE_POP3) {
        cap->type = OPENLI_EMAIL_TYPE_POP3;
    } else {
        cap->type = OPENLI_EMAIL_TYPE_UNKNOWN;
    }

    cap->session_id = strdup(space);
    cap->target_id = NULL;
    cap->datasource = NULL;
    cap->remote_ip = strdup(ip_b);
    cap->host_ip = strdup(ip_a);


    snprintf(portstr, 16, "%u", rem_port);
    cap->remote_port = strdup(portstr);
    snprintf(portstr, 16, "%u", host_port);
    cap->host_port = strdup(portstr);

    cap->timestamp = (trace_get_seconds(pkt) * 1000);
    cap->mail_id = 0;
    cap->msg_length = trace_get_payload_length(pkt);

    if (cap->msg_length > rem) {
        cap->msg_length = rem;
    }


    cap->own_content = 0;
    if (cap->msg_length > 0 && posttcp != NULL) {
        cap->content = (char *)posttcp;
    } else {
        cap->content = NULL;
    }
    return cap;
}

static void init_email_session(emailsession_t *sess,
        openli_email_captured_t *cap, char *sesskey,
        openli_email_worker_t *state) {

    struct sockaddr_storage *saddr;

    sess->key = strdup(sesskey);
    sess->cin = hashlittle(cap->session_id, strlen(cap->session_id),
            1872422);
    sess->session_id = strdup(cap->session_id);

    if (cap->type == OPENLI_EMAIL_TYPE_SMTP ||
            cap->type == OPENLI_EMAIL_TYPE_IMAP ||
            cap->type == OPENLI_EMAIL_TYPE_POP3) {
        sess->serveraddr = construct_sockaddr(cap->host_ip, cap->host_port,
                &sess->ai_family);
        sess->clientaddr = construct_sockaddr(cap->remote_ip, cap->remote_port,
                NULL);
    } else {
        /* TODO */
    }

    if (cap->type == OPENLI_EMAIL_TYPE_IMAP) {
        pthread_rwlock_rdlock(state->glob_config_mutex);
        sess->mask_credentials = *(state->mask_imap_creds);
        pthread_rwlock_unlock(state->glob_config_mutex);
    } else if (cap->type == OPENLI_EMAIL_TYPE_POP3) {
        pthread_rwlock_rdlock(state->glob_config_mutex);
        sess->mask_credentials = *(state->mask_pop3_creds);
        pthread_rwlock_unlock(state->glob_config_mutex);
    } else {
        sess->mask_credentials = 0;
    }

    memset(&(sess->sender), 0, sizeof(email_participant_t));
    sess->participants = NULL;
    sess->protocol = cap->type;
    sess->currstate = 0;
    sess->timeout_ev = NULL;
    sess->proto_state = NULL;
    sess->server_octets = 0;
    sess->client_octets = 0;
}

void add_email_participant(emailsession_t *sess, char *address, int issender) {

    email_participant_t *part;

    if (!issender) {
        HASH_FIND(hh, sess->participants, address, strlen(address), part);
        if (!part) {
            part = calloc(1, sizeof(email_participant_t));
            part->emailaddr = address;
            part->is_sender = 0;
            HASH_ADD_KEYPTR(hh, sess->participants, part->emailaddr,
                    strlen(part->emailaddr), part);

            logger(LOG_INFO, "OpenLI: DEVDEBUG adding %s as a recipient for email session %s", address, sess->key);
        }
    } else {
        if (sess->sender.emailaddr) {
            free(sess->sender.emailaddr);
        }
        sess->sender.emailaddr = address;
        sess->sender.is_sender = 1;
        logger(LOG_INFO, "OpenLI: DEVDEBUG adding %s as the sender for email session %s", address, sess->key);
    }

}

void clear_email_participant_list(emailsession_t *sess) {

    email_participant_t *part, *tmp;

    if (!sess) {
        return;
    }
    HASH_ITER(hh, sess->participants, part, tmp) {
        HASH_DELETE(hh, sess->participants, part);
        if (part->emailaddr) {
            free(part->emailaddr);
        }
        free(part);
    }

}

void clear_email_sender(emailsession_t *sess) {

    if (!sess) {
        return;
    }
    if (sess->sender.emailaddr) {
        free(sess->sender.emailaddr);
        sess->sender.emailaddr = NULL;
    }
}

static void free_email_session(openli_email_worker_t *state,
        emailsession_t *sess) {


    if (!sess) {
        return;
    }

    clear_email_sender(sess);
    clear_email_participant_list(sess);

    if (sess->timeout_ev) {
        sync_epoll_t *ev, *found;
        ev = (sync_epoll_t *)sess->timeout_ev;
        HASH_FIND(hh, state->timeouts, &(ev->fd), sizeof(int), found);
        if (found) {
            HASH_DELETE(hh, state->timeouts, found);
        }
        close(ev->fd);
        free(ev);

        logger(LOG_INFO, "OpenLI: DEVDEBUG removed timeout event for %s",
                sess->key);
    }

    if (sess->protocol == OPENLI_EMAIL_TYPE_SMTP) {
        free_smtp_session_state(sess, sess->proto_state);
    }

    if (sess->protocol == OPENLI_EMAIL_TYPE_IMAP) {
        free_imap_session_state(sess, sess->proto_state);
    }

    if (sess->protocol == OPENLI_EMAIL_TYPE_POP3) {
        free_pop3_session_state(sess, sess->proto_state);
    }

    if (sess->serveraddr) {
        free(sess->serveraddr);
    }
    if (sess->clientaddr) {
        free(sess->clientaddr);
    }
    if (sess->session_id) {
        free(sess->session_id);
    }
    if (sess->key) {
        free(sess->key);
    }
    free(sess);

}

static void update_email_session_timeout(openli_email_worker_t *state,
        emailsession_t *sess) {
    sync_epoll_t *timerev, *syncev;
    struct itimerspec its;

    if (sess->timeout_ev) {
        timerev = (sync_epoll_t *)(sess->timeout_ev);

        HASH_FIND(hh, state->timeouts, &(timerev->fd), sizeof(int), syncev);
        if (syncev) {
            HASH_DELETE(hh, state->timeouts, syncev);
        }
        close(timerev->fd);
    } else {
        timerev = (sync_epoll_t *) calloc(1, sizeof(sync_epoll_t));
    }

    pthread_rwlock_rdlock(state->glob_config_mutex);
    if (sess->protocol == OPENLI_EMAIL_TYPE_SMTP) {
        its.it_value.tv_sec = state->timeout_thresholds->smtp * 60;
    } else if (sess->protocol == OPENLI_EMAIL_TYPE_POP3) {
        its.it_value.tv_sec = state->timeout_thresholds->pop3 * 60;
    } else if (sess->protocol == OPENLI_EMAIL_TYPE_IMAP) {
        its.it_value.tv_sec = state->timeout_thresholds->imap * 60;
    } else {
        its.it_value.tv_sec = 600;
    }
    pthread_rwlock_unlock(state->glob_config_mutex);

    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    sess->timeout_ev = (void *)timerev;
    timerev->fdtype = 0;
    timerev->fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(timerev->fd, 0, &its, NULL);

    timerev->ptr = sess;
    HASH_ADD_KEYPTR(hh, state->timeouts, &(timerev->fd), sizeof(int), timerev);

}

void free_captured_email(openli_email_captured_t *cap) {

    if (cap == NULL) {
        return;
    }

    if (cap->session_id) {
        free(cap->session_id);
    }

    if (cap->target_id) {
        free(cap->target_id);
    }

    if (cap->remote_ip) {
        free(cap->remote_ip);
    }

    if (cap->remote_port) {
        free(cap->remote_port);
    }

    if (cap->host_ip) {
        free(cap->host_ip);
    }

    if (cap->host_port) {
        free(cap->host_port);
    }

    if (cap->datasource) {
        free(cap->datasource);
    }

    if (cap->content && cap->own_content) {
        free(cap->content);
    }

    free(cap);
}

static void start_email_intercept(openli_email_worker_t *state,
        emailintercept_t *em, int addtargets) {

    openli_export_recv_t *expmsg;
    email_target_t *tgt, *tmp;

    if (state->tracker_threads <= 1) {
        em->common.seqtrackerid = 0;
    } else {
        em->common.seqtrackerid = hash_liid(em->common.liid) % state->tracker_threads;
    }

    HASH_ADD_KEYPTR(hh_liid, state->allintercepts, em->common.liid,
            em->common.liid_len, em);

    if (addtargets) {
        HASH_ITER(hh, em->targets, tgt, tmp) {
            if (add_intercept_to_email_user_intercept_list(
                    &(state->alltargets), em, tgt) < 0) {
                logger(LOG_INFO, "OpenLI: error while adding all email targets for intercept %s", em->common.liid);
                break;
            }
        }
    }

    if (state->emailid == 0) {
        expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_INTERCEPT_DETAILS;
        expmsg->data.cept.liid = strdup(em->common.liid);
        expmsg->data.cept.authcc = strdup(em->common.authcc);
        expmsg->data.cept.delivcc = strdup(em->common.delivcc);
        expmsg->data.cept.seqtrackerid = em->common.seqtrackerid;

        publish_openli_msg(state->zmq_pubsocks[em->common.seqtrackerid],
                expmsg);
    }
    em->awaitingconfirm = 0;
}

static void update_email_intercept(openli_email_worker_t *state,
        emailintercept_t *found, emailintercept_t *latest) {

    assert(strcmp(found->common.liid, latest->common.liid) == 0);

    if (found->common.authcc) {
        free(found->common.authcc);
    }
    found->common.authcc = latest->common.authcc;
    found->common.authcc_len = latest->common.authcc_len;
    latest->common.authcc = NULL;

    if (found->common.delivcc) {
        free(found->common.delivcc);
    }
    found->common.delivcc = latest->common.delivcc;
    found->common.delivcc_len = latest->common.delivcc_len;
    latest->common.delivcc = NULL;

    found->common.tostart_time = latest->common.tostart_time;
    found->common.toend_time = latest->common.toend_time;
    found->common.tomediate = latest->common.tomediate;

    /* XXX targetagency and destid shouldn't matter, unless we actually
     * use them in this thread.
     *
     * I think they're only relevant in the forwarding thread though */

}

static void remove_email_intercept(openli_email_worker_t *state,
        emailintercept_t *em, int removetargets) {

    openli_export_recv_t *expmsg;
    int i;
    email_target_t *tgt, *tmp;

    /* Either this intercept has been explicitly withdrawn, in which case
     * we need to also purge any target addresses for it, OR the
     * intercept has been reannounced so we're going to "update" it. For an
     * update, we want to keep all existing targets active, but be prepared
     * to drop any that are not subsequently confirmed by the provisioner.
     */
    HASH_ITER(hh, em->targets, tgt, tmp) {
        if (removetargets) {
            if (remove_intercept_from_email_user_intercept_list(
                    &(state->alltargets), em, tgt) < 0) {
                logger(LOG_INFO, "OpenLI: error while removing all email targets for intercept %s", em->common.liid);
                break;
            }
        } else {
            /* Flag this target as needing confirmation */
            tgt->awaitingconfirm = 1;
        }
    }

    HASH_DELETE(hh_liid, state->allintercepts, em);

    if (state->emailid == 0 && removetargets != 0) {
        expmsg = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_INTERCEPT_OVER;
        expmsg->data.cept.liid = strdup(em->common.liid);
        expmsg->data.cept.authcc = strdup(em->common.authcc);
        expmsg->data.cept.delivcc = strdup(em->common.delivcc);
        expmsg->data.cept.seqtrackerid = em->common.seqtrackerid;

        publish_openli_msg(state->zmq_pubsocks[em->common.seqtrackerid],
                expmsg);

        for (i = 0; i < state->fwd_threads; i++) {

            expmsg = (openli_export_recv_t *)calloc(1,
                    sizeof(openli_export_recv_t));
            expmsg->type = OPENLI_EXPORT_INTERCEPT_OVER;
            expmsg->data.cept.liid = strdup(em->common.liid);
            expmsg->data.cept.authcc = strdup(em->common.authcc);
            expmsg->data.cept.delivcc = strdup(em->common.delivcc);
            expmsg->data.cept.seqtrackerid = em->common.seqtrackerid;

            publish_openli_msg(state->zmq_fwdsocks[i], expmsg);
        }

        pthread_mutex_lock(state->stats_mutex);
        state->stats->emailintercepts_ended_diff ++;
        state->stats->emailintercepts_ended_total ++;
        pthread_mutex_unlock(state->stats_mutex);

        logger(LOG_INFO,
                "OpenLI: removed email intercept %s from email worker threads",
                em->common.liid);
    }

    free_single_emailintercept(em);

}

static int add_new_email_intercept(openli_email_worker_t *state,
        provisioner_msg_t *msg) {

    emailintercept_t *em, *found;
    int ret = 0;

    em = calloc(1, sizeof(emailintercept_t));

    if (decode_emailintercept_start(msg->msgbody, msg->msglen, em) < 0) {
        logger(LOG_INFO, "OpenLI: email worker failed to decode email intercept start message from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, state->allintercepts, em->common.liid,
            em->common.liid_len, found);

    if (found) {
        email_target_t *tgt, *tmp;
        /* Don't halt any target intercepts just yet -- hopefully a target
         * update is going to follow this...
         */
        HASH_ITER(hh, found->targets, tgt, tmp) {
            tgt->awaitingconfirm = 1;
        }

        update_email_intercept(state, found, em);
        found->awaitingconfirm = 0;
        free_single_emailintercept(em);
        ret = 1;
    } else {
        start_email_intercept(state, em, 0);
        if (state->emailid == 0) {
            pthread_mutex_lock(state->stats_mutex);
            state->stats->emailintercepts_added_diff ++;
            state->stats->emailintercepts_added_total ++;
            pthread_mutex_unlock(state->stats_mutex);

            logger(LOG_INFO, "OpenLI: added new email intercept for %s to email worker threads", em->common.liid);
        }
    }


    return ret;
}

static int modify_email_intercept(openli_email_worker_t *state,
        provisioner_msg_t *provmsg) {

    emailintercept_t *decode, *found;
    openli_export_recv_t *expmsg;

    decode = calloc(1, sizeof(emailintercept_t));
    if (decode_emailintercept_modify(provmsg->msgbody, provmsg->msglen,
            decode) < 0) {
        logger(LOG_INFO, "OpenLI: received invalid email intercept modification from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, state->allintercepts, decode->common.liid,
            decode->common.liid_len, found);
    if (!found) {
        start_email_intercept(state, decode, 0);
        return 0;
    }

    if (decode->common.tostart_time != found->common.tostart_time ||
            decode->common.toend_time != found->common.toend_time) {
        logger(LOG_INFO,
                "OpenLI: Email intercept %s has changed start / end times -- now %lu, %lu",
                found->common.liid, decode->common.tostart_time,
                decode->common.toend_time);
        found->common.tostart_time = decode->common.tostart_time;
        found->common.toend_time = decode->common.toend_time;
    }

    if (decode->common.tomediate != found->common.tomediate) {
        char space[1024];
        intercept_mediation_mode_as_string(decode->common.tomediate, space,
                1024);
        logger(LOG_INFO,
                "OpenLI: Email intercept %s has changed mediation mode to: %s",
                decode->common.liid, space);
        found->common.tomediate = decode->common.tomediate;
    }

    if (strcmp(decode->common.delivcc, found->common.delivcc) != 0 ||
            strcmp(decode->common.authcc, found->common.authcc) != 0) {
        char *tmp;
        tmp = decode->common.authcc;
        decode->common.authcc = found->common.authcc;
        found->common.authcc = tmp;
        tmp = decode->common.delivcc;
        decode->common.delivcc = found->common.delivcc;
        found->common.delivcc = tmp;

        expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_INTERCEPT_DETAILS;
        expmsg->data.cept.liid = strdup(found->common.liid);
        expmsg->data.cept.authcc = strdup(found->common.authcc);
        expmsg->data.cept.delivcc = strdup(found->common.delivcc);
        expmsg->data.cept.seqtrackerid = found->common.seqtrackerid;

        publish_openli_msg(state->zmq_pubsocks[found->common.seqtrackerid],
                expmsg);
    }

    free_single_emailintercept(decode);
    return 0;
}

static int halt_email_intercept(openli_email_worker_t *state,
        provisioner_msg_t *provmsg) {

    emailintercept_t *decode, *found;

    decode = calloc(1, sizeof(emailintercept_t));
    if (decode_emailintercept_halt(provmsg->msgbody, provmsg->msglen,
            decode) < 0) {
        logger(LOG_INFO, "OpenLI: received invalid email intercept withdrawal from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, state->allintercepts, decode->common.liid,
            decode->common.liid_len, found);
    if (!found && state->emailid == 0) {
        logger(LOG_INFO, "OpenLI: tried to halt email intercept %s but this was not in the intercept map?", decode->common.liid);
        free_single_emailintercept(decode);
        return -1;
    }

    remove_email_intercept(state, found, 1);
    free_single_emailintercept(decode);
    return 0;
}

static int process_email_target_withdraw(openli_email_worker_t *state,
        email_target_t *tgt, char *liid) {

    emailintercept_t *found;
    email_target_t *tgtfound;

    HASH_FIND(hh_liid, state->allintercepts, liid, strlen(liid), found);
    if (!found) {
        logger(LOG_INFO, "OpenLI: received email target withdrawal for intercept %s, but this intercept is not active according to email worker thread %d",
                liid, state->emailid);
        return -1;
    }

    if (remove_intercept_from_email_user_intercept_list(&(state->alltargets),
            found, tgt) < 0) {
        logger(LOG_INFO, "OpenLI: email worker thread %d failed to remove email target %s for intercept %s", state->emailid, tgt->address, liid);
        return -1;
    }

    HASH_FIND(hh, found->targets, tgt->address, strlen(tgt->address), tgtfound);
    if (tgtfound) {
        HASH_DELETE(hh, found->targets, tgtfound);
        if (tgtfound->address) {
            free(tgtfound->address);
        }
        free(tgtfound);
    }

    return 0;
}

static int remove_email_target(openli_email_worker_t *state,
        provisioner_msg_t *provmsg) {

    email_target_t *tgt;
    char liid[256];
    int ret;

    tgt = calloc(1, sizeof(email_target_t));

    if (decode_email_target_withdraw(provmsg->msgbody, provmsg->msglen,
            tgt, liid, 256) < 0) {
        logger(LOG_INFO, "OpenLI: email worker %d received invalid email target withdrawal from provisioner", state->emailid);
        return -1;
    }

    ret = process_email_target_withdraw(state, tgt, liid);

    if (tgt->address) {
        free(tgt->address);
    }
    free(tgt);
    return ret;
}

static int add_email_target(openli_email_worker_t *state,
        provisioner_msg_t *provmsg) {

    email_target_t *tgt, *tgtfound;
    emailintercept_t *found;
    char liid[256];

    tgt = calloc(1, sizeof(email_target_t));
    if (decode_email_target_announcement(provmsg->msgbody, provmsg->msglen,
            tgt, liid, 256) < 0) {
        logger(LOG_INFO, "OpenLI: email worker %d received invalid email target announcement from provisioner", state->emailid);
        return -1;
    }

    assert(tgt->address);

    HASH_FIND(hh_liid, state->allintercepts, liid, strlen(liid), found);
    if (!found) {
        logger(LOG_INFO, "OpenLI: received email target announcement for intercept %s, but this intercept is not active according to email worker thread %d",
        liid, state->emailid);
        return -1;
    }

    if (add_intercept_to_email_user_intercept_list(&(state->alltargets),
            found, tgt) < 0) {
        logger(LOG_INFO, "OpenLI: email worker thread %d failed to add email target %s for intercept %s", state->emailid, tgt->address, liid);
        return -1;
    }

    HASH_FIND(hh, found->targets, tgt->address, strlen(tgt->address), tgtfound);
    if (!tgtfound) {
        tgt->awaitingconfirm = 0;
        HASH_ADD_KEYPTR(hh, found->targets, tgt->address, strlen(tgt->address),
                tgt);
    } else {
        tgtfound->awaitingconfirm = 0;
        if (tgt->address) {
            free(tgt->address);
        }
        free(tgt);
    }
    return 0;
}

static void flag_all_email_intercepts(openli_email_worker_t *state) {
    emailintercept_t *em, *tmp;
    email_target_t *tgt, *tmp2;

    HASH_ITER(hh_liid, state->allintercepts, em, tmp) {
        em->awaitingconfirm = 1;
        HASH_ITER(hh, em->targets, tgt, tmp2) {
            tgt->awaitingconfirm = 1;
        }
    }
}

static void disable_unconfirmed_email_intercepts(openli_email_worker_t *state)
{
    emailintercept_t *em, *tmp;
    email_target_t *tgt, *tmp2;

    HASH_ITER(hh_liid, state->allintercepts, em, tmp) {
        if (em->awaitingconfirm) {
            remove_email_intercept(state, em, 1);
        } else {
            HASH_ITER(hh, em->targets, tgt, tmp2) {
                if (tgt->awaitingconfirm) {
                    process_email_target_withdraw(state, tgt, em->common.liid);
                }
            }
        }
    }
}

static int handle_provisioner_message(openli_email_worker_t *state,
        openli_export_recv_t *msg) {

    int ret = 0;

    switch(msg->data.provmsg.msgtype) {
        case OPENLI_PROTO_START_EMAILINTERCEPT:
            ret = add_new_email_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_HALT_EMAILINTERCEPT:
            ret = halt_email_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_MODIFY_EMAILINTERCEPT:
            ret = modify_email_intercept(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_ANNOUNCE_EMAIL_TARGET:
            ret = add_email_target(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_WITHDRAW_EMAIL_TARGET:
            ret = remove_email_target(state, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            disable_unconfirmed_email_intercepts(state);
            break;
        case OPENLI_PROTO_DISCONNECT:
            flag_all_email_intercepts(state);
            break;
        default:
            logger(LOG_INFO, "OpenLI: email worker thread %d received unexpected message type from provisioner: %u",
                    state->emailid, msg->data.provmsg.msgtype);
            ret = -1;
    }


    if (msg->data.provmsg.msgbody) {
        free(msg->data.provmsg.msgbody);
    }

    return ret;
}

static int process_sync_thread_message(openli_email_worker_t *state) {

    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(state->zmq_ii_sock, &msg, sizeof(msg),
                ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving II in email thread %d: %s",
                    state->emailid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            free(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_PROVISIONER_MESSAGE) {
            handle_provisioner_message(state, msg);
        }

        /* TODO handle other message types */

        free(msg);
    } while (x > 0);

    return 1;
}

static int find_and_update_active_session(openli_email_worker_t *state,
        openli_email_captured_t *cap) {

    char sesskey[256];
    emailsession_t *sess;
    int r = 0;

    snprintf(sesskey, 256, "%s-%s", email_type_to_string(cap->type),
            cap->session_id);

    HASH_FIND(hh, state->activesessions, sesskey, strlen(sesskey), sess);
    if (!sess) {
        sess = calloc(1, sizeof(emailsession_t));
        init_email_session(sess, cap, sesskey, state);
        HASH_ADD_KEYPTR(hh, state->activesessions, sess->key,
                strlen(sess->key), sess);

        if (state->emailid == 0) {
            logger(LOG_INFO, "OpenLI: DEVDEBUG adding new session '%s'",
                    sesskey);
        }
    }

    update_email_session_timeout(state, sess);

    if (sess->protocol == OPENLI_EMAIL_TYPE_SMTP) {
        r = update_smtp_session_by_ingestion(state, sess, cap);
    } else if (sess->protocol == OPENLI_EMAIL_TYPE_IMAP) {
        r = update_imap_session_by_ingestion(state, sess, cap);
    } else if (sess->protocol == OPENLI_EMAIL_TYPE_POP3) {
        r = update_pop3_session_by_ingestion(state, sess, cap);
    }

    if (r < 0) {
        logger(LOG_INFO,
                "OpenLI: error updating %s session '%s' -- removing session...",
                email_type_to_string(cap->type), sess->key);

        HASH_DELETE(hh, state->activesessions, sess);
        free_email_session(state, sess);
    } else if (r == 1) {
        logger(LOG_INFO, "OpenLI: DEVDEBUG %s session '%s' is over",
                email_type_to_string(cap->type), sess->key);
        HASH_DELETE(hh, state->activesessions, sess);
        free_email_session(state, sess);
    }

    free_captured_email(cap);
}

static int process_received_packet(openli_email_worker_t *state) {
    openli_state_update_t recvd;
    int rc;
    openli_email_captured_t *cap = NULL;

    do {
        rc = zmq_recv(state->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving email packet in email thread %d: %s", state->emailid, strerror(errno));
            return -1;
        }

        cap = convert_packet_to_email_captured(recvd.data.pkt, recvd.type);

        if (cap == NULL) {
            logger(LOG_INFO, "OpenLI: unable to derive email session ID from received packet in email thread %d", state->emailid);
            return -1;
        }
        if (cap->content != NULL) {
            find_and_update_active_session(state, cap);
        } else {
            free_captured_email(cap);
        }

        trace_destroy_packet(recvd.data.pkt);
    } while (rc > 0);

    return 0;
}

static int process_ingested_capture(openli_email_worker_t *state) {
    openli_email_captured_t *cap = NULL;
    int x, r;
    emailsession_t *sess;

    do {
        x = zmq_recv(state->zmq_ingest_recvsock, &cap, sizeof(cap),
                ZMQ_DONTWAIT);

        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving ingested email contents in email thread %d: %s",
                    state->emailid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (cap == NULL) {
            break;
        }
        find_and_update_active_session(state, cap);

    } while (x > 0);

    return 1;
}

static void email_worker_main(openli_email_worker_t *state) {

    emailsession_t **expired = NULL;
    int x;
    int topoll_req;
    sync_epoll_t *ev, *tmp;

    logger(LOG_INFO, "OpenLI: starting email processing thread %d",
            state->emailid);

    /* TODO add other consumer sockets to topoll */

    while (1) {
        topoll_req = 3 + HASH_CNT(hh, state->timeouts);

        if (topoll_req > state->topoll_size) {
            if (state->topoll) {
                free(state->topoll);
            }
            if (expired) {
                free(expired);
            }
            state->topoll = calloc(topoll_req, sizeof(zmq_pollitem_t));
            state->topoll_size = topoll_req;
            expired = calloc(topoll_req, sizeof(emailsession_t *));
        }

        state->topoll[0].socket = state->zmq_ii_sock;
        state->topoll[0].events = ZMQ_POLLIN;

        state->topoll[1].socket = state->zmq_ingest_recvsock;
        state->topoll[1].events = ZMQ_POLLIN;

        state->topoll[2].socket = state->zmq_colthread_recvsock;
        state->topoll[2].events = ZMQ_POLLIN;

        x = 3;
        HASH_ITER(hh, state->timeouts, ev, tmp) {
            state->topoll[x].socket = NULL;
            state->topoll[x].fd = ev->fd;
            state->topoll[x].events = ZMQ_POLLIN;
            expired[x] = (emailsession_t *)(ev->ptr);
            x++;
        }

        if ((x = zmq_poll(state->topoll, topoll_req, 50)) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO, "OpenLI: error while polling in email processor %d: %s", state->emailid, strerror(errno));
            return;
        }

        if (x == 0) {
            continue;
        }

        if (state->topoll[0].revents & ZMQ_POLLIN) {
            /* message from the sync thread */
            x = process_sync_thread_message(state);
            if (x < 0) {
                break;
            }
            state->topoll[0].revents = 0;
        }

        if (state->topoll[1].revents & ZMQ_POLLIN) {
            /* message from the email ingesting thread */
            x = process_ingested_capture(state);
            if (x < 0) {
                break;
            }
            state->topoll[1].revents = 0;
        }

        if (state->topoll[2].revents & ZMQ_POLLIN) {
            /* message from the email ingesting thread */
            x = process_received_packet(state);
            if (x < 0) {
                break;
            }
            state->topoll[2].revents = 0;
        }

        for (x = 3; x < topoll_req; x++) {
            emailsession_t *sessfound;

            if (state->topoll[x].revents & ZMQ_POLLIN) {
                logger(LOG_INFO, "OpenLI: DEVDEBUG expiring email session '%s' due to inactivity", expired[x]->key);

                HASH_FIND(hh, state->activesessions, expired[x]->key,
                        strlen(expired[x]->key), sessfound);
                if (sessfound) {
                    HASH_DELETE(hh, state->activesessions, sessfound);
                }
                free_email_session(state, expired[x]);
            }
        }
    }
    if (expired) {
        free(expired);
    }
}

static inline void clear_zmqsocks(void **zmq_socks, int sockcount) {
    int i, zero = 0;
    if (zmq_socks == NULL) {
        return;
    }

    for (i = 0; i < sockcount; i++) {
        if (zmq_socks[i] == NULL) {
            continue;
        }
        zmq_setsockopt(zmq_socks[i], ZMQ_LINGER, &zero, sizeof(zero));
        zmq_close(zmq_socks[i]);
    }
    free(zmq_socks);
}

static inline int init_zmqsocks(void **zmq_socks, int sockcount,
        const char *basename, void *zmq_ctxt) {

    int i, zero = 0;
    char sockname[256];
    int ret = 0;

    for (i = 0; i < sockcount; i++) {
        zmq_socks[i] = zmq_socket(zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 256, "%s-%d", basename, i);
        if (zmq_connect(zmq_socks[i], sockname) < 0) {
            ret = -1;
            logger(LOG_INFO,
                    "OpenLI: email worker failed to bind to publishing zmq %s: %s",
                    sockname, strerror(errno));

            zmq_close(zmq_socks[i]);
            zmq_socks[i] = NULL;
        }
    }
    return ret;
}

static void free_all_email_sessions(openli_email_worker_t *state) {

    emailsession_t *sess, *tmp;

    HASH_ITER(hh, state->activesessions, sess, tmp) {
        HASH_DELETE(hh, state->activesessions, sess);
        free_email_session(state, sess);
    }

}

void *start_email_worker_thread(void *arg) {

    openli_email_worker_t *state = (openli_email_worker_t *)arg;
    int x, zero = 0;
    char sockname[256];
    sync_epoll_t *syncev, *tmp;
    openli_state_update_t recvd;

    state->zmq_pubsocks = calloc(state->tracker_threads, sizeof(void *));
    state->zmq_fwdsocks = calloc(state->fwd_threads, sizeof(void *));

    init_zmqsocks(state->zmq_pubsocks, state->tracker_threads,
            "inproc://openlipub", state->zmq_ctxt);

    init_zmqsocks(state->zmq_fwdsocks, state->fwd_threads,
            "inproc://openliforwardercontrol_sync", state->zmq_ctxt);

    state->zmq_ii_sock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openliemailcontrol_sync-%d",
            state->emailid);
    if (zmq_bind(state->zmq_ii_sock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: email processing thread %d failed to bind to II zmq: %s", state->emailid, strerror(errno));
        goto haltemailworker;
    }

     if (zmq_setsockopt(state->zmq_ii_sock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
         logger(LOG_INFO, "OpenLI: email processing thread %d failed to configure II zmq: %s", state->emailid, strerror(errno));
         goto haltemailworker;
     }

    state->zmq_ingest_recvsock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openliemailworker-ingest%d",
            state->emailid);

    if (zmq_bind(state->zmq_ingest_recvsock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: email processing thread %d failed to bind to ingesting zmq: %s", state->emailid, strerror(errno));
        goto haltemailworker;
    }

    if (zmq_setsockopt(state->zmq_ingest_recvsock, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
         logger(LOG_INFO, "OpenLI: email processing thread %d failed to configure ingesting zmq: %s", state->emailid, strerror(errno));
         goto haltemailworker;
    }

    state->zmq_colthread_recvsock = zmq_socket(state->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openliemailworker-colrecv%d",
            state->emailid);

    if (zmq_bind(state->zmq_colthread_recvsock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: email processing thread %d failed to bind to colthread zmq: %s", state->emailid, strerror(errno));
        goto haltemailworker;
    }

    if (zmq_setsockopt(state->zmq_colthread_recvsock, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
         logger(LOG_INFO, "OpenLI: email processing thread %d failed to configure colthread zmq: %s", state->emailid, strerror(errno));
         goto haltemailworker;
    }

    email_worker_main(state);

    do {
        /* drain remaining email captures and free them */
        x = zmq_recv(state->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (x > 0);

haltemailworker:
    logger(LOG_INFO, "OpenLI: halting email processing thread %d",
            state->emailid);
    /* free all state for intercepts and active sessions */
    clear_email_user_intercept_list(state->alltargets);
    free_all_emailintercepts(&(state->allintercepts));
    free_all_email_sessions(state);

    /* close all ZMQs */
    zmq_close(state->zmq_ii_sock);

    if (state->topoll) {
        free(state->topoll);
    }

    zmq_close(state->zmq_ingest_recvsock);
    zmq_close(state->zmq_colthread_recvsock);

    clear_zmqsocks(state->zmq_pubsocks, state->tracker_threads);
    clear_zmqsocks(state->zmq_fwdsocks, state->fwd_threads);

    /* All timeouts should be freed when we release the active sessions,
     * but just in case there are any left floating around...
     */
    HASH_ITER(hh, state->timeouts, syncev, tmp) {
        HASH_DELETE(hh, state->timeouts, syncev);
        free(syncev);
    }

    pthread_exit(NULL);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

