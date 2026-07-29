/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
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
#include <stdio.h>
#include <libtrace.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <libwandder.h>

#include "collector.h"
#include "logger.h"
#include "util.h"
#include "intercept.h"
#include "netcomms.h"

struct m3ua_layer {
    uint8_t version;
    uint8_t reserved; 
    uint8_t class;
    uint8_t type;
    uint32_t length;
} PACKED;

struct m2pa_layer {
    uint8_t version;
    uint8_t spare;
    uint8_t class;
    uint8_t type;
    uint32_t length;
    uint8_t bsn_spare;
    uint8_t bsn[3];
    uint8_t fsn_spare; 
    uint8_t fsn[3];
    uint8_t priority;
} PACKED;


void *sctp_thread_begin(void *arg);

uint8_t *parse_sccp_for_tcap_tids(uint8_t *sccp, uint16_t len,
        uint16_t *tcap_len, uint32_t *otid, uint32_t *dtid) {
    size_t data_offset, i;
    uint8_t *tcap, *itemptr;
    wandder_decoder_t *dec = NULL;
    uint32_t ident, length, val;
    uint8_t is_gsm = 0;

    if (sccp == NULL || len < 5) {
        return NULL;
    }

    if ((*sccp) == 0x09) {
        // UDT (unitdata)
        data_offset = 5 + sccp[4];
    } else if ((*sccp) == 0x11) {
        data_offset = 6 + sccp[5];
    } else {
        return NULL;
    }

    if (data_offset >= len) {
        return NULL;
    }

    tcap = sccp + data_offset;
    len -= data_offset;
    *otid = 0;
    *dtid = 0;
    *tcap_len = len;

    dec = init_wandder_decoder(dec, tcap, len, false);
    if (wandder_decode_next(dec) <= 0) {
        free_wandder_decoder(dec);
        return NULL;
    }

    while (wandder_decode_next(dec) > 0) {
        ident = wandder_get_identifier(dec);
        length = wandder_get_itemlen(dec);
        itemptr = wandder_get_itemptr(dec);

        if (ident == 8) {
            val = 0;
            for (i = 0; i < length && i < 4; i++) {
                val = (val << 8) | *(itemptr + i);
            }
            *otid = val;
        } else if (ident == 9) {
            val = 0;
            for (i = 0; i < length && i < 4; i++) {
                val = (val << 8) | *(itemptr + i);
            }
            *dtid = val;
        } else if (ident == 12) {
            is_gsm = 1;
        } else {
            wandder_decode_skip(dec);
        }
    }

    free_wandder_decoder(dec);
    if (is_gsm) {
        return tcap;
    }

    // not a packet that is relevant to SIGTRAN interception
    return NULL;
}

uint8_t *parse_m3ua_header_for_sccp(uint8_t *m3ua, uint16_t len,
        uint16_t *sccp_len, uint32_t *opc, uint32_t *dpc) {

    struct m3ua_layer *hdr = (struct m3ua_layer *)m3ua;
    uint32_t newlen;
    uint16_t offset = 0, *ptr;
    uint16_t tag, tvlen;
    uint8_t *si, *sccp;

    if (hdr == NULL || len < sizeof(struct m3ua_layer)) {
        return NULL;
    }

    if (hdr->version != 1 || hdr->class != 1 || hdr->type != 1) {
        return NULL;
    }

    newlen = ntohl(hdr->length);
    if (newlen < len) {
        len = newlen;
    }


    offset = sizeof(struct m3ua_layer);
    sccp = NULL;
    *sccp_len = 0;

    while (offset < len - 4) {
        ptr = (uint16_t *)(m3ua + offset);
        tag = ntohs(*ptr);
        ptr++;
        tvlen = ntohs(*ptr);
        ptr++;

        if (tag == 0x0210) {
            if (tvlen < 16) {
                break;
            }
            *opc = ntohl(*((uint32_t *)ptr));
            *dpc = ntohl(*((uint32_t *)(ptr + 2))); // offset is 4 bytes
            si = (uint8_t *)(ptr + 4);         // offset is 8 bytes
            if (*si == 3) {
                sccp = (uint8_t *)(ptr + 6);
                *sccp_len = tvlen - 16;
            }
            break;
        }
        // maintain 4 byte alignment
        offset += ((tvlen + 3) & ~3);
    }
    return sccp;
}

uint8_t *parse_m2pa_header_for_sccp(uint8_t *m2pa, uint16_t len,
        uint16_t *sccp_len, uint32_t *opc, uint32_t *dpc) {

    struct m2pa_layer *hdr = (struct m2pa_layer *)m2pa;
    uint32_t newlen;
    uint16_t offset;
    uint8_t si;
    uint8_t *sccp;
    uint32_t routelabel;

    if (hdr == NULL || len < sizeof(struct m2pa_layer)) {
        return NULL;
    }

    if (hdr->version != 1 || hdr->class != 0x0b || hdr->type != 1) {
        return NULL;
    }

    newlen = ntohl(hdr->length);
    if (newlen < len) {
        len = newlen;
    }

    offset = sizeof(struct m2pa_layer);
    if (len - offset < 5) {
        return NULL;
    }

    si = (*(m2pa + offset)) & 0x0F;
    routelabel = *((uint32_t *)(m2pa + offset + 1));

    *opc = (routelabel & 0x0FFFC000) >> 14;
    *dpc = routelabel & 0x00003FFF;

    offset += 5;
    if (si == 3) {
        sccp = m2pa + offset;
        *sccp_len = len - offset;
    } else {
        *sccp_len = 0;
        sccp = NULL;
    }
    return sccp;
}

void start_sctp_worker_thread(openli_sctp_worker_t *sctp, int workerid,
        void *globalstate) {

    char name[1024];
    collector_global_t *glob = (collector_global_t *)globalstate;

    snprintf(name, 1024, "sctpworker-%d", workerid);

    sctp->zmq_ctxt = glob->zmq_ctxt;
    sctp->zmq_packet_return = NULL;
    sctp->workerid = workerid;
    sctp->zmq_ii_sock = NULL;
    sctp->zmq_pubsocks = NULL;
    sctp->zmq_colthread_recvsock = NULL;
    sctp->tracker_threads = glob->seqtracker_threads;
    sctp->voipintercepts = NULL;
    sctp->worker_threadname = strdup(name);
    sctp->haltinfo = NULL;

    pthread_create(&(sctp->threadid), NULL, sctp_thread_begin, (void *)sctp);
    pthread_setname_np(sctp->threadid, sctp->worker_threadname);

}

static int sctp_worker_handle_provisioner_message(openli_sctp_worker_t *sctp,
        openli_export_recv_t *msg) {
    int ret = 0;

    switch(msg->data.provmsg.msgtype) {
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            // disable_unconfirmed_sigtran_intercepts(sctp);
            break;
        case OPENLI_PROTO_DISCONNECT:
            // flag_sigtran_intercepts(sctp);
            break;
        case OPENLI_PROTO_START_VOIPINTERCEPT:
            // ret = add_new_sigtran_intercept(sctp, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_HALT_VOIPINTERCEPT:
            // ret = halt_sigtran_intercept(sctp, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_MODIFY_VOIPINTERCEPT:
            // ret = modify_sigtran_intercept(sctp, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_ANNOUNCE_SIP_TARGET:
            // ret = add_sigtran_target_identity(sctp, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_WITHDRAW_SIP_TARGET:
            // ret = remove_sigtran_target_identity(sctp, &(msg->data.provmsg));
            break;
        default:
            logger(LOG_INFO,
                    "OpenLI: SCTP worker thread %d received unexpected message type from provisioner: %u",
                    sctp->workerid, msg->data.provmsg.msgtype);
            ret = -1;
    }

    if (msg->data.provmsg.msgbody) {
        free(msg->data.provmsg.msgbody);
    }

    return ret;
}

static int sctp_worker_process_sync_thread_message(openli_sctp_worker_t *sctp) {

    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(sctp->zmq_ii_sock, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving II in SCTP thread %d: %s",
                    sctp->workerid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            sctp->haltinfo = msg->data.haltinfo;
            free(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_PROVISIONER_MESSAGE) {
            if (sctp_worker_handle_provisioner_message(sctp, msg) < 0) {
                free(msg);
                return -1;
            }
        }

        free(msg);
    } while (x > 0);

    return 1;

}

static int sctp_worker_process_packet(openli_sctp_worker_t *sctp) {
    openli_state_update_t recvd;
    int rc;

    do {
        rc = zmq_recv(sctp->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving packet in SCTP worker thread %d: %s",
                    sctp->workerid, strerror(errno));
            return -1;
        }

        if (recvd.type != OPENLI_UPDATE_SCCP) {
            logger(LOG_INFO,
                    "OpenLI: SCTP worker thread %d received unexpected update type %u",
                    sctp->workerid, recvd.type);
            break;
        }

        // process_sccp_content(sctp, &(recvd.data.sccp));
        if (recvd.data.sccp.content) {
            free(recvd.data.sccp.content);
        }

    } while (rc > 0);

    return 0;
}

void sctp_worker_main(openli_sctp_worker_t *sctp) {

    zmq_pollitem_t *topoll;
    sync_epoll_t purgetimer;
    struct itimerspec its;
    int x;

    logger(LOG_INFO, "OpenLI: starting SCTP worker thread %d", sctp->workerid);
    topoll = calloc(3, sizeof(zmq_pollitem_t));

    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    purgetimer.fdtype = 0;
    purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(purgetimer.fd, 0, &its, NULL);

    topoll[0].socket = sctp->zmq_ii_sock;
    topoll[0].events = ZMQ_POLLIN;
    topoll[0].revents = 0;

    topoll[1].socket = sctp->zmq_colthread_recvsock;
    topoll[1].events = ZMQ_POLLIN;
    topoll[1].revents = 0;

    topoll[2].socket = NULL;
    topoll[2].fd = purgetimer.fd;
    topoll[2].events = ZMQ_POLLIN;
    topoll[2].revents = 0;

    while (1) {
        if ((x = zmq_poll(topoll, 3, 50)) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO,
                    "OpenLI: error while polling in SCTP worker thread %d: %s",
                    sctp->workerid, strerror(errno));
            break;
        }

        if (x == 0) {
            continue;
        }

        if (topoll[0].revents & ZMQ_POLLIN) {
            x = sctp_worker_process_sync_thread_message(sctp);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }

        if (topoll[1].revents & ZMQ_POLLIN) {
            x = sctp_worker_process_packet(sctp);
            if (x < 0) {
                break;
            }
            topoll[1].revents = 0;
        }

        if (topoll[2].revents & ZMQ_POLLIN) {
            topoll[2].revents = 0;
            close(topoll[2].fd);

            // clear requests that have not seen a response in 5 seconds

            // clear transactions that have not been active for 10 seconds

            // clear IMSI mappings that have not been seen for a day

            purgetimer.fdtype = 0;
            purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
            timerfd_settime(purgetimer.fd, 0, &its, NULL);
            topoll[2].fd = purgetimer.fd;
        }
    }
    free(topoll);

}

void *sctp_thread_begin(void *arg) {
    openli_sctp_worker_t *sctp = (openli_sctp_worker_t *)arg;
    int x;
    openli_state_update_t recvd;

    sctp->zmq_pubsocks = calloc(sctp->tracker_threads, sizeof(void *));
    init_zmq_socket_array(sctp->zmq_pubsocks, sctp->tracker_threads,
            "inproc://openlipub", sctp->zmq_ctxt, -1);

    sctp->zmq_packet_return =
            init_zmq_packet_return_publish(sctp->zmq_ctxt, "SCTP",
                    sctp->workerid);

    sctp->zmq_ii_sock = init_zmq_ii_consumer(sctp->zmq_ctxt, "SCTP",
            sctp->workerid);
    if (sctp->zmq_ii_sock == NULL) {
        goto haltsctpworker;
    }

    sctp->zmq_colthread_recvsock =
            init_zmq_colthread_recv_consumer(sctp->zmq_ctxt, "SCTP",
                    sctp->workerid);
    if (sctp->zmq_colthread_recvsock == NULL) {
        goto haltsctpworker;
    }

    sctp_worker_main(sctp);

    do {
        x = zmq_recv(sctp->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(RECVD_PKT);
        }
    } while (x > 0);

haltsctpworker:
    logger(LOG_INFO, "OpenLI: halting SCTP processing thread %d",
            sctp->workerid);

    if (sctp->zmq_packet_return) {
        zmq_close(sctp->zmq_packet_return);
    }
    if (sctp->zmq_ii_sock) {
        zmq_close(sctp->zmq_ii_sock);
    }
    if (sctp->zmq_colthread_recvsock) {
        zmq_close(sctp->zmq_colthread_recvsock);
    }
    free_all_voipintercepts(&(sctp->voipintercepts));
    clear_zmq_socket_array(sctp->zmq_pubsocks, sctp->tracker_threads);
    free((char *)sctp->worker_threadname);

    if (sctp->haltinfo) {
        pthread_mutex_lock(&(sctp->haltinfo->mutex));
        sctp->haltinfo->halted ++;
        pthread_cond_signal(&(sctp->haltinfo->cond));
        pthread_mutex_unlock(&(sctp->haltinfo->mutex));
    }


    pthread_exit(NULL);
}
