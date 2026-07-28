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

#include "collector.h"
#include "logger.h"
#include "util.h"
#include "intercept.h"
#include "netcomms.h"

void *sctp_thread_begin(void *arg);

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

        if (recvd.type != OPENLI_UPDATE_SCTP) {
            logger(LOG_INFO,
                    "OpenLI: SCTP worker thread %d received unexpected update type %u",
                    sctp->workerid, recvd.type);
            break;
        }

        // process_sctp_packet(sctp, RECVD_PKT, RECVD_PINFO);

        if (RECVD_PKT) {
            if (sctp->zmq_packet_return) {
                if (zmq_send(sctp->zmq_packet_return, &RECVD_PKT,
                            sizeof(RECVD_PKT), ZMQ_DONTWAIT) < 0) {
                    trace_destroy_packet(RECVD_PKT);
                }
            } else {
                trace_destroy_packet(RECVD_PKT);
            }
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
