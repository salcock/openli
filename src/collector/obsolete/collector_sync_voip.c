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

#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libtrace_parallel.h>
#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timerfd.h>

#include "etsili_core.h"
#include "collector.h"
#include "collector_sync_voip.h"
#include "collector_publish.h"
#include "configparser.h"
#include "logger.h"
#include "intercept.h"
#include "netcomms.h"
#include "util.h"
#include "ipmmiri.h"

collector_sync_voip_t *init_voip_sync_data(collector_global_t *glob) {

    int i;
    char sockname[128];

    collector_sync_voip_t *sync = (collector_sync_voip_t *)
            malloc(sizeof(collector_sync_voip_t));


    sync->glob = &(glob->syncvoip);
    sync->info = &(glob->sharedinfo);
    sync->info_mutex = &(glob->config_mutex);

    sync->log_bad_instruct = 1;
    sync->log_bad_sip = 1;
    sync->pubsockcount = glob->seqtracker_threads;
    sync->zmq_pubsocks = calloc(sync->pubsockcount, sizeof(void *));

    sync->forwardcount = glob->forwarding_threads;
    sync->zmq_fwdctrlsocks = calloc(sync->forwardcount, sizeof(void *));

    sync->topoll = calloc(128, sizeof(zmq_pollitem_t));
    sync->topoll_size = 128;
    sync->expiring_streams = calloc(128, sizeof(struct rtpstreaminf *));

    sync->timeouts = NULL;

    sync->intersyncq = &(glob->intersyncq);
    sync->intersync_fd = libtrace_message_queue_get_fd(sync->intersyncq);

    for (i = 0; i < sync->pubsockcount; i++) {
        sync->zmq_pubsocks[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 128, "inproc://openlipub-%d", i);
        if (zmq_connect(sync->zmq_pubsocks[i], sockname) < 0) {
            logger(LOG_INFO,
                    "OpenLI: colsync thread failed to bind to publishing zmq: %s",
                    strerror(errno));
            zmq_close(sync->zmq_pubsocks[i]);
            sync->zmq_pubsocks[i] = NULL;
        }

        /* Do we need to set a HWM? */
    }

    for (i = 0; i < sync->forwardcount; i++) {
        sync->zmq_fwdctrlsocks[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 128, "inproc://openliforwardercontrol_sync-%d", i);
        if (zmq_connect(sync->zmq_fwdctrlsocks[i], sockname) != 0) {
            logger(LOG_INFO, "OpenLI: colsyncvoip thread unable to connect to zmq control socket for forwarding threads: %s",
                    strerror(errno));
            zmq_close(sync->zmq_fwdctrlsocks[i]);
            sync->zmq_fwdctrlsocks[i] = NULL;
        }
    }

    sync->zmq_colsock = zmq_socket(glob->zmq_ctxt, ZMQ_PULL);
    if (zmq_bind(sync->zmq_colsock, "inproc://openli-voipsync") != 0) {
        logger(LOG_INFO, "OpenLI: colsync VOIP thread unable to bind to zmq socket for collector updates: %s",
                strerror(errno));
        zmq_close(sync->zmq_colsock);
        sync->zmq_colsock = NULL;
    }


    sync->voipintercepts = NULL;
    sync->knowncallids = NULL;
    sync->sipparser = NULL;

    sync->sipdebugupdate = NULL;
    sync->sipdebugout = NULL;
    sync->ignore_sdpo_matches = glob->ignore_sdpo_matches;

    if (glob->ignore_sdpo_matches) {
        logger(LOG_INFO, "OpenLI: disabling tracking of multiple SIP legs using SDP O identifier");
    }

    if (glob->sipdebugfile) {
        sync->sipdebugfile = glob->sipdebugfile;
        glob->sipdebugfile = NULL;
    } else {
        sync->sipdebugfile = NULL;
    }

    return sync;
}

void clean_sync_voip_data(collector_sync_voip_t *sync) {
    int zero = 0, i;
    sync_epoll_t *syncev, *tmp;

    free_voip_cinmap(sync->knowncallids);
    HASH_ITER(hh, sync->timeouts, syncev, tmp) {
        HASH_DELETE(hh, sync->timeouts, syncev);
    }
    if (sync->voipintercepts) {
        free_all_voipintercepts(&(sync->voipintercepts));
    }
    if (sync->sipparser) {
        release_sip_parser(sync->sipparser);
    }

    if (sync->topoll) {
        free(sync->topoll);
    }

    if (sync->expiring_streams) {
        free(sync->expiring_streams);
    }


    sync->voipintercepts = NULL;
    sync->knowncallids = NULL;
    sync->sipparser = NULL;

    if (sync->sipdebugupdate) {
        trace_destroy_output(sync->sipdebugupdate);
    }

    if (sync->sipdebugout) {
        trace_destroy_output(sync->sipdebugout);
    }

    if (sync->sipdebugfile) {
        free(sync->sipdebugfile);
    }

    for (i = 0; i < sync->pubsockcount; i++) {
        if (sync->zmq_pubsocks[i] == NULL) {
            continue;
        }

        zmq_setsockopt(sync->zmq_pubsocks[i], ZMQ_LINGER, &zero, sizeof(zero));
        zmq_close(sync->zmq_pubsocks[i]);
    }

    for (i = 0; i < sync->forwardcount; i++) {
        if (sync->zmq_fwdctrlsocks[i] == NULL) {
            continue;
        }
        zmq_setsockopt(sync->zmq_fwdctrlsocks[i], ZMQ_LINGER, &zero,
                    sizeof(zero));
        zmq_close(sync->zmq_fwdctrlsocks[i]);
        sync->zmq_fwdctrlsocks[i] = NULL;
    }

    if (sync->zmq_colsock) {
        zmq_setsockopt(sync->zmq_colsock, ZMQ_LINGER, &zero, sizeof(zero));
        zmq_close(sync->zmq_colsock);
    }

    free(sync->zmq_pubsocks);
    free(sync->zmq_fwdctrlsocks);

}

static inline void push_single_voipstreamintercept(collector_sync_voip_t *sync,
        libtrace_message_queue_t *q, rtpstreaminf_t *orig) {

    rtpstreaminf_t *copy;
    openli_pushed_t msg;

    copy = deep_copy_rtpstream(orig);
    if (!copy) {
        logger(LOG_INFO,
                "OpenLI: unable to copy RTP stream in sync thread due to lack of memory.");
        logger(LOG_INFO,
                "OpenLI: forcing provisioner to halt.");
        exit(-2);
    }

    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = OPENLI_PUSH_IPMMINTERCEPT;
    msg.data.ipmmint = copy;

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->voipsessions_added_diff ++;
    sync->glob->stats->voipsessions_added_total ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);

    libtrace_message_queue_put(q, (void *)(&msg));
}

static void push_time_update_active_voipstreams(
        libtrace_message_queue_t *q, voipintercept_t *vint) {

    openli_pushed_t msg;
    rtpstreaminf_t *cin = NULL;

    if (vint->active_cins == NULL) {
        return;
    }

    for (cin = vint->active_cins; cin != NULL; cin=cin->hh.next) {
        if (cin->active == 0) {
            continue;
        }
        memset(&msg, 0, sizeof(openli_pushed_t));
        msg.type = OPENLI_PUSH_UPDATE_VOIPINTERCEPT;
        msg.data.ipmmint = create_rtpstream(vint, cin->cin);

        libtrace_message_queue_put(q, (void *)(&msg));
    }

}

static void push_halt_active_voipstreams(collector_sync_voip_t *sync,
        libtrace_message_queue_t *q, voipintercept_t *vint) {

    rtpstreaminf_t *cin = NULL;
    char *streamdup;
    openli_pushed_t msg;

    if (vint->active_cins == NULL) {
        return;
    }

    for (cin = vint->active_cins; cin != NULL; cin=cin->hh.next) {
        if (cin->active == 0) {
            continue;
        }
        streamdup = strdup(cin->streamkey);
        memset(&msg, 0, sizeof(openli_pushed_t));
        msg.type = OPENLI_PUSH_HALT_IPMMINTERCEPT;
        msg.data.rtpstreamkey = streamdup;

        pthread_mutex_lock(sync->glob->stats_mutex);
        sync->glob->stats->voipsessions_ended_diff ++;
        sync->glob->stats->voipsessions_ended_total ++;
        pthread_mutex_unlock(sync->glob->stats_mutex);

        libtrace_message_queue_put(q, (void *)(&msg));

        /* If we were already about to time this intercept out, make sure
         * we kill the timer.
         */
        if (cin->timeout_ev) {
            sync_epoll_t *timerev = (sync_epoll_t *)(cin->timeout_ev);
            sync_epoll_t *syncev;

            HASH_FIND(hh, sync->timeouts, &(timerev->fd), sizeof(int), syncev);
            if (syncev) {
                HASH_DELETE(hh, sync->timeouts, syncev);
            }

            close(timerev->fd);
            free(timerev);
            cin->timeout_ev = NULL;
        }
    }
}

static void push_voipintercept_halt_to_threads(collector_sync_voip_t *sync,
        voipintercept_t *vint) {

    sync_sendq_t *sendq, *tmp;

    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues), sendq, tmp) {
        push_halt_active_voipstreams(sync, sendq->q, vint);
    }
}

static void push_voip_intercept_update_to_threads(collector_sync_voip_t *sync,
        voipintercept_t *vint) {

    sync_sendq_t *sendq, *tmp;
    openli_export_recv_t *expmsg;

    expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    expmsg->type = OPENLI_EXPORT_INTERCEPT_CHANGED;
    expmsg->data.cept.liid = strdup(vint->common.liid);
    expmsg->data.cept.authcc = strdup(vint->common.authcc);
    expmsg->data.cept.delivcc = strdup(vint->common.delivcc);
    expmsg->data.cept.encryptmethod = vint->common.encrypt;
    if (vint->common.encryptkey) {
        expmsg->data.cept.encryptkey = strdup(vint->common.encryptkey);
    } else {
        expmsg->data.cept.encryptkey = NULL;
    }
    expmsg->data.cept.seqtrackerid = vint->common.seqtrackerid;
    publish_openli_msg(sync->zmq_pubsocks[vint->common.seqtrackerid], expmsg);

    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues), sendq, tmp) {
        push_time_update_active_voipstreams(sendq->q, vint);
    }
}

static void push_all_active_voipstreams(collector_sync_voip_t *sync,
        libtrace_message_queue_t *q, voipintercept_t *vint) {

    rtpstreaminf_t *cin = NULL;

    if (vint->active_cins == NULL) {
        return;
    }

    for (cin = vint->active_cins; cin != NULL; cin=cin->hh.next) {
        if (cin->active == 0) {
            continue;
        }

        push_single_voipstreamintercept(sync, q, cin);
    }

}

static int update_rtp_stream(collector_sync_voip_t *sync, rtpstreaminf_t *rtp,
        char *ipstr, char *portstr, char *mediatype, uint8_t dir) {

    uint32_t port;
    struct sockaddr_storage *saddr;
    int family, i;
    struct sipmediastream *mstream = NULL;
    int changed = 0;

    errno = 0;
    port = strtoul(portstr, NULL, 0);

    if (errno != 0 || port > 65535) {
        if (sync->log_bad_sip) {
            logger(LOG_INFO, "OpenLI: invalid RTP port number: %s", portstr);
            return -1;
        }
    }

    convert_ipstr_to_sockaddr(ipstr, &(saddr), &(family));

    for (i = 0; i < rtp->streamcount; i++) {

        if (strcmp(rtp->mediastreams[i].mediatype, mediatype) == 0) {
            mstream = &(rtp->mediastreams[i]);
            break;
        }
    }

    if (mstream == NULL) {
        if (rtp->streamcount > 0 && (rtp->streamcount %
                RTP_STREAM_ALLOC) == 0) {
            rtp->mediastreams = realloc(rtp->mediastreams,
                    (rtp->streamcount + RTP_STREAM_ALLOC) *
                        sizeof(struct sipmediastream));
            mstream = &(rtp->mediastreams[rtp->streamcount]);
        }
        mstream = &(rtp->mediastreams[rtp->streamcount]);
        rtp->streamcount ++;

        mstream->targetport = 0;
        mstream->otherport = 0;
        mstream->mediatype = strdup(mediatype);
    }

    /* If we get here, the RTP stream is not in our list. */
    if (dir == ETSI_DIR_FROM_TARGET) {
        if (rtp->targetaddr) {
            /* has the address or port changed? should we warn? */
            if (memcmp(rtp->targetaddr, saddr, sizeof(struct sockaddr_storage))
                    != 0) {
                changed = 1;
            }
            free(rtp->targetaddr);
        }
        rtp->ai_family = family;
        rtp->targetaddr = saddr;
        if (mstream->targetport != 0 && port != mstream->targetport) {
            changed = 1;
        }
        mstream->targetport = (uint16_t)port;


    } else {
        if (rtp->otheraddr) {
            /* has the address or port changed? should we warn? */
            if (memcmp(rtp->otheraddr, saddr, sizeof(struct sockaddr_storage))
                    != 0) {
                changed = 1;
            }
            free(rtp->otheraddr);
        }
        rtp->ai_family = family;
        rtp->otheraddr = saddr;
        if (mstream->otherport != 0 && port != mstream->otherport) {
            changed = 1;
        }
        mstream->otherport = (uint16_t)port;
    }
    return changed;
}

static inline int announce_rtp_streams_if_required(
        collector_sync_voip_t *sync, rtpstreaminf_t *rtp) {

    sync_sendq_t *sendq, *tmp;

    /* Not got the full 5-tuple for the RTP stream yet
     *
     * This naively assumes that all media streams are fully announced
     * at the same time -- if different media streams are announced
     * in different SIP messages, then this is going to need to get smarter.
     */
    if (!rtp->targetaddr || !rtp->otheraddr) {
        return 0;
    }

    if (rtp->active == 1 && rtp->changed == 0) {
        return 0;
    }

    /* If we get here, we need to push the RTP stream details to the
     * processing threads. */
    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues), sendq, tmp) {
        push_single_voipstreamintercept(sync, sendq->q, rtp);
    }
    rtp->active = 1;
    rtp->changed = 0;
    free(rtp->invitecseq);
    rtp->invitecseq = NULL;
    return 1;
}

/* TODO very similar to code in intercept.c */
static inline void remove_cin_callid_from_map(voipcinmap_t **cinmap,
        char *callid) {

    voipcinmap_t *c;
    HASH_FIND(hh_callid, *cinmap, callid, strlen(callid), c);
    if (c) {
        HASH_DELETE(hh_callid, *cinmap, c);
        if (c->shared) {
            c->shared->refs --;
            if (c->shared->refs == 0) {
                free(c->shared);
            }
        }
        if (c->username) {
            free(c->username);
        }
        if (c->realm) {
            free(c->realm);
        }
        free(c->callid);
        free(c);
    }
}

static void remove_cin_sdpkeys_for_target(voipsdpmap_t **sdpmap,
        char *username, char *realm) {

    voipsdpmap_t *s, *tmp;
    openli_sip_identity_t a, b;

    a.username = username;
    a.realm = realm;
    HASH_ITER(hh_sdp, *sdpmap, s, tmp) {
        b.username = s->username;
        b.realm = s->realm;

        if (!are_sip_identities_same(&a, &b)) {
            continue;
        }

        HASH_DELETE(hh_sdp, *sdpmap, s);
        if (s->shared) {
            s->shared->refs --;
            if (s->shared->refs == 0) {
                free(s->shared);
            }
        }
        if (s->username) {
            free(s->username);
        }
        if (s->realm) {
            free(s->realm);
        }
        free(s);
    }

}

static void remove_cin_callids_for_target(voipcinmap_t **cinmap,
        char *username, char *realm) {

    voipcinmap_t *c, *tmp;
    openli_sip_identity_t a, b;

    a.username = username;
    a.realm = realm;
    HASH_ITER(hh_callid, *cinmap, c, tmp) {
        b.username = c->username;
        b.realm = c->realm;

        if (!are_sip_identities_same(&a, &b)) {
            continue;
        }

        HASH_DELETE(hh_callid, *cinmap, c);
        if (c->shared) {
            c->shared->refs --;
            if (c->shared->refs == 0) {
                free(c->shared);
            }
        }
        if (c->username) {
            free(c->username);
        }
        if (c->realm) {
            free(c->realm);
        }
        free(c->callid);
        free(c);
    }

}

static inline voipcinmap_t *update_cin_callid_map(voipcinmap_t **cinmap,
        char *callid, voipintshared_t *vshared,
        char *targetuser, char *targetrealm) {

    voipcinmap_t *newcinmap;

    HASH_FIND(hh_callid, *cinmap, callid, strlen(callid), newcinmap);
    if (newcinmap) {
        return newcinmap;
    }

    newcinmap = (voipcinmap_t *)malloc(sizeof(voipcinmap_t));
    if (!newcinmap) {
        logger(LOG_INFO,
                "OpenLI: out of memory in collector_sync thread.");
        logger(LOG_INFO,
                "OpenLI: forcing provisioner to halt.");
        exit(-2);
    }
    newcinmap->callid = strdup(callid);
    newcinmap->username = strdup(targetuser);
    if (targetrealm) {
        newcinmap->realm = strdup(targetrealm);
    } else {
        newcinmap->realm = NULL;
    }
    newcinmap->shared = vshared;
    if (newcinmap->shared) {
        newcinmap->shared->refs ++;
    }
    newcinmap->smsonly = 0;     // TODO fix when we merge with SMS worker

    HASH_ADD_KEYPTR(hh_callid, *cinmap, newcinmap->callid,
            strlen(newcinmap->callid), newcinmap);
    return newcinmap;
}

static inline voipsdpmap_t *update_cin_sdp_map(voipintercept_t *vint,
        sip_sdp_identifier_t *sdpo, voipintshared_t *vshared, char *targetuser,
        char *targetrealm) {

    voipsdpmap_t *newsdpmap;

    newsdpmap = (voipsdpmap_t *)calloc(1, sizeof(voipsdpmap_t));
    if (!newsdpmap) {
        logger(LOG_INFO,
                "OpenLI: out of memory in collector_sync thread.");
        logger(LOG_INFO,
                "OpenLI: forcing provisioner to halt.");
        exit(-2);
    }
    newsdpmap->sdpkey.sessionid = sdpo->sessionid;
    newsdpmap->sdpkey.version = sdpo->version;

    /* make sure we null terminate if the address or username is very long */
    /* TODO maybe we'd be better off just strduping these as well? */
    strncpy(newsdpmap->sdpkey.address, sdpo->address,
            sizeof(newsdpmap->sdpkey.address));
    newsdpmap->sdpkey.address[sizeof(newsdpmap->sdpkey.address) - 1] = '\0';
    strncpy(newsdpmap->sdpkey.username, sdpo->username,
            sizeof(newsdpmap->sdpkey.username) - 1);
    newsdpmap->sdpkey.username[sizeof(newsdpmap->sdpkey.username) - 1] = '\0';

    newsdpmap->username = strdup(targetuser);
    if (targetrealm) {
        newsdpmap->realm = strdup(targetrealm);
    } else {
        newsdpmap->realm = NULL;
    }
    newsdpmap->shared = vshared;
    if (newsdpmap->shared) {
        newsdpmap->shared->refs ++;
    }

    HASH_ADD_KEYPTR(hh_sdp, vint->cin_sdp_map, &(newsdpmap->sdpkey),
            sizeof(sip_sdp_identifier_t), newsdpmap);

    return newsdpmap;
}

static int create_new_voipcin(rtpstreaminf_t **activecins, uint32_t cin_id,
        voipintercept_t *vint) {

    rtpstreaminf_t *newcin;

    newcin = create_rtpstream(vint, cin_id);

    if (!newcin) {
        logger(LOG_INFO,
                "OpenLI: out of memory while creating new RTP stream");
        logger(LOG_INFO,
                "OpenLI: forcing provisioner to halt.");
        exit(-2);
    }
    HASH_ADD_KEYPTR(hh, *activecins, newcin->streamkey,
            strlen(newcin->streamkey), newcin);
    return 0;

}

static inline int lookup_sip_callid(collector_sync_voip_t *sync, char *callid) {

    voipcinmap_t *lookup;

    HASH_FIND(hh_callid, sync->knowncallids, callid, strlen(callid), lookup);
    if (!lookup) {
        return 0;
    }
    return 1;
}

static sipregister_t *create_new_voip_registration(collector_sync_voip_t *sync,
        voipintercept_t *vint, char *callid,
        openli_sip_identity_t *targetuser) {

    sipregister_t *newreg = NULL;
    uint32_t cin_id = 0;

    if (update_cin_callid_map(&(sync->knowncallids), callid, NULL,
            targetuser->username, targetuser->realm) == NULL) {
        remove_cin_callid_from_map(&(vint->cin_callid_map), callid);
        return NULL;
    }

    HASH_FIND(hh, vint->active_registrations, callid, strlen(callid), newreg);
    if (!newreg) {
        cin_id = hashlittle(callid, strlen(callid), 0xceefface);
        cin_id = (cin_id % (uint32_t)(pow(2, 31)));
        newreg = create_sipregister(vint, callid, cin_id);

        HASH_ADD_KEYPTR(hh, vint->active_registrations, newreg->callid,
                strlen(newreg->callid), newreg);

    }

    return newreg;
}

static voipintshared_t *create_new_voip_session(collector_sync_voip_t *sync,
        char *callid, sip_sdp_identifier_t *sdpo, voipintercept_t *vint,
        openli_sip_identity_t *targetuser) {

    voipintshared_t *vshared = NULL;
    uint32_t cin_id = 0;

    cin_id = hashlittle(callid, strlen(callid), 0xceefface);
    cin_id = (cin_id % (uint32_t)(pow(2, 31)));

    if (create_new_voipcin(&(vint->active_cins), cin_id, vint) == -1) {
        return NULL;
    }

    logger(LOG_INFO,
            "OpenLI: creating new VOIP session for LIID %s (callID=%s)",
            vint->common.liid, callid);

    vshared = (voipintshared_t *)malloc(sizeof(voipintshared_t));
    vshared->cin = cin_id;
    vshared->refs = 0;

    if (update_cin_callid_map(&(vint->cin_callid_map), callid,
                vshared, targetuser->username, targetuser->realm) == NULL) {
        free(vshared);
        return NULL;
    }

    if (update_cin_callid_map(&(sync->knowncallids), callid, NULL,
                targetuser->username, targetuser->realm) == NULL) {
        remove_cin_callid_from_map(&(vint->cin_callid_map), callid);
        free(vshared);
        return NULL;
    }

    if (sdpo && update_cin_sdp_map(vint, sdpo, vshared,
                targetuser->username, targetuser->realm) == NULL) {
        remove_cin_callid_from_map(&(vint->cin_callid_map), callid);
        remove_cin_callid_from_map(&(sync->knowncallids), callid);

        free(vshared);
        return NULL;
    }
    return vshared;
}

static int process_sip_183sessprog(collector_sync_voip_t *sync,
        rtpstreaminf_t *thisrtp, voipintercept_t *vint,
        openli_export_recv_t *irimsg) {

    char *cseqstr, *ipstr, *portstr, *mediatype;
    int i = 1;
    int changed = 0;

    cseqstr = get_sip_cseq(sync->sipparser);

    if (thisrtp->invitecseq && strcmp(thisrtp->invitecseq,
                cseqstr) == 0) {
        uint8_t dir = 0xff;

        ipstr = get_sip_media_ipaddr(sync->sipparser);
        portstr = get_sip_media_port(sync->sipparser, 0);
        mediatype = get_sip_media_type(sync->sipparser, 0);

        if (!ipstr || !portstr || !mediatype) {
            free(cseqstr);
            return 0;
        }


        if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipsrc,
                16) == 0) {
            dir = 0;
        } else if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipdest,
                16) == 0) {
            dir = 1;
        }

        while (dir != 0xff && thisrtp->invitecseq_stack == 1 && portstr &&
                mediatype && ipstr) {

            if ((changed = update_rtp_stream(sync, thisrtp, ipstr,
                    portstr, mediatype, dir)) == -1) {
                if (sync->log_bad_sip) {
                    logger(LOG_INFO,
                        "OpenLI: error adding new RTP stream for LIID %s (%s:%s)",
                        vint->common.liid, ipstr, portstr);
                }
                free(cseqstr);
                return -1;
            }
            portstr = get_sip_media_port(sync->sipparser, i);
            mediatype = get_sip_media_type(sync->sipparser, i);
            i++;
            if (changed) {
                thisrtp->changed = 1;
            }
        }

        if (thisrtp->invitecseq_stack >= 1) {
            thisrtp->invitecseq_stack --;
            announce_rtp_streams_if_required(sync, thisrtp);
        }
    }
    free(cseqstr);
    return 0;
}

static int process_sip_200ok(collector_sync_voip_t *sync,
        rtpstreaminf_t *thisrtp, voipintercept_t *vint,
        etsili_iri_type_t *iritype, openli_export_recv_t *irimsg) {

    char *ipstr, *portstr, *cseqstr, *mediatype;
    int i = 1;
    int changed = 0;

    cseqstr = get_sip_cseq(sync->sipparser);

    if (thisrtp->invitecseq && strcmp(thisrtp->invitecseq,
                cseqstr) == 0) {
        uint8_t dir = 0xff;
        ipstr = get_sip_media_ipaddr(sync->sipparser);
        portstr = get_sip_media_port(sync->sipparser, 0);
        mediatype = get_sip_media_type(sync->sipparser, 0);

        if (!ipstr || !portstr || !mediatype) {
            free(cseqstr);
            return 0;
        }

        if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipsrc,
                16) == 0) {
            dir = 0;
        } else if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipdest,
                16) == 0) {
            dir = 1;
        }

        /* while loop here because there may be multiple media streams
         * in the SDP body (e.g. video and audio).
         */
        while (dir != 0xff && thisrtp->invitecseq_stack == 1 && portstr &&
                ipstr && mediatype) {
            if ((changed = update_rtp_stream(sync, thisrtp, ipstr,
                    portstr, mediatype, dir)) == -1) {
                if (sync->log_bad_sip) {
                    logger(LOG_INFO,
                        "OpenLI: error adding new RTP stream for LIID %s (%s:%s)",
                        vint->common.liid, ipstr, portstr);
                }
                free(cseqstr);
                return -1;
            }
            portstr = get_sip_media_port(sync->sipparser, i);
            mediatype = get_sip_media_type(sync->sipparser, i);
            i++;
            if (changed) {
                thisrtp->changed = 1;
            }
        }
        if (thisrtp->invitecseq_stack >= 1) {
            thisrtp->invitecseq_stack --;
            announce_rtp_streams_if_required(sync, thisrtp);
        }

    } else if (thisrtp->byecseq && strcmp(thisrtp->byecseq,
                cseqstr) == 0 && thisrtp->byematched == 0) {
        sync_epoll_t *timeout = (sync_epoll_t *)calloc(1,
                sizeof(sync_epoll_t));
        struct itimerspec its;

        its.it_value.tv_sec = 30;
        its.it_value.tv_nsec = 0;
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;

        /* Call for this session should be over */
        thisrtp->timeout_ev = (void *)timeout;
        timeout->fdtype = SYNC_EVENT_SIP_TIMEOUT;
        timeout->fd = timerfd_create(CLOCK_MONOTONIC, 0);
        timerfd_settime(timeout->fd, 0, &its, NULL);

        timeout->ptr = thisrtp;
        if (timeout->fd > 0) {
            HASH_ADD_KEYPTR(hh, sync->timeouts, &(timeout->fd), sizeof(int),
                    timeout);
        } else {
            /* if we can't get a valid file descriptor for a timer, we
             * have to just purge the call right away... */
            free(timeout);
            thisrtp->timeout_ev = NULL;
            push_voipintercept_halt_to_threads(sync, thisrtp->parent);
        }

        thisrtp->byematched = 1;
        *iritype = ETSILI_IRI_END;
    }
    free(cseqstr);
    return 0;
}

static inline void create_sip_ipiri(collector_sync_voip_t *sync,
        voipintercept_t *vint, openli_export_recv_t *irimsg,
        etsili_iri_type_t iritype, int64_t cin, openli_location_t *loc,
        int loc_count, libtrace_packet_t **pkts, int pkt_cnt) {

    openli_export_recv_t *copy;

    if (vint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
        return;
    }

    if (vint->common.tostart_time > irimsg->ts.tv_sec) {
        return;
    }

    if (vint->common.toend_time > 0 &&
            vint->common.toend_time <= irimsg->ts.tv_sec) {
        return;
    }

    if (vint->common.targetagency == NULL ||
            strcmp(vint->common.targetagency, "pcapdisk") == 0) {
        int i;
        if (pkts == NULL) {
            return;
        }
        for (i = 0; i < pkt_cnt; i++) {
            if (pkts[i] == NULL) {
                continue;
            }
            copy = create_rawip_iri_job(vint->common.liid, vint->common.destid,
                pkts[i]);
            publish_openli_msg(sync->zmq_pubsocks[vint->common.seqtrackerid],
                    copy);
        }
        return;
    }
    /* TODO consider recycling IRI messages like we do with IPCCs */

    /* Wrap this packet up in an IRI and forward it on to the exporter.
     * irimsg may be used multiple times, so make a copy and forward
     * that instead. */
    copy = calloc(1, sizeof(openli_export_recv_t));
    memcpy(copy, irimsg, sizeof(openli_export_recv_t));

    copy->data.ipmmiri.liid = strdup(vint->common.liid);
    copy->destid = vint->common.destid;
    copy->data.ipmmiri.iritype = iritype;
    copy->data.ipmmiri.cin = cin;

    copy->data.ipmmiri.content = malloc(copy->data.ipmmiri.contentlen);
    memcpy(copy->data.ipmmiri.content, irimsg->data.ipmmiri.content,
            irimsg->data.ipmmiri.contentlen);
    copy_location_into_ipmmiri_job(copy, loc, loc_count);

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->ipmmiri_created ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);
    publish_openli_msg(sync->zmq_pubsocks[vint->common.seqtrackerid], copy);
}

static int process_sip_register_followup(collector_sync_voip_t *sync,
        voipintercept_t *vint, sipregister_t *sipreg,
        openli_export_recv_t *irimsg, libtrace_packet_t **pkts,
        int pkt_cnt) {


    create_sip_ipiri(sync, vint, irimsg, ETSILI_IRI_REPORT, sipreg->cin,
            NULL, 0, pkts, pkt_cnt);
    return 1;
}

static int process_sip_other(collector_sync_voip_t *sync, char *callid,
        openli_export_recv_t *irimsg, libtrace_packet_t **pkts, int pkt_cnt) {

    voipintercept_t *vint, *tmp;
    voipcinmap_t *findcin;
    sipregister_t *findreg;
    voipintshared_t *vshared;
    char rtpkey[256];
    rtpstreaminf_t *thisrtp;
    etsili_iri_type_t iritype = ETSILI_IRI_CONTINUE;
    int exportcount = 0;
    int badsip = 0, r, loc_cnt;
    openli_location_t *locptr;

    locptr = NULL;
    loc_cnt = 0;
    if ((r = get_sip_paccess_network_info(sync->sipparser, &locptr,
                &loc_cnt)) < 0) {
        if (sync->log_bad_sip) {
            logger(LOG_INFO,
                    "OpenLI: P-Access-Network-Info is malformed?");
            sync->log_bad_sip = 0;

        }
    }

    HASH_ITER(hh_liid, sync->voipintercepts, vint, tmp) {

        /* Is this call ID associated with this intercept? */
        HASH_FIND(hh_callid, vint->cin_callid_map, callid, strlen(callid),
                findcin);

        if (!findcin) {
            HASH_FIND(hh, vint->active_registrations, callid,
                    strlen(callid), findreg);
            if (findreg) {
                exportcount += process_sip_register_followup(sync, vint,
                        findreg, irimsg, pkts, pkt_cnt);
            }
            continue;
        }

        vshared = findcin->shared;

        snprintf(rtpkey, 256, "%s-%u", vint->common.liid, vshared->cin);
        HASH_FIND(hh, vint->active_cins, rtpkey, strlen(rtpkey), thisrtp);
        if (thisrtp == NULL) {
            if (sync->log_bad_sip) {
                logger(LOG_INFO,
                        "OpenLI: unable to find %u in the active call list for %s",
                        vshared->cin, vint->common.liid);
            }
            badsip = 1;
            continue;
        }

        /* Check for a new RTP stream announcement in a 200 OK */
        if (sip_is_200ok(sync->sipparser)) {
            if (process_sip_200ok(sync, thisrtp, vint, &iritype, irimsg) < 0) {
                badsip = 1;
                continue;
            }
        }

        /* Check for 183 Session Progress, as this can contain RTP info */
        /* Also check for 180, which can be handled in more or less the
         * same way from our perspective...
         */
        if (sip_is_183sessprog(sync->sipparser) ||
                    sip_is_180ringing(sync->sipparser)) {
            if (process_sip_183sessprog(sync, thisrtp, vint, irimsg) < 0) {
                badsip = 1;
                continue;
            }
        }

        /* Check for a BYE or CANCEL*/
        if ((sip_is_bye(sync->sipparser) || sip_is_cancel(sync->sipparser))
                && !thisrtp->byematched) {
            if (thisrtp->byecseq) {
                free(thisrtp->byecseq);
            }
            thisrtp->byecseq = get_sip_cseq(sync->sipparser);
        }

        if (thisrtp->byematched && iritype != ETSILI_IRI_END) {
            /* All post-END IRIs must be REPORTs */
            iritype = ETSILI_IRI_REPORT;
        }

        /* Wrap this packet up in an IRI and forward it on to the exporter */
        create_sip_ipiri(sync, vint, irimsg, iritype, vshared->cin, locptr,
                loc_cnt, pkts, pkt_cnt);
        exportcount += 1;
    }
    if (locptr) {
        free(locptr);
    }
    if (badsip) {
        return -1;
    }
    return exportcount;

}

static int process_sip_register(collector_sync_voip_t *sync, char *callid,
        openli_export_recv_t *irimsg, libtrace_packet_t **pkts, int pkt_cnt) {

    openli_sip_identity_t *matched = NULL;
    voipintercept_t *vint, *tmp;
    sipregister_t *sipreg;
    int exportcount = 0, r, loc_cnt;
    uint8_t trust_sip_from;
    openli_location_t *locptr;

    openli_sip_identity_set_t all_identities;

    locptr = NULL;
    loc_cnt = 0;

    if (extract_sip_identities(sync->sipparser, &all_identities,
            sync->log_bad_sip) < 0) {
        sync->log_bad_sip = 0;
        return -1;
    }

    if ((r = get_sip_paccess_network_info(sync->sipparser, &locptr,
                &loc_cnt)) < 0) {
        if (sync->log_bad_sip) {
            logger(LOG_INFO,
                    "OpenLI: P-Access-Network-Info is malformed?");
            sync->log_bad_sip = 0;

        }
    }

    pthread_rwlock_rdlock(sync->info_mutex);
    trust_sip_from = sync->info->trust_sip_from;
    pthread_rwlock_unlock(sync->info_mutex);

    HASH_ITER(hh_liid, sync->voipintercepts, vint, tmp) {
        sipreg = NULL;

        matched = match_sip_target_against_identities(vint->targets,
                &all_identities, trust_sip_from);
        if (matched == NULL) {
            continue;
        }
        sipreg = create_new_voip_registration(sync, vint, callid, matched);
        if (!sipreg) {
            continue;
        }
        create_sip_ipiri(sync, vint, irimsg, ETSILI_IRI_REPORT, sipreg->cin,
                locptr, loc_cnt, pkts, pkt_cnt);
        exportcount += 1;
    }

    if (locptr) {
        free(locptr);
    }
    release_openli_sip_identity_set(&all_identities);

    return exportcount;
}

static int process_sip_invite(collector_sync_voip_t *sync, char *callid,
        sip_sdp_identifier_t *sdpo, openli_export_recv_t *irimsg,
        libtrace_packet_t **pkts, int pkt_cnt) {

    voipintercept_t *vint, *tmp;
    voipcinmap_t *findcin;
    voipsdpmap_t *findsdp = NULL;
    voipintshared_t *vshared;
    openli_sip_identity_t *matched = NULL;
    char rtpkey[256];
    rtpstreaminf_t *thisrtp;
    char *ipstr, *portstr, *mediatype;
    int exportcount = 0;
    etsili_iri_type_t iritype = ETSILI_IRI_REPORT;
    int badsip = 0;
    int i = 1, r, loc_cnt;
    uint8_t dir = 0xff;
    openli_sip_identity_set_t all_identities;
    uint8_t trust_sip_from;
    openli_location_t *locptr;
    char *invitecseq = NULL;

    locptr = NULL;
    loc_cnt = 0;

    if (extract_sip_identities(sync->sipparser, &all_identities,
            sync->log_bad_sip) < 0) {
        sync->log_bad_sip = 0;
        return -1;
    }

    if ((r = get_sip_paccess_network_info(sync->sipparser, &locptr,
                &loc_cnt)) < 0) {
        if (sync->log_bad_sip) {
            logger(LOG_INFO,
                    "OpenLI: P-Access-Network-Info is malformed?");
            sync->log_bad_sip = 0;

        }
    }

    pthread_rwlock_rdlock(sync->info_mutex);
    trust_sip_from = sync->info->trust_sip_from;
    pthread_rwlock_unlock(sync->info_mutex);

    invitecseq = get_sip_cseq(sync->sipparser);
    HASH_ITER(hh_liid, sync->voipintercepts, vint, tmp) {
        vshared = NULL;

        /* Is this a call ID we've seen already? */
        HASH_FIND(hh_callid, vint->cin_callid_map, callid, strlen(callid),
                findcin);

        if (!sync->ignore_sdpo_matches) {
            HASH_FIND(hh_sdp, vint->cin_sdp_map, sdpo,
                    sizeof(sip_sdp_identifier_t), findsdp);
        } else {
            findsdp = NULL;
        }

        if (findcin) {
            if (findsdp) {
                if (findsdp->shared->cin != findcin->shared->cin) {
                    if (sync->log_bad_sip) {
                        logger(LOG_INFO,
                                "OpenLI: mismatched CINs for call %s and SDP identifier %u:%u:%s:%s",
                                callid,
                                sdpo->sessionid, sdpo->version, sdpo->username,
                                sdpo->address);
                    }
                    badsip = 1;
                    break;
                }
            }

            update_cin_sdp_map(vint, sdpo, findcin->shared, findcin->username,
                    findcin->realm);
            vshared = findcin->shared;
            iritype = ETSILI_IRI_CONTINUE;

        } else if (findsdp) {
            /* New call ID but already seen this session from another
             * call leg
             */
            update_cin_callid_map(&(vint->cin_callid_map), callid,
                        findsdp->shared, findsdp->username, findsdp->realm);
            vshared = findsdp->shared;
            iritype = ETSILI_IRI_CONTINUE;

        } else {
            /* Doesn't match an existing intercept, but could match one of
             * our target identities */
            matched = match_sip_target_against_identities(vint->targets,
                    &all_identities, trust_sip_from);
            if (matched == NULL) {
                continue;
            }
            vshared = create_new_voip_session(sync, callid, sdpo, vint,
                    matched);

            iritype = ETSILI_IRI_BEGIN;
        }

        if (!vshared) {
            continue;
        }

        snprintf(rtpkey, 256, "%s-%u", vint->common.liid, vshared->cin);
        HASH_FIND(hh, vint->active_cins, rtpkey, strlen(rtpkey), thisrtp);
        if (thisrtp == NULL) {
            if (sync->log_bad_sip) {
                logger(LOG_INFO,
                    "OpenLI: unable to find %u in the active call list for %s",
                    vshared->cin, vint->common.liid);
            }
            badsip = 1;
            continue;
        }

        thisrtp->changed = 0;

        ipstr = get_sip_media_ipaddr(sync->sipparser);
        portstr = get_sip_media_port(sync->sipparser, 0);
        mediatype = get_sip_media_type(sync->sipparser, 0);

        if (thisrtp->invitecseq && invitecseq &&
                strcmp(thisrtp->invitecseq, invitecseq) == 0) {
            dir = 0xff;
        } else if (iritype == ETSILI_IRI_BEGIN) {
            memcpy(thisrtp->inviter, irimsg->data.ipmmiri.ipsrc, 16);
            dir = 0;
        } else if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipsrc,
                16) == 0) {
            dir = 0;
        } else if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipdest,
                16) == 0) {
            dir = 1;
        }

        while (dir != 0xff && ipstr && portstr && !badsip && mediatype) {
            int changed;
            if ((changed = update_rtp_stream(sync, thisrtp, ipstr,
                    portstr, mediatype, dir)) == -1) {
                if (sync->log_bad_sip) {
                    logger(LOG_INFO,
                        "OpenLI: error adding new RTP stream for LIID %s (%s:%s)",
                        vint->common.liid, ipstr, portstr);
                }
                badsip = 1;
                break;
            }
            portstr = get_sip_media_port(sync->sipparser, i);
            mediatype = get_sip_media_type(sync->sipparser, i);
            i++;
            if (changed) {
                thisrtp->changed = 1;
            }
        }

        //announce_rtp_streams_if_required(sync, thisrtp);
        if (badsip) {
            continue;
        }

        /* A bit of an explanation of invitecseq_stack...
         *
         * This is mainly dedicated to resolving issues that arise
         * when we see both sides of a proxied SIP session (i.e.
         * A->B followed by B->C and the reverse for the opposite
         * direction).
         *
         * In these cases, we have to be careful to only track the
         * RTP session for ONE of the sides of the proxying, otherwise
         * we get confused and try to intercept RTP streams that don't
         * exist (such as the outgoing port from A->B and the incoming
         * port for C->B).
         *
         * To further complicate matters, we can see reversed direction
         * INVITEs (e.g. on call connection to confirm the media port)
         * so we cannot assume that an INVITE is coming from the caller.
         *
         * So what I'm trying to do here is two things:
         *  1. always track the RTP stream for A->B session only.
         *  2. don't screw up if we see a reversed INVITE.
         *
         * I'm doing this by counting the number of times I see a
         * specific INVITE cseq, and reducing that count whenever I
         * see a 183 or 200 with the response SDP info. When the count
         * gets down to zero, that response must belong to the initial
         * A->B INVITE.
         *
         * For subsequent INVITEs, the counting only starts when the initial
         * inviting IP address was involved (either as a sender or receiver)
         * so if a reverse INVITE from C->B won't be looked at for RTP stream
         * tracking purposes until it is proxied to the B->A link.
         *
         * There is one edge case where this will still break and I have
         * no idea how to resolve it: if the proxy is not A->B and B->C,
         * but instead is A->B and B->A.
         */
        if (invitecseq) {
            if (dir != 0xff && thisrtp->invitecseq == NULL) {
                thisrtp->invitecseq = strdup(invitecseq);
                thisrtp->invitecseq_stack = 1;
            } else if (thisrtp->invitecseq != NULL &&
                    strcmp(invitecseq, thisrtp->invitecseq) == 0) {
                thisrtp->invitecseq_stack ++;
            } else if (dir != 0xff && thisrtp->invitecseq != NULL) {
                free(thisrtp->invitecseq);
                thisrtp->invitecseq = NULL;
                thisrtp->invitecseq = strdup(invitecseq);
                thisrtp->invitecseq_stack = 1;
            }
        }

        create_sip_ipiri(sync, vint, irimsg, iritype, vshared->cin, locptr,
                loc_cnt, pkts, pkt_cnt);
        exportcount += 1;
    }

    if (invitecseq) {
        free(invitecseq);
    }
    if (locptr) {
        free(locptr);
    }
    release_openli_sip_identity_set(&all_identities);

    if (badsip) {
        return -1;
    }
    return exportcount;

}

static int update_sip_state(collector_sync_voip_t *sync,
        libtrace_packet_t **pkts, int pkt_cnt, openli_export_recv_t *irimsg) {

    char *callid, *sessid, *sessversion, *sessaddr, *sessuser;
    sip_sdp_identifier_t sdpo;
    int iserr = 0;
    int ret;

    callid = get_sip_callid(sync->sipparser);
    sessid = get_sip_session_id(sync->sipparser);
    sessversion = get_sip_session_version(sync->sipparser);
    sessaddr = get_sip_session_address(sync->sipparser);
    sessuser = get_sip_session_username(sync->sipparser);

    if (callid == NULL) {
        if (sync->log_bad_sip) {
            logger(LOG_INFO, "OpenLI: SIP packet has no Call ID?");
        }
        iserr = 1;
        goto sipgiveup;
    }

    memset(sdpo.address, 0, sizeof(sdpo.address));
    memset(sdpo.username, 0, sizeof(sdpo.username));

    if (sessid != NULL) {
        errno = 0;
        sdpo.sessionid = strtoul(sessid, NULL, 0);
        if (errno != 0) {
            if (sync->log_bad_sip) {
                logger(LOG_INFO, "OpenLI: invalid session ID in SIP packet %s",
                        sessid);
            }
            sessid = NULL;
            sdpo.sessionid = 0;
        }
    } else {
        sdpo.sessionid = 0;
    }

    if (sessversion != NULL) {
        errno = 0;
        sdpo.version = strtoul(sessversion, NULL, 0);
        if (errno != 0) {
            if (sync->log_bad_sip) {
                logger(LOG_INFO, "OpenLI: invalid version in SIP packet %s",
                        sessid);
            }
            sessversion = NULL;
            sdpo.version = 0;
        }
    } else {
        sdpo.version = 0;
    }

    if (sessaddr != NULL) {
        strncpy(sdpo.address, sessaddr, sizeof(sdpo.address) - 1);
    } else {
        strncpy(sdpo.address, callid, sizeof(sdpo.address) - 1);
    }

    if (sessuser != NULL) {
        strncpy(sdpo.username, sessuser, sizeof(sdpo.username) - 1);
    } else {
        strncpy(sdpo.username, "unknown", sizeof(sdpo.username) - 1);
    }

    ret = 0;
    if (sip_is_invite(sync->sipparser)) {
        if ((ret = process_sip_invite(sync, callid, &sdpo, irimsg, pkts,
                pkt_cnt)) < 0) {
            iserr = 1;
            if (sync->log_bad_sip) {
                logger(LOG_INFO, "OpenLI: error while processing SIP invite");
            }
            goto sipgiveup;
        }
    } else if (sip_is_register(sync->sipparser)) {
        if ((ret = process_sip_register(sync, callid, irimsg, pkts,
                pkt_cnt)) < 0) {
            iserr = 1;
            if (sync->log_bad_sip) {
                logger(LOG_INFO, "OpenLI: error while processing SIP register");
            }
            goto sipgiveup;
        }
    } else if (lookup_sip_callid(sync, callid) != 0) {
        /* SIP packet matches a "known" call of interest */
        if ((ret = process_sip_other(sync, callid, irimsg, pkts,
                pkt_cnt)) < 0) {
            iserr = 1;
            if (sync->log_bad_sip) {
                logger(LOG_INFO, "OpenLI: error while processing non-invite SIP");
            }
            goto sipgiveup;
        }
    }
    if (ret == 0) {
        return 0;
    }

sipgiveup:

    if (iserr) {
        pthread_mutex_lock(sync->glob->stats_mutex);
        sync->glob->stats->bad_sip_packets ++;
        pthread_mutex_unlock(sync->glob->stats_mutex);
        return -1;
    }
    return 1;

}

static int update_modified_voipintercept(collector_sync_voip_t *sync,
        voipintercept_t *vint, voipintercept_t *tomod) {

    int changed = 0, encodingchanged = 0;

    sync->log_bad_instruct = 1;

    encodingchanged = update_modified_intercept_common(&(vint->common),
            &(tomod->common), OPENLI_INTERCEPT_TYPE_VOIP, &changed);

    if (tomod->options != vint->options) {
        if (tomod->options & (1UL << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT)) {
            logger(LOG_INFO,
                    "OpenLI: VOIP intercept %s is now ignoring RTP comfort noise",
                    tomod->common.liid);
        } else {
            logger(LOG_INFO,
                    "OpenLI: VOIP intercept %s is now intercepting RTP comfort noise",
                    tomod->common.liid);
        }
        vint->options = tomod->options;
        changed = 1;
    }

    if (encodingchanged) {
        openli_export_recv_t *expmsg;
        expmsg = create_intercept_details_msg(&(vint->common));
        expmsg->type = OPENLI_EXPORT_INTERCEPT_CHANGED;
        publish_openli_msg(sync->zmq_pubsocks[vint->common.seqtrackerid],
                expmsg);
    }

    if (changed) {
        push_voip_intercept_update_to_threads(sync, vint);
    }

    return 0;
}

static int modify_voipintercept(collector_sync_voip_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    voipintercept_t *vint, *tomod;

    tomod = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_modify(intmsg, msglen, tomod) == -1) {
        if (sync->log_bad_instruct) {
            logger(LOG_INFO,
                "OpenLI: received invalid VOIP intercept modification from provisioner.");
        }
        return -1;
    }

    HASH_FIND(hh_liid, sync->voipintercepts, tomod->common.liid,
            tomod->common.liid_len, vint);
    if (!vint) {
        if (sync->log_bad_instruct) {
            logger(LOG_INFO,
                "OpenLI: received modification for VOIP intercept %s but it is not present in the sync intercept list?",
                tomod->common.liid);
        }
        return 0;
    }

    update_modified_voipintercept(sync, vint, tomod);
    free_single_voipintercept(tomod);
    return 1;
}

static inline void remove_voipintercept(collector_sync_voip_t *sync,
        voipintercept_t *vint) {

    openli_export_recv_t *expmsg, *fwdmsg;
    int i;

    push_voipintercept_halt_to_threads(sync, vint);

    expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    expmsg->type = OPENLI_EXPORT_INTERCEPT_OVER;
    expmsg->data.cept.liid = strdup(vint->common.liid);
    expmsg->data.cept.authcc = strdup(vint->common.authcc);
    expmsg->data.cept.delivcc = strdup(vint->common.delivcc);
    expmsg->data.cept.seqtrackerid = vint->common.seqtrackerid;

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->voipintercepts_ended_diff ++;
    sync->glob->stats->voipintercepts_ended_total ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);
    publish_openli_msg(sync->zmq_pubsocks[vint->common.seqtrackerid], expmsg);

    for (i = 0; i < sync->forwardcount; i++) {
        fwdmsg = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));
        fwdmsg->type = OPENLI_EXPORT_INTERCEPT_OVER;
        fwdmsg->data.cept.liid = strdup(vint->common.liid);
        fwdmsg->data.cept.authcc = strdup(vint->common.authcc);
        fwdmsg->data.cept.delivcc = strdup(vint->common.delivcc);
        publish_openli_msg(sync->zmq_fwdctrlsocks[i], fwdmsg);
    }


    HASH_DELETE(hh_liid, sync->voipintercepts, vint);
    free_single_voipintercept(vint);
}

static int halt_voipintercept(collector_sync_voip_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    voipintercept_t *vint, *torem;

    torem = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_halt(intmsg, msglen, torem) == -1) {
        if (sync->log_bad_instruct) {
            logger(LOG_INFO,
                "OpenLI: received invalid VOIP intercept withdrawal from provisioner.");
        }
        return -1;
    }

    HASH_FIND(hh_liid, sync->voipintercepts, torem->common.liid,
            torem->common.liid_len, vint);
    if (!vint) {
        return 0;
    }

    sync->log_bad_instruct = 1;
    logger(LOG_INFO, "OpenLI: sync thread withdrawing VOIP intercept %s",
            torem->common.liid);

    remove_voipintercept(sync, vint);
    free_single_voipintercept(torem);
    return 0;
}

static int halt_single_rtpstream(collector_sync_voip_t *sync, rtpstreaminf_t *rtp) {

    voipcinmap_t *cin_callid, *tmp;
    voipsdpmap_t *cin_sdp, *tmp2;
    sync_sendq_t *sendq, *tmp3;
    sync_epoll_t *syncev;

    if (rtp->timeout_ev) {
        sync_epoll_t *timerev = (sync_epoll_t *)(rtp->timeout_ev);

        HASH_FIND(hh, sync->timeouts, &(timerev->fd), sizeof(int), syncev);
        if (syncev) {
            HASH_DELETE(hh, sync->timeouts, syncev);
        }

        close(timerev->fd);
        free(timerev);
        rtp->timeout_ev = NULL;
    }


    if (rtp->active) {
        HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues), sendq,
                tmp3) {
           openli_pushed_t msg;
           memset(&msg, 0, sizeof(openli_pushed_t));
           msg.type = OPENLI_PUSH_HALT_IPMMINTERCEPT;
           msg.data.rtpstreamkey = strdup(rtp->streamkey);
           libtrace_message_queue_put(sendq->q, (void *)(&msg));
        }
    }

    HASH_DEL(rtp->parent->active_cins, rtp);

    /* TODO this is painful, maybe include reverse references in the shared
     * data structure?
     */
    HASH_ITER(hh_callid, rtp->parent->cin_callid_map, cin_callid, tmp) {
        if (cin_callid->shared->cin == rtp->cin) {
            HASH_DELETE(hh_callid, rtp->parent->cin_callid_map, cin_callid);
            free(cin_callid->callid);
            cin_callid->shared->refs --;
            if (cin_callid->shared->refs == 0) {
                free(cin_callid->shared);
                break;
            }
            if (cin_callid->username) {
                free(cin_callid->username);
            }
            if (cin_callid->realm) {
                free(cin_callid->realm);
            }
            free(cin_callid);
        }
    }

    HASH_ITER(hh_sdp, rtp->parent->cin_sdp_map, cin_sdp, tmp2) {
        int stop = 0;
        if (cin_sdp->shared->cin == rtp->cin) {
            HASH_DELETE(hh_sdp, rtp->parent->cin_sdp_map, cin_sdp);
            cin_sdp->shared->refs --;
            if (cin_sdp->shared->refs == 0) {
                free(cin_sdp->shared);
                stop = 1;
            }
            if (cin_sdp->username) {
                free(cin_sdp->username);
            }
            if (cin_sdp->realm) {
                free(cin_sdp->realm);
            }
            free(cin_sdp);
            if (stop) {
                break;
            }
        }
    }

    free_single_rtpstream(rtp);

    return 0;
}

static int new_voip_sip_target(collector_sync_voip_t *sync, uint8_t *intmsg,
		uint16_t msglen) {

    voipintercept_t *vint;
    openli_sip_identity_t sipid;
    char liidspace[1024];

    if (decode_sip_target_announcement(intmsg, msglen, &sipid, liidspace,
            1024) < 0) {
        if (sync->log_bad_instruct) {
            logger(LOG_INFO,
                    "OpenLI: received invalid SIP target from provisioner.");
        }
        return -1;
    }

    HASH_FIND(hh_liid, sync->voipintercepts, liidspace, strlen(liidspace),
            vint);
    if (!vint) {
        if (sync->log_bad_instruct) {
            logger(LOG_INFO,
                    "OpenLI: received SIP target for unknown VOIP LIID %s.",
                    liidspace);
        }
        return -1;
    }

    sync->log_bad_instruct = 1;
    logger(LOG_INFO,
            "OpenLI: collector received new SIP target for LIID %s.",
            vint->common.liid);

    add_new_sip_target_to_list(vint, &sipid);
    return 0;
}


static int withdraw_voip_sip_target(collector_sync_voip_t *sync,
        uint8_t *intmsg, uint16_t msglen) {

    voipintercept_t *vint;
    openli_sip_identity_t sipid;
    char liidspace[1024];
    int ret = 0;

    if (decode_sip_target_announcement(intmsg, msglen, &sipid, liidspace,
            1024) < 0) {
        if (sync->log_bad_instruct) {
            logger(LOG_INFO,
                "OpenLI: received invalid SIP target withdrawal from provisioner.");
        }
        ret = -1;
        goto withdrawend;
    }

    HASH_FIND(hh_liid, sync->voipintercepts, liidspace, strlen(liidspace),
            vint);
    if (!vint) {
        if (sync->log_bad_instruct) {
            logger(LOG_INFO,
                "OpenLI: received SIP target withdrawal for unknown VOIP LIID %s.",
                liidspace);
        }
        ret = -1;
        goto withdrawend;
    }

    sync->log_bad_instruct = 1;
    logger(LOG_INFO,
            "OpenLI: collector is withdrawing SIP target for LIID %s.",
            vint->common.liid);
    disable_sip_target_from_list(vint, &sipid);

withdrawend:
    if (sipid.username) {
        free(sipid.username);
    }
    if (sipid.realm) {
        free(sipid.realm);
    }
    return ret;
}

static int new_voipintercept(collector_sync_voip_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    voipintercept_t *vint, *toadd;
    sync_sendq_t *sendq, *tmp;
    openli_export_recv_t *expmsg;

    toadd = (voipintercept_t *)malloc(sizeof(voipintercept_t));
    if (decode_voipintercept_start(intmsg, msglen, toadd) == -1) {
        if (sync->log_bad_instruct) {
            logger(LOG_INFO,
                "OpenLI: received invalid VOIP intercept from provisioner.");
        }
        return -1;
    }

    if (sync->log_bad_instruct == 0) {
        sync->log_bad_instruct = 1;
    }

    HASH_FIND(hh_liid, sync->voipintercepts, toadd->common.liid,
            toadd->common.liid_len, vint);
    if (vint) {
        vint->awaitingconfirm = 0;
        vint->active = 1;
        update_modified_voipintercept(sync, vint, toadd);
        free_single_voipintercept(toadd);
        return 0;
    } else {
        vint = toadd;
    }

    vint->common.seqtrackerid = hash_liid(vint->common.liid) %
            sync->pubsockcount;

    HASH_ADD_KEYPTR(hh_liid, sync->voipintercepts, vint->common.liid,
            vint->common.liid_len, vint);

    expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    expmsg->type = OPENLI_EXPORT_INTERCEPT_DETAILS;
    expmsg->data.cept.liid = strdup(vint->common.liid);
    expmsg->data.cept.authcc = strdup(vint->common.authcc);
    expmsg->data.cept.delivcc = strdup(vint->common.delivcc);
    expmsg->data.cept.encryptmethod = vint->common.encrypt;
    if (vint->common.encryptkey) {
        expmsg->data.cept.encryptkey = strdup(vint->common.encryptkey);
    } else {
        expmsg->data.cept.encryptkey = NULL;
    }
    expmsg->data.cept.seqtrackerid = vint->common.seqtrackerid;

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->voipintercepts_added_diff ++;
    sync->glob->stats->voipintercepts_added_total ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);

    publish_openli_msg(sync->zmq_pubsocks[vint->common.seqtrackerid], expmsg);

    pthread_mutex_lock(&(sync->glob->mutex));
    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues), sendq, tmp) {
        /* Forward all active CINs to our collector threads */
        push_all_active_voipstreams(sync, sendq->q, vint);

    }

    pthread_mutex_unlock(&(sync->glob->mutex));
    logger(LOG_INFO,
            "OpenLI: adding new VOIP intercept %s (start time %lu, end time %lu)", vint->common.liid, vint->common.tostart_time, vint->common.toend_time);
    return 0;
}

static libtrace_out_t *open_debug_output(char *basename, char *ext) {

    libtrace_out_t *out = NULL;
    char fname[1024];
    int compressmethod = TRACE_OPTION_COMPRESSTYPE_ZLIB;
    int compresslevel = 1;

    snprintf(fname, 1024, "pcapfile:%s-%s.pcap.gz", basename, ext);
    out = trace_create_output(fname);
    if (trace_is_err_output(out)) {
        trace_perror_output(out, "trace_create_output");
        goto debugfail;
    }

    if (trace_config_output(out, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
            &compressmethod) == -1) {
        trace_perror_output(out, "config compress type");
        goto debugfail;
    }

    if (trace_config_output(out, TRACE_OPTION_OUTPUT_COMPRESS,
                    &compresslevel) == -1) {
        trace_perror_output(out, "config compress level");
        goto debugfail;
    }

    if (trace_start_output(out) == -1) {
        trace_perror_output(out, "trace_start_output");
        goto debugfail;
    }

    return out;

debugfail:
    if (out) {
        trace_destroy_output(out);
    }
    return NULL;
}

static inline void get_ip_addresses(libtrace_packet_t *pkt,
        openli_ipmmiri_job_t *job) {

    void *ipheader;
    uint16_t ethertype;
    uint32_t  rem;

    job->ipfamily = 0;

    ipheader = trace_get_layer3(pkt, &ethertype, &rem);
    if (!ipheader || rem == 0) {
        return;
    }

    if (ethertype == TRACE_ETHERTYPE_IP) {
        libtrace_ip_t *ip4 = (libtrace_ip_t *)ipheader;

        job->ipfamily = AF_INET;
        memcpy(job->ipsrc, &(ip4->ip_src.s_addr), sizeof(uint32_t));
        memcpy(job->ipdest, &(ip4->ip_dst.s_addr), sizeof(uint32_t));
    } else {
        libtrace_ip6_t *ip6 = (libtrace_ip6_t *)ipheader;
        job->ipfamily = AF_INET;
        memcpy(job->ipsrc, &(ip6->ip_src.s6_addr), sizeof(struct in6_addr));
        memcpy(job->ipdest, &(ip6->ip_dst.s6_addr), sizeof(struct in6_addr));
    }

}

static inline void handle_bad_sip_update(collector_sync_voip_t *sync,
        libtrace_packet_t **packets, int pkt_cnt, uint8_t during) {

    int i;

    if (sync->log_bad_sip) {
        if (during == SIP_PROCESSING_PARSING) {
            logger(LOG_INFO,
                    "OpenLI: sync thread parsed an invalid SIP packet?");
        } else if (during == SIP_PROCESSING_UPDATING_STATE) {
            logger(LOG_INFO,
                    "OpenLI: error while updating SIP state in collector.");
        } else if (during == SIP_PROCESSING_EXTRACTING_IPS) {
            logger(LOG_INFO,
                    "OpenLI: error while extracting IP addresses from SIP packet");
        } else if (during == SIP_PROCESSING_ADD_PARSER) {
            logger(LOG_INFO,
                    "OpenLI: sync thread received an invalid SIP packet?");
        } else {
            logger(LOG_INFO,
                    "OpenLI: unexpected error when processing SIP packet");

        }
        logger(LOG_INFO,
                "OpenLI: will not log any further invalid SIP instances.");
        sync->log_bad_sip = 0;
    }
    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->bad_sip_packets ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);

    if (sync->sipdebugfile && packets) {
        if (!sync->sipdebugout) {
            sync->sipdebugout = open_debug_output(
                    sync->sipdebugfile, "invalid");
        }
        if (sync->sipdebugout) {
            for (i = 0; i < pkt_cnt; i++) {
                if (packets[i] == NULL) {
                    continue;
                }
                trace_write_packet(sync->sipdebugout, packets[i]);
            }
        }
    }
}

static void sip_update_fast_path(collector_sync_voip_t *sync,
        libtrace_packet_t *recvdpkt) {

    int ret;
    openli_export_recv_t baseirimsg;

    /* The provided packet contains an entire SIP message, so we
     * don't need to worry about segmentation or multiple
     * messages within the same packet.
     */

    memset(&baseirimsg, 0, sizeof(openli_export_recv_t));

    baseirimsg.type = OPENLI_EXPORT_IPMMIRI;
    baseirimsg.data.ipmmiri.ipmmiri_style = OPENLI_IPMMIRI_SIP;
    baseirimsg.ts = trace_get_timeval(recvdpkt);

    if (extract_ip_addresses(recvdpkt, baseirimsg.data.ipmmiri.ipsrc,
            baseirimsg.data.ipmmiri.ipdest,
            &(baseirimsg.data.ipmmiri.ipfamily)) != 0) {
        handle_bad_sip_update(sync, &recvdpkt, 1,
                SIP_PROCESSING_EXTRACTING_IPS);
        return;
    }

    ret = parse_next_sip_message(sync->sipparser, NULL, NULL);
    if (ret == 0) {
        return;
    }
    if (ret < 0) {
        handle_bad_sip_update(sync, &recvdpkt, 1, SIP_PROCESSING_PARSING);
        return;

    }
    baseirimsg.data.ipmmiri.content = (uint8_t *)get_sip_contents(
            sync->sipparser, &(baseirimsg.data.ipmmiri.contentlen));

    if (update_sip_state(sync, &recvdpkt, 1, &baseirimsg) < 0) {
        handle_bad_sip_update(sync, &recvdpkt, 1,
                SIP_PROCESSING_UPDATING_STATE);
    }

}

static void sip_update_slow_path(collector_sync_voip_t *sync,
        libtrace_packet_t *recvdpkt, uint8_t doonce) {

    int ret, i;
    openli_export_recv_t baseirimsg;
    libtrace_packet_t **packets = NULL;
    int pkt_cnt = 0;

    memset(&baseirimsg, 0, sizeof(openli_export_recv_t));

    baseirimsg.type = OPENLI_EXPORT_IPMMIRI;
    baseirimsg.data.ipmmiri.ipmmiri_style = OPENLI_IPMMIRI_SIP;
    baseirimsg.ts = trace_get_timeval(recvdpkt);

    if (extract_ip_addresses(recvdpkt, baseirimsg.data.ipmmiri.ipsrc,
            baseirimsg.data.ipmmiri.ipdest,
            &(baseirimsg.data.ipmmiri.ipfamily)) != 0) {
        handle_bad_sip_update(sync, &recvdpkt, 1,
                SIP_PROCESSING_EXTRACTING_IPS);
        return;
    }

    do {
        if (packets != NULL) {
            for (i = 0; i < pkt_cnt; i++) {
                if (packets[i]) {
                    trace_destroy_packet(packets[i]);
                }
            }
            free(packets);
            pkt_cnt = 0;
            packets = NULL;
        }

        ret = parse_next_sip_message(sync->sipparser, &packets, &pkt_cnt);
        if (ret == 0) {
            return;
        }
        if (ret < 0) {
            handle_bad_sip_update(sync, packets, pkt_cnt,
                    SIP_PROCESSING_PARSING);
            continue;
        }
        baseirimsg.data.ipmmiri.content = (uint8_t *)get_sip_contents(
                sync->sipparser, &(baseirimsg.data.ipmmiri.contentlen));
        if (update_sip_state(sync, packets, pkt_cnt, &baseirimsg) < 0) {
            handle_bad_sip_update(sync, packets, pkt_cnt,
                    SIP_PROCESSING_UPDATING_STATE);
            continue;
        }

    } while (!doonce);

    if (packets) {
        for (i = 0; i < pkt_cnt; i++) {
            if (packets[i]) {
                trace_destroy_packet(packets[i]);
            }
        }
        free(packets);
    }

}

static void examine_sip_update(collector_sync_voip_t *sync,
        libtrace_packet_t *recvdpkt) {

    int ret;

    ret = add_sip_packet_to_parser(&(sync->sipparser), recvdpkt,
            sync->log_bad_sip);

    if (ret == SIP_ACTION_ERROR) {
        handle_bad_sip_update(sync, &recvdpkt, 1,
                SIP_PROCESSING_ADD_PARSER);
    } else if (ret == SIP_ACTION_USE_PACKET) {
        sip_update_fast_path(sync, recvdpkt);
    } else if (ret == SIP_ACTION_REASSEMBLE_TCP) {
        sip_update_slow_path(sync, recvdpkt, 0);
        recvdpkt = NULL;        // consumed by the reassembler
    } else if (ret == SIP_ACTION_REASSEMBLE_IPFRAG) {
        sip_update_slow_path(sync, recvdpkt, 1);
    }

    if (recvdpkt) {
        trace_destroy_packet(recvdpkt);
    }
}

static inline int process_colthread_message(collector_sync_voip_t *sync) {

    openli_state_update_t recvd;
    int rc;

    do {
        rc = zmq_recv(sync->zmq_colsock, &recvd, sizeof(recvd), ZMQ_DONTWAIT);

        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO, "openli-collector: VOIP sync thread had an error receiving message from collector threads: %s", strerror(errno));
            return -1;
        }

        /* If a hello from a thread, push all active VOIP intercepts back */
        if (recvd.type == OPENLI_UPDATE_HELLO) {
            voipintercept_t *v;
            for (v = sync->voipintercepts; v != NULL; v = v->hh_liid.next) {
                push_all_active_voipstreams(sync, recvd.data.replyq, v);
            }
        }

        /* If an update from a thread, update appropriate internal state */

        /* If this resolves an unknown mapping or changes an existing one,
         * push II update messages to processing threads */

        /* If this relates to an active intercept, create IRI and export */

        if (recvd.type == OPENLI_UPDATE_SIP) {
            examine_sip_update(sync, recvd.data.pkt);
        }
    } while (rc > 0);

    return 0;
}

static void post_disable_unconfirmed_voip_intercept(voipintercept_t *vint,
        void *arg) {

    collector_sync_voip_t *sync = (collector_sync_voip_t *)(arg);
    if (sync && vint) {
        push_voipintercept_halt_to_threads(sync, vint);
    }
}

static void post_disable_unconfirmed_voip_target(openli_sip_identity_t *sipid,
        voipintercept_t *v, void *arg) {

    collector_sync_voip_t *sync = (collector_sync_voip_t *)(arg);
    if (sync == NULL || v == NULL || sipid == NULL) {
        return;
    }

    /* remove any active calls for this identity */
    remove_cin_callids_for_target(&(v->cin_callid_map),
            sipid->username, sipid->realm);
    remove_cin_sdpkeys_for_target(&(v->cin_sdp_map),
            sipid->username, sipid->realm);
    remove_cin_callids_for_target(&(sync->knowncallids),
            sipid->username, sipid->realm);
}

static inline int process_intersync_msg(collector_sync_voip_t *sync) {

    openli_intersync_msg_t syncmsg;

    libtrace_message_queue_get(sync->intersyncq, (void *)(&syncmsg));

    switch(syncmsg.msgtype) {
        case OPENLI_PROTO_START_VOIPINTERCEPT:
            if (new_voipintercept(sync, syncmsg.msgbody, syncmsg.msglen) < 0) {
                /* error, do something XXX */
                sync->log_bad_instruct = 0;
            }
            break;
        case OPENLI_PROTO_HALT_VOIPINTERCEPT:
            if (halt_voipintercept(sync, syncmsg.msgbody, syncmsg.msglen) < 0) {
                /* error, do something XXX */
                sync->log_bad_instruct = 0;
            }
            break;
        case OPENLI_PROTO_MODIFY_VOIPINTERCEPT:
            if (modify_voipintercept(sync, syncmsg.msgbody, syncmsg.msglen)
                    < 0) {
                /* error, do something XXX */
                sync->log_bad_instruct = 0;
            }
            break;
        case OPENLI_PROTO_ANNOUNCE_SIP_TARGET:
            if (new_voip_sip_target(sync, syncmsg.msgbody,
                    syncmsg.msglen) < 0) {
                /* error, do something XXX */
                sync->log_bad_instruct = 0;
            }
            break;
        case OPENLI_PROTO_WITHDRAW_SIP_TARGET:
            if (withdraw_voip_sip_target(sync, syncmsg.msgbody,
                    syncmsg.msglen) < 0) {
                /* error, do something XXX */
                sync->log_bad_instruct = 0;
            }
            break;
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            disable_unconfirmed_voip_intercepts(&(sync->voipintercepts),
                    post_disable_unconfirmed_voip_intercept, sync,
                    post_disable_unconfirmed_voip_target, sync);
            break;
        case OPENLI_PROTO_DISCONNECT:
            flag_voip_intercepts_as_unconfirmed(&(sync->voipintercepts));
            break;
        case OPENLI_PROTO_CONFIG_RELOADED:
            sync->log_bad_sip = 1;
            break;
    }

    if (syncmsg.msgbody) {
        free(syncmsg.msgbody);
    }
    return 0;
}


int sync_voip_thread_main(collector_sync_voip_t *sync) {

    int i, rc;
    sync_epoll_t *syncev, *tmp;
    int topoll_size = 2 + HASH_CNT(hh, sync->timeouts);

    if (sync->topoll_size < topoll_size) {
        free(sync->topoll);
        free(sync->expiring_streams);

        sync->topoll = calloc(topoll_size, sizeof(zmq_pollitem_t));
        sync->expiring_streams = calloc(topoll_size,
                sizeof(struct rtpstreaminf *));
        sync->topoll_size = topoll_size;
    }

    sync->topoll[0].socket = sync->zmq_colsock;
    sync->topoll[0].events = ZMQ_POLLIN;

    sync->topoll[1].socket = NULL;
    sync->topoll[1].fd = sync->intersync_fd;
    sync->topoll[1].events = ZMQ_POLLIN;

    i = 2;
    HASH_ITER(hh, sync->timeouts, syncev, tmp) {
        sync->topoll[i].socket = NULL;
        sync->topoll[i].fd = syncev->fd;
        sync->topoll[i].events = ZMQ_POLLIN;
        sync->expiring_streams[i] = (struct rtpstreaminf *)(syncev->ptr);
        i++;
    }

    rc = zmq_poll(sync->topoll, topoll_size, 50);

    if (rc < 0) {
        return rc;
    }

    for (i = 2; i < topoll_size; i++) {
        if (sync->topoll[i].revents & ZMQ_POLLIN) {
            halt_single_rtpstream(sync, sync->expiring_streams[i]);
        }
    }

    if (sync->topoll[1].revents & ZMQ_POLLIN) {
        process_intersync_msg(sync);
    }

    if (sync->topoll[0].revents & ZMQ_POLLIN) {
        if (process_colthread_message(sync) < 0) {
            return -1;
        }
    }

    return 1;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
