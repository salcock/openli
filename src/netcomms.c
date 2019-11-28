/*
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "netcomms.h"
#include "logger.h"
#include "byteswap.h"

#define DEBUG_DUMP 0

static inline void dump_buffer_contents(uint8_t *buf, uint16_t len) {

#if DEBUG_DUMP
    uint16_t i = 0;

    for (i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if (i % 16 == 15) {
            printf("\n");
        }
    }
#else
    (void)len;
#endif

}

net_buffer_t *create_net_buffer(net_buffer_type_t buftype, int fd, SSL *ssl) {

    net_buffer_t *nb = (net_buffer_t *)malloc(sizeof(net_buffer_t));
    nb->buf = (char *)malloc(NETBUF_ALLOC_SIZE);
    nb->appendptr = nb->buf;
    nb->actptr = nb->buf;
    nb->alloced = NETBUF_ALLOC_SIZE;
    nb->fd = fd;
    nb->buftype = buftype;
    nb->ssl = ssl;
    return nb;
}

void destroy_net_buffer(net_buffer_t *nb) {
    if (nb == NULL) {
        return;
    }
    free(nb->buf);
    free(nb);
}

inline int fd_set_nonblock(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

inline int fd_set_block(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static inline int extend_net_buffer(net_buffer_t *nb, int musthave) {

    int bufused = nb->alloced - NETBUF_SPACE_REM(nb);
    int frontfree = NETBUF_FRONT_FREE(nb);
    int contsize = NETBUF_CONTENT_SIZE(nb);
    char *tmp = NULL;

    if (frontfree >= 0.75 * nb->alloced) {
        memmove(nb->buf, nb->buf + frontfree, contsize);
        nb->actptr = nb->buf;
        nb->appendptr = nb->actptr + contsize;

        if (NETBUF_SPACE_REM(nb) >= musthave) {
            return 0;
        }
        frontfree = 0;
        bufused = nb->alloced - NETBUF_SPACE_REM(nb);
    }

    tmp = (char *)realloc(nb->buf, nb->alloced + NETBUF_ALLOC_SIZE);
    if (tmp == NULL) {
        /* OOM */
        return -1;
    }

    nb->buf = tmp;
    nb->alloced += NETBUF_ALLOC_SIZE;
    nb->actptr = nb->buf + frontfree;
    nb->appendptr = nb->actptr + contsize;

    return 0;

}

static int push_generic_onto_net_buffer(net_buffer_t *nb,
        uint8_t *data, uint16_t len) {

    if (len == 0) {
        return len;
    }

    while (NETBUF_SPACE_REM(nb) < len) {
        if (extend_net_buffer(nb, len) == -1) {
            return -1;
        }
    }

    memcpy(nb->appendptr, data, len);
    nb->appendptr += len;
    return len;
}

static inline void populate_header(ii_header_t *hdr,
        openli_proto_msgtype_t msgtype, uint16_t len, uint64_t intid) {

    hdr->magic = htonl(OPENLI_PROTO_MAGIC);
    hdr->bodylen = htons(len);
    hdr->intercepttype = htons((uint16_t)msgtype);
    hdr->internalid = bswap_host_to_be64(intid);
}

/* Quick and dirty method for constructing a netcomm protocol header
 * that can be used to push netcomm messages via sockets that are not
 * wrapped in a net buffer structure (e.g. collector->mediator sessions
 * which use the collector export API rather than net buffer, but will
 * use net buffer on the mediator side for receiving and decoding).
 */
int construct_netcomm_protocol_header(ii_header_t *newhdr,
        uint32_t contentlen,
        uint16_t msgtype, uint64_t internalid, uint32_t *hdrlen) {

    if (contentlen > 65535) {
        logger(LOG_INFO,
                "Content of size %u cannot fit in a single netcomm PDU.",
                contentlen);
        return -1;
    }

    populate_header(newhdr, (openli_proto_msgtype_t)msgtype,
            (uint16_t)contentlen, internalid);
    *hdrlen = sizeof(ii_header_t);
    return 0;

}

static inline int push_tlv(net_buffer_t *nb, openli_proto_fieldtype_t type,
        uint8_t *value, uint16_t vallen) {

    char tmp[4096];
    char *ptr = tmp;
    uint16_t shorttype, swaplen;

    if (vallen > 4096 - 4) {
        logger(LOG_INFO,
                "OpenLI: internal protocol does not support value fields larger than %u bytes.",
                4096 - 4);
        logger(LOG_INFO, "Supplied field was %u bytes.", vallen);
        return -1;
    }

    shorttype = htons((uint16_t)type);
    swaplen = htons(vallen);

    memcpy(ptr, &shorttype, sizeof(uint16_t));
    ptr += 2;
    memcpy(ptr, &swaplen, sizeof(uint16_t));
    ptr += 2;
    memcpy(ptr, value, vallen);

    return push_generic_onto_net_buffer(nb, tmp, vallen + 4);
}

int push_auth_onto_net_buffer(net_buffer_t *nb, openli_proto_msgtype_t msgtype)
{

    ii_header_t hdr;

    if (msgtype == OPENLI_PROTO_COLLECTOR_AUTH) {
        populate_header(&hdr, msgtype, 0, OPENLI_COLLECTOR_MAGIC);
    } else if (msgtype == OPENLI_PROTO_MEDIATOR_AUTH) {
        populate_header(&hdr, msgtype, 0, OPENLI_MEDIATOR_MAGIC);
    } else {
        logger(LOG_INFO, "OpenLI: invalid auth message type: %d.", msgtype);
        return -1;
    }

    return push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t));
}

int push_disconnect_mediators_onto_net_buffer(net_buffer_t *nb) {
    ii_header_t hdr;

    /* TODO maybe add some extra security to this? */
    populate_header(&hdr, OPENLI_PROTO_DISCONNECT_MEDIATORS, 0, 0);
    return push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t));
}


#define LIIDMAP_BODY_LEN(agency, liid) \
    (strlen(agency) + strlen(liid) + (2 * 4))

int push_liid_mapping_onto_net_buffer(net_buffer_t *nb, char *agency,
        char *liid) {

    ii_header_t hdr;
    uint16_t totallen;

    totallen = LIIDMAP_BODY_LEN(agency, liid);
    populate_header(&hdr, OPENLI_PROTO_MEDIATE_INTERCEPT, totallen, 0);

    if (push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LEAID, (uint8_t *)(agency),
                strlen(agency)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LIID, (uint8_t *)(liid),
                strlen(liid)) == -1) {
        return -1;
    }
    return (int)totallen;
}

int push_cease_mediation_onto_net_buffer(net_buffer_t *nb, char *liid,
        int liid_len) {
    ii_header_t hdr;
    uint16_t totallen;

    totallen = liid_len + 4;
    populate_header(&hdr, OPENLI_PROTO_CEASE_MEDIATION, totallen, 0);

    if (push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LIID, (uint8_t *)(liid),
                liid_len) == -1) {
        return -1;
    }
    return (int)totallen;
}

#define LEA_BODY_LEN(lea) \
    (strlen(lea->agencyid) + strlen(lea->hi2_ipstr) + \
    strlen(lea->hi2_portstr) + strlen(lea->hi3_ipstr) + \
    strlen(lea->hi3_portstr) + sizeof(uint32_t) + sizeof(uint32_t) + (7 * 4))

#define LEA_WITHDRAW_BODY_LEN(lea) \
    (strlen(lea->agencyid) + (1 * 4))

int push_lea_onto_net_buffer(net_buffer_t *nb, liagency_t *lea) {
    ii_header_t hdr;
    uint16_t totallen;

    totallen = LEA_BODY_LEN(lea);
    populate_header(&hdr, OPENLI_PROTO_ANNOUNCE_LEA, totallen, 0);
    if (push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LEAID, (uint8_t *)(lea->agencyid),
                strlen(lea->agencyid)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_HI2IP, (uint8_t *)(lea->hi2_ipstr),
                strlen(lea->hi2_ipstr)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_HI2PORT, (uint8_t *)(lea->hi2_portstr),
                strlen(lea->hi2_portstr)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_HI3IP, (uint8_t *)(lea->hi3_ipstr),
                strlen(lea->hi3_ipstr)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_HI3PORT, (uint8_t *)(lea->hi3_portstr),
                strlen(lea->hi3_portstr)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_KAFREQ,
                (uint8_t *)(&lea->keepalivefreq),
                sizeof(uint32_t)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_KAWAIT,
                (uint8_t *)(&lea->keepalivewait),
                sizeof(uint32_t)) == -1) {
        return -1;
    }
    return (int)totallen;

}

int push_lea_withdrawal_onto_net_buffer(net_buffer_t *nb, liagency_t *lea) {
    ii_header_t hdr;
    uint16_t totallen;

    totallen = LEA_WITHDRAW_BODY_LEN(lea);
    populate_header(&hdr, OPENLI_PROTO_WITHDRAW_LEA, totallen, 0);
    if (push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LEAID, (uint8_t *)(lea->agencyid),
                strlen(lea->agencyid)) == -1) {
        return -1;
    }
    return (int)totallen;
}

#define VENDMIRROR_IPINTERCEPT_MODIFY_BODY_LEN(ipint) \
        (ipint->common.liid_len + ipint->common.authcc_len + \
         ipint->username_len + sizeof(ipint->accesstype) + \
         sizeof(ipint->options) + \
         sizeof(ipint->vendmirrorid) + (6 * 4))

#define IPINTERCEPT_MODIFY_BODY_LEN(ipint) \
        (ipint->common.liid_len + ipint->common.authcc_len + \
         ipint->username_len + sizeof(ipint->accesstype) + \
         sizeof(ipint->options) + (5 * 4))

static int _push_ipintercept_modify(net_buffer_t *nb, ipintercept_t *ipint) {

    ii_header_t hdr;
    uint16_t totallen;
    int ret;

    /* Pre-compute our body length so we can write it in the header */
    if (ipint->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
        totallen = VENDMIRROR_IPINTERCEPT_MODIFY_BODY_LEN(ipint);
    } else {
        totallen = IPINTERCEPT_MODIFY_BODY_LEN(ipint);
    }
    if (totallen > 65535) {
        logger(LOG_INFO,
                "OpenLI: IP intercept modifcation is too long to fit in a single message (%d).",
                totallen);
        return -1;
    }

    /* Push on header */
    populate_header(&hdr, OPENLI_PROTO_MODIFY_IPINTERCEPT, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        goto pushmodfail;
    }

    /* Push on each intercept field */

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LIID, ipint->common.liid,
                strlen(ipint->common.liid)) == -1) {
        goto pushmodfail;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_AUTHCC, ipint->common.authcc,
            strlen(ipint->common.authcc)) == -1) {
        goto pushmodfail;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_USERNAME, ipint->username,
            ipint->username_len) == -1) {
        goto pushmodfail;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_ACCESSTYPE,
            (uint8_t *)(&(ipint->accesstype)),
            sizeof(ipint->accesstype)) == -1) {
        goto pushmodfail;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_INTOPTIONS,
            (uint8_t *)(&(ipint->options)),
            sizeof(ipint->options)) == -1) {
        goto pushmodfail;
    }

    if (ipint->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
        if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_VENDMIRRORID,
                (uint8_t *)(&ipint->vendmirrorid),
                sizeof(ipint->vendmirrorid))) == -1) {
            goto pushmodfail;
        }
    }

    return (int)totallen;

pushmodfail:
    logger(LOG_INFO,
            "OpenLI: unable to push IP intercept modify for %s to collector fd %d",
            ipint->common.liid, nb->fd);
    return -1;

}

#define VOIPINTERCEPT_MODIFY_BODY_LEN(vint) \
        (vint->common.liid_len + vint->common.authcc_len + \
         sizeof(vint->options) + (3 * 4))

static int _push_voipintercept_modify(net_buffer_t *nb, voipintercept_t *vint)
{
    ii_header_t hdr;
    uint16_t totallen;
    int ret;

    /* Pre-compute our body length so we can write it in the header */
    totallen = VOIPINTERCEPT_MODIFY_BODY_LEN(vint);
    if (totallen > 65535) {
        logger(LOG_INFO,
                "OpenLI: VOIP intercept modifcation is too long to fit in a single message (%d).",
                totallen);
        return -1;
    }


    /* Push on header */
    populate_header(&hdr, OPENLI_PROTO_MODIFY_VOIPINTERCEPT, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        goto pushmodfail;
    }

    /* Push on each intercept field */

    if (push_tlv(nb, OPENLI_PROTO_FIELD_INTOPTIONS,
            (uint8_t *)(&vint->options), sizeof(vint->options)) == -1) {
        goto pushmodfail;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LIID, vint->common.liid,
                strlen(vint->common.liid)) == -1) {
        goto pushmodfail;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_AUTHCC, vint->common.authcc,
            strlen(vint->common.authcc)) == -1) {
        goto pushmodfail;
    }


    return (int)totallen;

pushmodfail:
    logger(LOG_INFO,
            "OpenLI: unable to push VOIP intercept modify for %s to collector fd %d",
            vint->common.liid, nb->fd);
    return -1;
}

int push_intercept_modify_onto_net_buffer(net_buffer_t *nb, void *data,
        openli_proto_msgtype_t modtype) {

    if (modtype == OPENLI_PROTO_MODIFY_VOIPINTERCEPT) {
        return _push_voipintercept_modify(nb, (voipintercept_t *)data);
    } else if (modtype == OPENLI_PROTO_MODIFY_IPINTERCEPT) {
        return _push_ipintercept_modify(nb, (ipintercept_t *)data);
    }

    logger(LOG_INFO, "OpenLI: bad modtype in push_intercept_modify_onto_net_buffer: %d\n", modtype);
    return -1;
}

#define VOIPINTERCEPT_BODY_LEN(vint) \
        (vint->common.liid_len + vint->common.authcc_len + \
         vint->common.delivcc_len + strlen(vint->common.targetagency) + \
         sizeof(vint->common.destid) + sizeof(vint->options) \
         + (6 * 4))

#define INTERCEPT_WITHDRAW_BODY_LEN(liid, authcc) \
        (strlen(liid) + strlen(authcc) + (2 * 4))

int push_intercept_withdrawal_onto_net_buffer(net_buffer_t *nb,
        void *data, openli_proto_msgtype_t wdtype) {

    ii_header_t hdr;
    uint16_t totallen;
    int ret;
    char *liid, *authcc;
    voipintercept_t *vint = NULL;
    ipintercept_t *ipint =  NULL;

    if (wdtype == OPENLI_PROTO_HALT_VOIPINTERCEPT) {
        vint = (voipintercept_t *)data;
        liid = vint->common.liid;
        authcc = vint->common.authcc;
    } else if (wdtype == OPENLI_PROTO_HALT_IPINTERCEPT) {
        ipint = (ipintercept_t *)data;
        liid = ipint->common.liid;
        authcc = ipint->common.authcc;
    } else {
        logger(LOG_INFO,
                "OpenLI: invalid withdrawal type: %d\n", wdtype);
        return -1;
    }

    /* Pre-compute our body length so we can write it in the header */
    totallen = INTERCEPT_WITHDRAW_BODY_LEN(liid, authcc);
    if (totallen > 65535) {
        logger(LOG_INFO,
                "OpenLI: intercept withdrawal is too long to fit in a single message (%d).",
                totallen);
        return -1;
    }


    /* Push on header */
    populate_header(&hdr, wdtype, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        goto pushwdfail;
    }

    /* Push on each intercept field */

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LIID, liid, strlen(liid)) == -1) {
        goto pushwdfail;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_AUTHCC, authcc, strlen(authcc)) == -1) {
        goto pushwdfail;
    }

    return (int)totallen;

pushwdfail:
    logger(LOG_INFO,
            "OpenLI: unable to push intercept withdraw for %s to collector fd %d",
            liid, nb->fd);
    return -1;
}

int push_voipintercept_onto_net_buffer(net_buffer_t *nb, void *data) {

    ii_header_t hdr;
    uint16_t totallen;
    int ret;
    voipintercept_t *vint = (voipintercept_t *)data;

    /* Pre-compute our body length so we can write it in the header */
    if (VOIPINTERCEPT_BODY_LEN(vint) > 65535) {
        logger(LOG_INFO,
                "OpenLI: VOIP intercept announcement is too long to fit in a single message (%d).",
                VOIPINTERCEPT_BODY_LEN(vint));
        return -1;
    }

    totallen = VOIPINTERCEPT_BODY_LEN(vint);

    /* Push on header */
    populate_header(&hdr, OPENLI_PROTO_START_VOIPINTERCEPT, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        goto pushvoipintfail;
    }

    /* Push on each intercept field */
    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_LIID, vint->common.liid,
            vint->common.liid_len)) == -1) {
        goto pushvoipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_AUTHCC, vint->common.authcc,
            vint->common.authcc_len)) == -1) {
        goto pushvoipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_DELIVCC, vint->common.delivcc,
            vint->common.delivcc_len)) == -1) {
        goto pushvoipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_LEAID, vint->common.targetagency,
            strlen(vint->common.targetagency))) == -1) {
        goto pushvoipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORID,
            (uint8_t *)&(vint->common.destid),
            sizeof(vint->common.destid))) == -1) {
        goto pushvoipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_INTOPTIONS,
            (uint8_t *)&(vint->options), sizeof(vint->options))) == -1) {
        goto pushvoipintfail;
    }


    return (int)totallen;

pushvoipintfail:
    logger(LOG_INFO,
            "OpenLI: unable to push new VOIP intercept %s to collector fd %d",
            vint->common.liid, nb->fd);
    return -1;
}

#define SIPTARGET_BODY_LEN_NOREALM(sipid, vint) \
        (vint->common.liid_len + sipid->username_len + (2 * 4))

#define SIPTARGET_BODY_LEN(sipid, vint) \
        (vint->common.liid_len + sipid->username_len + sipid->realm_len \
        + (3 * 4))

static inline int push_sip_target_onto_net_buffer_generic(net_buffer_t *nb,
        openli_sip_identity_t *sipid, voipintercept_t *vint,
        openli_proto_msgtype_t msgtype) {

    uint16_t totallen;
    ii_header_t hdr;
    int ret;

    if (msgtype != OPENLI_PROTO_ANNOUNCE_SIP_TARGET &&
            msgtype != OPENLI_PROTO_WITHDRAW_SIP_TARGET) {
        logger(LOG_INFO,
                "OpenLI: push_sip_target_onto_net_buffer_generic() called with invalid message type: %d",
                msgtype);
        return -1;
    }

    if (sipid->realm) {
        totallen = SIPTARGET_BODY_LEN(sipid, vint);
    } else {
        totallen = SIPTARGET_BODY_LEN_NOREALM(sipid, vint);
    }

    if (totallen > 65535) {
        logger(LOG_INFO,
                "OpenLI: SIP target announcement is too long to fit in a single message (%d).",
                totallen);
        return -1;
    }

    /* Push on header */
    populate_header(&hdr, msgtype, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        goto pushsiptargetfail;
    }

    /* Push on each field */
    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_LIID, vint->common.liid,
            vint->common.liid_len)) == -1) {
        goto pushsiptargetfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_SIP_USER, sipid->username,
            sipid->username_len)) == -1) {
        goto pushsiptargetfail;
    }

    if (sipid->realm) {
        if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_SIP_REALM,
                sipid->realm, sipid->realm_len)) == -1) {
            goto pushsiptargetfail;
        }
    }

    /* Technically, we should also include authCC in here too for
     * multi-national operators but that can probably wait for now.
     */

    return (int)totallen;

pushsiptargetfail:
    if (sipid->realm) {
        logger(LOG_INFO,
                "OpenLI: unable to push new SIP target %s@%s to collector fd %d",
            sipid->username, sipid->realm, nb->fd);
    } else {
        logger(LOG_INFO,
                "OpenLI: unable to push new SIP target %s@* to collector fd %d",
            sipid->username, nb->fd);
    }
    return -1;
}

int push_sip_target_onto_net_buffer(net_buffer_t *nb,
        openli_sip_identity_t *sipid, voipintercept_t *vint) {

    return push_sip_target_onto_net_buffer_generic(nb, sipid, vint,
            OPENLI_PROTO_ANNOUNCE_SIP_TARGET);
}

int push_sip_target_withdrawal_onto_net_buffer(net_buffer_t *nb,
        openli_sip_identity_t *sipid, voipintercept_t *vint) {

    return push_sip_target_onto_net_buffer_generic(nb, sipid, vint,
            OPENLI_PROTO_WITHDRAW_SIP_TARGET);
}

#define STATICIP_RANGE_BODY_LEN(ipint, ipr) \
        (strlen(ipr->rangestr) + sizeof(ipr->cin) + \
        ipint->common.liid_len + (3 * 4))

static int push_static_ipranges_generic(net_buffer_t *nb, ipintercept_t *ipint,
        static_ipranges_t *ipr, openli_proto_msgtype_t msgtype) {

    ii_header_t hdr;
    int totallen;
    int ret;

    if (ipr == NULL) {
        return 0;
    }

    totallen = STATICIP_RANGE_BODY_LEN(ipint, ipr);
    if (totallen > 65535) {
        logger(LOG_INFO,
                "OpenLI: static IP range is too long to fit in a single message (%d).", totallen);
        return -1;
    }

    populate_header(&hdr, msgtype, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
                    sizeof(ii_header_t))) == -1) {
        goto pushstaticipfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_STATICIP_RANGE,
                    ipr->rangestr, strlen(ipr->rangestr))) == -1) {
        goto pushstaticipfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_LIID,
                    ipint->common.liid, ipint->common.liid_len)) == -1) {
        goto pushstaticipfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_CIN,
                    (uint8_t *)(&(ipr->cin)), sizeof(ipr->cin))) == -1) {
        goto pushstaticipfail;
    }

    return 0;

pushstaticipfail:
    logger(LOG_INFO,
            "OpenLI: unable to push static IP range to collector %d.", nb->fd);
    return -1;
}

int push_static_ipranges_removal_onto_net_buffer(net_buffer_t *nb,
        ipintercept_t *ipint, static_ipranges_t *ipr) {

    return push_static_ipranges_generic(nb, ipint, ipr,
            OPENLI_PROTO_REMOVE_STATICIPS);
}

int push_static_ipranges_modify_onto_net_buffer(net_buffer_t *nb,
        ipintercept_t *ipint, static_ipranges_t *ipr) {

    return push_static_ipranges_generic(nb, ipint, ipr,
            OPENLI_PROTO_MODIFY_STATICIPS);
}

int push_static_ipranges_onto_net_buffer(net_buffer_t *nb,
        ipintercept_t *ipint, static_ipranges_t *ipr) {

    return push_static_ipranges_generic(nb, ipint, ipr,
            OPENLI_PROTO_ADD_STATICIPS);
}

#define IPINTERCEPT_BODY_LEN(ipint) \
        (ipint->common.liid_len + ipint->common.authcc_len + \
         ipint->common.delivcc_len + \
         ipint->username_len + sizeof(ipint->common.destid) + \
         strlen(ipint->common.targetagency) + \
         sizeof(ipint->options) + \
         sizeof(ipint->accesstype) + (8 * 4))

#define VENDMIRROR_IPINTERCEPT_BODY_LEN(ipint) \
        (ipint->common.liid_len + ipint->common.authcc_len + \
         ipint->common.delivcc_len + ipint->username_len + \
         strlen(ipint->common.targetagency) + \
         sizeof(ipint->vendmirrorid) + sizeof(ipint->common.destid) + \
         sizeof(ipint->options) + \
         sizeof(ipint->accesstype) + (9 * 4))

int push_ipintercept_onto_net_buffer(net_buffer_t *nb, void *data) {

    /* Pre-compute our body length so we can write it in the header */
    ii_header_t hdr;
    int totallen;
    int ret;
    ipintercept_t *ipint = (ipintercept_t *)data;
    static_ipranges_t *ipr, *tmpr;

    if (ipint->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
        totallen = VENDMIRROR_IPINTERCEPT_BODY_LEN(ipint);
    } else {
        totallen = IPINTERCEPT_BODY_LEN(ipint);
    }

    if (totallen > 65535) {
        logger(LOG_INFO,
                "OpenLI: intercept announcement is too long to fit in a single message (%d).",
                totallen);
        return -1;
    }


    /* Push on header */
    populate_header(&hdr, OPENLI_PROTO_START_IPINTERCEPT, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        goto pushipintfail;
    }

    /* Push on each intercept field */
    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_LIID, ipint->common.liid,
            ipint->common.liid_len)) == -1) {
        goto pushipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_AUTHCC, ipint->common.authcc,
            ipint->common.authcc_len)) == -1) {
        goto pushipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_DELIVCC, ipint->common.delivcc,
            ipint->common.delivcc_len)) == -1) {
        goto pushipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_USERNAME, ipint->username,
            ipint->username_len)) == -1) {
        goto pushipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_LEAID,
            ipint->common.targetagency,
            strlen(ipint->common.targetagency))) == -1) {
        goto pushipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_ACCESSTYPE,
            (uint8_t *)(&ipint->accesstype),
            sizeof(ipint->accesstype))) == -1) {
        goto pushipintfail;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_INTOPTIONS,
            (uint8_t *)(&ipint->options),
            sizeof(ipint->options))) == -1) {
        goto pushipintfail;
    }

    if (ipint->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
        if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_VENDMIRRORID,
                (uint8_t *)(&ipint->vendmirrorid),
                sizeof(ipint->vendmirrorid))) == -1) {
            goto pushipintfail;
        }
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORID,
            (uint8_t *)&(ipint->common.destid),
            sizeof(ipint->common.destid))) == -1) {
        goto pushipintfail;
    }

    HASH_ITER(hh, ipint->statics, ipr, tmpr) {
        if (push_static_ipranges_onto_net_buffer(nb, ipint, ipr) < 0) {
            return -1;
        }
    }

    return (int)totallen;

pushipintfail:
    logger(LOG_INFO,
            "OpenLI: unable to push new IP intercept %s to collector fd %d",
            ipint->common.liid, nb->fd);
    return -1;
}

#define MEDIATOR_BODY_LEN(med) \
    (sizeof(med->mediatorid) + strlen(med->ipstr) + strlen(med->portstr) \
     + (3 * 4))

static inline int push_mediator_msg_onto_net_buffer(net_buffer_t *nb,
        openli_mediator_t *med, openli_proto_msgtype_t type) {

    ii_header_t hdr;
    uint16_t totallen;
    int ret;

    /* Pre-compute our body length so we can write it in the header */
    if (MEDIATOR_BODY_LEN(med) > 65535) {
        logger(LOG_INFO,
                "OpenLI: mediator announcement is too long to fit in a single message (%d).",
                MEDIATOR_BODY_LEN(med));
        return -1;
    }

    totallen = MEDIATOR_BODY_LEN(med);

    /* Push on header */
    populate_header(&hdr, type, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        return -1;
    }

    /* Push on each mediator field */
    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORID,
            (uint8_t *)&(med->mediatorid), sizeof(med->mediatorid))) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORIP, med->ipstr,
            strlen(med->ipstr))) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORPORT, med->portstr,
            strlen(med->portstr))) == -1) {
        return -1;
    }

    return (int)totallen;
}

int push_mediator_onto_net_buffer(net_buffer_t *nb, openli_mediator_t *med) {

    return push_mediator_msg_onto_net_buffer(nb, med,
            OPENLI_PROTO_ANNOUNCE_MEDIATOR);
}

int push_mediator_withdraw_onto_net_buffer(net_buffer_t *nb,
        openli_mediator_t *med) {

    return push_mediator_msg_onto_net_buffer(nb, med,
            OPENLI_PROTO_WITHDRAW_MEDIATOR);
}

#define CORESERVER_BODY_LEN(cs) \
    (sizeof(uint8_t) + strlen(cs->ipstr) + \
    (cs->portstr ? (strlen(cs->portstr) + (3 * 4)) : (2 * 4)))

static int push_coreserver_msg_onto_net_buffer(net_buffer_t *nb,
        coreserver_t *cs, uint8_t cstype, openli_proto_msgtype_t type) {

    ii_header_t hdr;
    uint16_t totallen;
    int ret;

    /* Pre-compute our body length so we can write it in the header */
    totallen = CORESERVER_BODY_LEN(cs);
    if (totallen > 65535) {
        logger(LOG_INFO,
                "OpenLI: %s server announcement is too long to fit in a single message (%d).",
                coreserver_type_to_string(cstype), totallen);
        return -1;
    }

    /* Push on header */
    populate_header(&hdr, type, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        return -1;
    }

    /* Push on each field */
    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_CORESERVER_TYPE,
            (uint8_t *)&(cstype), sizeof(cstype))) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_CORESERVER_IP, cs->ipstr,
            strlen(cs->ipstr))) == -1) {
        return -1;
    }

    if (cs->portstr) {
        if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_CORESERVER_PORT, cs->portstr,
                strlen(cs->portstr))) == -1) {
            return -1;
        }
    }

    return (int)totallen;
}

int push_coreserver_onto_net_buffer(net_buffer_t *nb, coreserver_t *cs,
        uint8_t cstype) {

    return push_coreserver_msg_onto_net_buffer(nb, cs, cstype,
            OPENLI_PROTO_ANNOUNCE_CORESERVER);
}

int push_coreserver_withdraw_onto_net_buffer(net_buffer_t *nb, coreserver_t *cs,
        uint8_t cstype) {

    return push_coreserver_msg_onto_net_buffer(nb, cs, cstype,
            OPENLI_PROTO_WITHDRAW_CORESERVER);
}

int push_nomore_intercepts(net_buffer_t *nb) {
    ii_header_t hdr;
    populate_header(&hdr, OPENLI_PROTO_NOMORE_INTERCEPTS, 0, 0);

    return push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t));
}

int transmit_net_buffer(net_buffer_t *nb, openli_proto_msgtype_t *err) {
    int ret;

    if (nb == NULL) {
        *err = OPENLI_PROTO_NULL_BUFFER;
        return -1;
    }

    if (nb->buftype != NETBUF_SEND) {
        *err = OPENLI_PROTO_WRONG_BUFFER_TYPE;
        return -1;
    }

    if (NETBUF_CONTENT_SIZE(nb) == 0) {
        return 0;
    }

    //dump_buffer_contents(nb->actptr, NETBUF_CONTENT_SIZE(nb));

    if (nb->ssl != NULL){
        ret = SSL_write(nb->ssl, nb->actptr, NETBUF_CONTENT_SIZE(nb));
    }
    else {
        ret = send(nb->fd, nb->actptr, NETBUF_CONTENT_SIZE(nb), MSG_DONTWAIT);
    }

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Socket not available right now... */
            return 1;
        }
        *err = OPENLI_PROTO_SEND_ERROR;
        return -1;
    }


    nb->actptr += ret;

    /* If we've got a lot of unused space at the front of the buffer,
     * reclaim it by moving our content back to the front.
     */
    if (NETBUF_FRONT_FREE(nb) > NETBUF_ALLOC_SIZE) {
        int consize = NETBUF_CONTENT_SIZE(nb);

        if (consize > 0) {
            memmove(nb->buf, nb->actptr, consize);
        }
        nb->actptr = nb->buf;
        nb->appendptr = nb->actptr + consize;

        /* TODO consider shrinking the buffer if alloced > 10 allocations
         * and consize < 0.3 * alloced.
         */
    }

    return NETBUF_CONTENT_SIZE(nb);
}

static openli_proto_msgtype_t parse_received_message(net_buffer_t *nb,
        uint8_t **msgbody, uint16_t *msglen, uint64_t *intid) {

    ii_header_t *hdr;
    openli_proto_msgtype_t rettype;

    if (NETBUF_CONTENT_SIZE(nb) < sizeof(ii_header_t)) {
        return OPENLI_PROTO_NO_MESSAGE;
    }

    hdr = (ii_header_t *)(nb->actptr);

    if (ntohl(hdr->magic) != OPENLI_PROTO_MAGIC) {
        dump_buffer_contents(nb->actptr, 64);
        return OPENLI_PROTO_INVALID_MESSAGE;
    }

    if (NETBUF_CONTENT_SIZE(nb) < sizeof(ii_header_t) + ntohs(hdr->bodylen)) {
        return OPENLI_PROTO_NO_MESSAGE;
    }

    /* Got a complete message */
    *msgbody = ((uint8_t *)(nb->actptr)) + sizeof(ii_header_t);
    *msglen = ntohs(hdr->bodylen);
    *intid = bswap_be_to_host64(hdr->internalid);
    rettype = ntohs(hdr->intercepttype);

    nb->actptr += ((*msglen) + sizeof(ii_header_t));

    return rettype;
}

static int decode_tlv(uint8_t *start, uint8_t *end,
        openli_proto_fieldtype_t *t, uint16_t *l, uint8_t **v) {

    uint16_t t16 = ntohs(*(uint16_t *)start);
    *t = t16;

    start += 2;
    if (start >= end) {
        logger(LOG_INFO, "OpenLI: truncated TLV.");
        return -1;
    }

    *l = ntohs(*((uint16_t *)start));
    start += 2;
    if (start >= end) {
        logger(LOG_INFO, "OpenLI: truncated TLV.");
        return -1;
    }

    if (start + *l > end) {
        logger(LOG_INFO, "OpenLI: truncated TLV -- value is %u bytes, length field says %u\n",
                end - start, *l);
        return -1;
    }

    *v = start;
    return 0;
}

#define DECODE_STRING_FIELD(target, valptr, vallen) \
    target = (char *)malloc(vallen + 1); \
    memcpy(target, valptr, vallen); \
    (target)[vallen] = '\0';

int decode_voipintercept_start(uint8_t *msgbody, uint16_t len,
        voipintercept_t *vint) {

    uint8_t *msgend = msgbody + len;

    vint->internalid = 0;
    vint->common.liid = NULL;
    vint->common.authcc = NULL;
    vint->common.delivcc = NULL;
    vint->active_cins = NULL;  /* Placeholder -- sync thread should populate */
    vint->active_registrations = NULL;  /* Placeholder */
    vint->cin_callid_map = NULL;
    vint->cin_sdp_map = NULL;
    vint->targets = libtrace_list_init(sizeof(openli_sip_identity_t *));
    vint->common.destid = 0;
    vint->common.targetagency = NULL;
    vint->active = 1;
    vint->awaitingconfirm = 0;
    vint->options = 0;

    vint->common.liid_len = 0;
    vint->common.authcc_len = 0;
    vint->common.delivcc_len = 0;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_MEDIATORID) {
            vint->common.destid = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_INTOPTIONS) {
            vint->options = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_LIID) {
            DECODE_STRING_FIELD(vint->common.liid, valptr, vallen);
            vint->common.liid_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_AUTHCC) {
            DECODE_STRING_FIELD(vint->common.authcc, valptr, vallen);
            vint->common.authcc_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_LEAID) {
            DECODE_STRING_FIELD(vint->common.targetagency, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_DELIVCC) {
            DECODE_STRING_FIELD(vint->common.delivcc, valptr, vallen);
            vint->common.delivcc_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_INTERCEPTID) {
            vint->internalid = *((uint64_t *)valptr);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_INFO,
                "OpenLI: invalid field in received VOIP intercept: %d.", f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}

int decode_voipintercept_halt(uint8_t *msgbody, uint16_t len,
        voipintercept_t *vint) {
    return decode_voipintercept_start(msgbody, len, vint);
}

int decode_voipintercept_modify(uint8_t *msgbody, uint16_t len,
        voipintercept_t *vint) {
    return decode_voipintercept_start(msgbody, len, vint);
}

int decode_ipintercept_halt(uint8_t *msgbody, uint16_t len,
        ipintercept_t *ipint) {
    return decode_ipintercept_start(msgbody, len, ipint);
}

int decode_ipintercept_modify(uint8_t *msgbody, uint16_t len,
        ipintercept_t *ipint) {
    return decode_ipintercept_start(msgbody, len, ipint);
}

int decode_ipintercept_start(uint8_t *msgbody, uint16_t len,
        ipintercept_t *ipint) {

    uint8_t *msgend = msgbody + len;

    ipint->common.liid = NULL;
    ipint->common.authcc = NULL;
    ipint->common.delivcc = NULL;
    ipint->username = NULL;
    ipint->common.destid = 0;
    ipint->common.targetagency = NULL;
    ipint->awaitingconfirm = 0;
    ipint->vendmirrorid = OPENLI_VENDOR_MIRROR_NONE;
    ipint->accesstype = INTERNET_ACCESS_TYPE_UNDEFINED;
    ipint->statics = NULL;
    ipint->options = 0;

    ipint->common.liid_len = 0;
    ipint->common.authcc_len = 0;
    ipint->common.delivcc_len = 0;
    ipint->username_len = 0;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_MEDIATORID) {
            ipint->common.destid = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_VENDMIRRORID) {
            ipint->vendmirrorid = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_ACCESSTYPE) {
            ipint->accesstype = *((internet_access_method_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_LIID) {
            DECODE_STRING_FIELD(ipint->common.liid, valptr, vallen);
            ipint->common.liid_len = vallen;
            ipint->common.seqtrackerid = 0;
        } else if (f == OPENLI_PROTO_FIELD_AUTHCC) {
            DECODE_STRING_FIELD(ipint->common.authcc, valptr, vallen);
            ipint->common.authcc_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_DELIVCC) {
            DECODE_STRING_FIELD(ipint->common.delivcc, valptr, vallen);
            ipint->common.delivcc_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_LEAID) {
            DECODE_STRING_FIELD(ipint->common.targetagency, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_INTOPTIONS) {
            ipint->options = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_USERNAME) {
            DECODE_STRING_FIELD(ipint->username, valptr, vallen);
            if (vallen == 0) {
                free(ipint->username);
                ipint->username = NULL;
            }
            ipint->username_len = vallen;
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_INFO,
                "OpenLI: invalid field in received IP intercept: %d.", f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;

}

int decode_mediator_announcement(uint8_t *msgbody, uint16_t len,
        openli_mediator_t *med) {

    uint8_t *msgend = msgbody + len;

    med->ipstr = NULL;
    med->portstr = NULL;
    med->mediatorid = 0;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_MEDIATORID) {
            med->mediatorid = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_MEDIATORIP) {
            DECODE_STRING_FIELD(med->ipstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_MEDIATORPORT) {
            DECODE_STRING_FIELD(med->portstr, valptr, vallen);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_INFO,
                "OpenLI: invalid field in received mediator announcement: %d.",
                f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}

int decode_mediator_withdraw(uint8_t *msgbody, uint16_t len,
        openli_mediator_t *med) {

    return decode_mediator_announcement(msgbody, len, med);
}

int decode_sip_target_announcement(uint8_t *msgbody, uint16_t len,
        openli_sip_identity_t *sipid, char *liidspace, int spacelen) {

    uint8_t *msgend = msgbody + len;
    sipid->realm = NULL;
    sipid->realm_len = 0;
    sipid->username = NULL;
    sipid->username_len = 0;
    sipid->awaitingconfirm = 0;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_SIP_USER) {
            DECODE_STRING_FIELD(sipid->username, valptr, vallen);
            sipid->username_len = strlen(sipid->username);
        } else if (f == OPENLI_PROTO_FIELD_SIP_REALM) {
            DECODE_STRING_FIELD(sipid->realm, valptr, vallen);
            sipid->realm_len = strlen(sipid->realm);
        } else if (f == OPENLI_PROTO_FIELD_LIID) {
            if (vallen >= spacelen) {
                logger(LOG_INFO,
                        "OpenLI: not enough space to save LIID from SIP target message -- space provided %d, required %u\n", spacelen, vallen);
                return -1;
            }
            strncpy(liidspace, (char *)valptr, vallen);
            liidspace[vallen] = '\0';
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_INFO,
                "OpenLI: invalid field in received core server announcement: %d.",
                f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    if (sipid->username == NULL) {
        logger(LOG_INFO,
                "OpenLI: received a SIP target message with no username?");
        return -1;
    }
    return 0;
}

int decode_sip_target_withdraw(uint8_t *msgbody, uint16_t len,
        openli_sip_identity_t *sipid, char *liidspace, int spacelen) {

    return decode_sip_target_announcement(msgbody, len, sipid, liidspace,
            spacelen);
}

int decode_coreserver_announcement(uint8_t *msgbody, uint16_t len,
        coreserver_t *cs) {
    uint8_t *msgend = msgbody + len;

    cs->servertype = OPENLI_CORE_SERVER_UNKNOWN;
    cs->ipstr = NULL;
    cs->portstr = NULL;
    cs->info = NULL;
    cs->awaitingconfirm = 0;
    cs->serverkey = NULL;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_CORESERVER_TYPE) {
            cs->servertype = *((uint8_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_CORESERVER_IP) {
            DECODE_STRING_FIELD(cs->ipstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_CORESERVER_PORT) {
            DECODE_STRING_FIELD(cs->portstr, valptr, vallen);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_INFO,
                "OpenLI: invalid field in received core server announcement: %d.",
                f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    construct_coreserver_key(cs);
    if (cs->serverkey == NULL) {
        logger(LOG_INFO,
                "OpenLI: core server announcement is missing an IP address");
        return -1;
    }

    return 0;
}

int decode_coreserver_withdraw(uint8_t *msgbody, uint16_t len,
        coreserver_t *cs) {
    return decode_coreserver_announcement(msgbody, len, cs);
}

int decode_staticip_announcement(uint8_t *msgbody, uint16_t len,
        static_ipranges_t *ipr) {

    uint8_t *msgend = msgbody + len;
    ipr->rangestr = NULL;
    ipr->awaitingconfirm = 0;
    ipr->liid = NULL;
    ipr->cin = 1;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }
        if (f == OPENLI_PROTO_FIELD_LIID) {
            DECODE_STRING_FIELD(ipr->liid, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_STATICIP_RANGE) {
            DECODE_STRING_FIELD(ipr->rangestr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_CIN) {
            ipr->cin = *((uint32_t *)valptr);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_INFO,
                "OpenLI: invalid field in received LEA announcement: %d.",
                f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;

}

int decode_staticip_removal(uint8_t *msgbody, uint16_t len,
        static_ipranges_t *ipr) {
    return decode_staticip_announcement(msgbody, len, ipr);
}

int decode_staticip_modify(uint8_t *msgbody, uint16_t len,
        static_ipranges_t *ipr) {
    return decode_staticip_announcement(msgbody, len, ipr);
}

int decode_lea_announcement(uint8_t *msgbody, uint16_t len, liagency_t *lea) {

    uint8_t *msgend = msgbody + len;

    lea->hi2_ipstr = NULL;
    lea->hi2_portstr = NULL;
    lea->hi3_ipstr = NULL;
    lea->hi3_portstr = NULL;
    lea->agencyid = NULL;
    lea->keepalivefreq = 300;
    lea->keepalivewait = 0;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_LEAID) {
            DECODE_STRING_FIELD(lea->agencyid, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_HI2IP) {
            DECODE_STRING_FIELD(lea->hi2_ipstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_HI2PORT) {
            DECODE_STRING_FIELD(lea->hi2_portstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_HI3IP) {
            DECODE_STRING_FIELD(lea->hi3_ipstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_HI3PORT) {
            DECODE_STRING_FIELD(lea->hi3_portstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_KAFREQ) {
            lea->keepalivefreq = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_KAWAIT) {
            lea->keepalivewait = *((uint32_t *)valptr);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_INFO,
                "OpenLI: invalid field in received LEA announcement: %d.",
                f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}

int decode_lea_withdrawal(uint8_t *msgbody, uint16_t len, liagency_t *lea) {
    return decode_lea_announcement(msgbody, len, lea);
}

int decode_liid_mapping(uint8_t *msgbody, uint16_t len, char **agency,
        char **liid) {

    uint8_t *msgend = msgbody + len;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_LIID) {
            DECODE_STRING_FIELD(*liid, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_LEAID) {
            DECODE_STRING_FIELD(*agency, valptr, vallen);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_INFO,
                    "OpenLI: invalid field in received LIID mapping: %d.",
                    f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}

int decode_cease_mediation(uint8_t *msgbody, uint16_t len, char **liid) {
    uint8_t *msgend = msgbody + len;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_LIID) {
            DECODE_STRING_FIELD(*liid, valptr, vallen);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_INFO,
                    "OpenLI: invalid field in received cease mediation: %d.",
                    f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}


openli_proto_msgtype_t receive_net_buffer(net_buffer_t *nb, uint8_t **msgbody,
        uint16_t *msglen, uint64_t *intid) {

    ii_header_t *hdr;
    openli_proto_msgtype_t rettype;
    int ret;

    if (nb == NULL) {
        return OPENLI_PROTO_NULL_BUFFER;
    }

    if (nb->buftype != NETBUF_RECV) {
        return OPENLI_PROTO_WRONG_BUFFER_TYPE;
    }

    rettype = parse_received_message(nb, msgbody, msglen, intid);
    if (rettype != OPENLI_PROTO_NO_MESSAGE) {
        return rettype;
    }

    /* Not enough data in the buffer for a complete message, read some more. */
    if (NETBUF_SPACE_REM(nb) < NETBUF_ALLOC_SIZE) {
        if (extend_net_buffer(nb, NETBUF_ALLOC_SIZE) == -1) {
            return OPENLI_PROTO_BUFFER_TOO_FULL;
        }
    }

    if (nb->ssl != NULL){
        ret = SSL_read(nb->ssl, nb->appendptr, NETBUF_SPACE_REM(nb));
    }
    else {
        ret = recv(nb->fd, nb->appendptr, NETBUF_SPACE_REM(nb), MSG_DONTWAIT);
    }
    
    if (ret <= 0) {
        if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return OPENLI_PROTO_NO_MESSAGE;
        }
        if (ret == 0) {
            /* Other end disconnected */
            return OPENLI_PROTO_PEER_DISCONNECTED;
        }
        return OPENLI_PROTO_RECV_ERROR;
    }

    nb->appendptr += ret;

    rettype = parse_received_message(nb, msgbody, msglen, intid);
    return rettype;
}

void nb_log_transmit_error(openli_proto_msgtype_t err) {
    switch(err) {
        case OPENLI_PROTO_NULL_BUFFER:
            logger(LOG_INFO,
                    "OpenLI: attempted to transmit using a NULL buffer.");
            break;
        case OPENLI_PROTO_WRONG_BUFFER_TYPE:
            logger(LOG_INFO,
                    "OpenLI: attempted to transmit using a receive buffer.");
            break;
        case OPENLI_PROTO_SEND_ERROR:
            logger(LOG_INFO,
                    "OpenLI: error while transmitting data from net buffer: %s",
                    strerror(errno));
            break;
        case OPENLI_PROTO_PEER_DISCONNECTED:
            logger(LOG_INFO,
                    "OpenLI: remote peer disconnected while sending protocol message.");
            break;
        default:
            logger(LOG_DEBUG,
                    "OpenLI: unrecognised transmit net buffer error %d.", err);
            break;
    }

}

void nb_log_receive_error(openli_proto_msgtype_t err) {

    switch(err) {
        case OPENLI_PROTO_NULL_BUFFER:
            logger(LOG_INFO,
                    "OpenLI: attempted to receive using a NULL buffer.");
            break;
        case OPENLI_PROTO_WRONG_BUFFER_TYPE:
            logger(LOG_INFO,
                    "OpenLI: attempted to receive using a transmit buffer.");
            break;
        case OPENLI_PROTO_RECV_ERROR:
            logger(LOG_INFO,
                    "OpenLI: error while receiving data into net buffer: %s",
                    strerror(errno));
            break;
        case OPENLI_PROTO_BUFFER_TOO_FULL:
            logger(LOG_INFO,
                    "OpenLI: unable to allocate larger net buffer.");
            break;
        case OPENLI_PROTO_PEER_DISCONNECTED:
            logger(LOG_INFO,
                    "OpenLI: remote peer disconnected while receiving protocol message.");
            break;
        case OPENLI_PROTO_INVALID_MESSAGE:
            logger(LOG_INFO,
                    "OpenLI: received invalid protocol message.");
            break;
        default:
            logger(LOG_DEBUG,
                    "OpenLI: unrecognised receive net buffer error %d.", err);
            break;
    }

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
