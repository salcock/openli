/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
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
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "logger.h"
#include "mirror_reassembly.h"

mirror_reassembler_t *mirror_reassembly_create(void) {
    mirror_reassembler_t *mr = NULL;
    size_t i;

    mr = calloc(1, sizeof(mirror_reassembler_t));

    for (i = 0; i < MIRROR_REASS_BUCKET_COUNT; i++) {
        pthread_mutex_init(&(mr->buckets[i].lock), NULL);
    }

    return mr;
}

static inline void clean_mirror_reassembly_slot(mirror_reass_slot_t *slot) {

    if (!slot) return;

    if (slot->dynamic_buf) free(slot->dynamic_buf);
    memset(slot, 0, sizeof(mirror_reass_slot_t));
}

static mirror_reass_slot_t *lookup_reass_slot(mirror_reass_bucket_t *bucket,
        mirror_reass_key_t *key, time_t tv_sec, uint16_t offset) {

    size_t i;
    size_t firstfree = MIRROR_REASS_BUCKET_SLOT_COUNT;
    size_t oldest = MIRROR_REASS_BUCKET_SLOT_COUNT;
    struct timeval oldest_ts = {0, 0};
    mirror_reass_slot_t *slot;

    for (i = 0; i < MIRROR_REASS_BUCKET_SLOT_COUNT; i++) {
        if (bucket->slots[i].in_use && bucket->slots[i].deadline < tv_sec) {
            clean_mirror_reassembly_slot(&(bucket->slots[i]));
        }

        if (bucket->slots[i].in_use && memcmp(key, &bucket->slots[i].key,
                    sizeof(mirror_reass_key_t)) == 0) {
            return &(bucket->slots[i]);
        }

        if (!bucket->slots[i].in_use) {
            if (firstfree == MIRROR_REASS_BUCKET_SLOT_COUNT) {
                firstfree = i;
            }
        } else {
            if (oldest_ts.tv_sec == 0 || oldest_ts.tv_sec >
                    bucket->slots[i].first_ts.tv_sec) {
                oldest_ts = bucket->slots[i].first_ts;
                oldest = i;
            }
        }

    }

    if (firstfree < MIRROR_REASS_BUCKET_SLOT_COUNT) {
        slot = &(bucket->slots[firstfree]);
        memcpy(&(slot->key), key, sizeof(mirror_reass_key_t));
        return slot;
    }

    /* All the slots are full, so let's expire the oldest one */
    /* But let's only do that if this is the first offset (i.e. likely
     * to be a genuine "new" fragmented packet), we don't want left over
     * trailing fragments to be able to force out in-progress reassemblies.
     */
    if (offset != 0) {
        return NULL;
    }

    slot = &(bucket->slots[oldest]);
    clean_mirror_reassembly_slot(slot);
    memcpy(&(slot->key), key, sizeof(mirror_reass_key_t));
    return slot;

}

void mirror_reassembly_destroy(mirror_reassembler_t *mr) {
    size_t i, j;

    if (!mr) return;

    for (i = 0; i < MIRROR_REASS_BUCKET_COUNT; i++) {
        for (j = 0; j < MIRROR_REASS_BUCKET_SLOT_COUNT; j++) {
            clean_mirror_reassembly_slot(&(mr->buckets[i].slots[j]));
        }

        pthread_mutex_destroy(&(mr->buckets[i].lock));
    }

    free(mr);
}

static void produce_reassembled(mirror_reass_slot_t *slot, uint8_t **out_udp,
        uint32_t *out_len, struct timeval *out_ts) {

    memcpy(out_ts, &slot->first_ts, sizeof(struct timeval));

    if (slot->dynamic_buf) {
        *out_udp = slot->dynamic_buf;
        slot->dynamic_buf = 0;
    } else {
        *out_udp = malloc(slot->expected_tlen);
        if (*out_udp != NULL) {
            memcpy(*out_udp, slot->static_buf, slot->expected_tlen);
        }
    }

    *out_len = slot->expected_tlen;

    clean_mirror_reassembly_slot(slot);
}

static int walk_segments(mirror_reass_slot_t *slot) {
    size_t i;
    uint16_t expected = 0;
    uint8_t used[MIRROR_REASS_MAX_SEGMENTS];
    uint8_t used_count = 0, lowest_ind;
    uint16_t lowest_unused = 0xFFFF;

    if (slot->expected_tlen == 0) {
        return 0;
    }

    memset(used, 0, sizeof(used));

    while (used_count < slot->seg_count) {
        lowest_unused = 0xFFFF;
        lowest_ind = 0xFF;

        for (i = 0; i < slot->seg_count; i++) {

            if (used[i]) {
                continue;
            }

            if (lowest_unused > slot->segments[i].offset) {
                lowest_unused = slot->segments[i].offset;
                lowest_ind = i;
            }
        }

        if (lowest_unused * 8 > expected) {
            return 0;
        }

        if (lowest_unused * 8 + slot->segments[lowest_ind].length <= expected) {
            used[lowest_ind] = 1;
            used_count ++;
        } else {
            expected = lowest_unused * 8 + slot->segments[lowest_ind].length;
            used[lowest_ind] = 1;
            used_count ++;
        }

        if (expected == slot->expected_tlen) {
            return 1;
        }

    }

    return 0;

}

static int update_reass_slot(mirror_reass_slot_t *slot, uint8_t *content,
        uint32_t rem, struct timeval ts, uint16_t offset) {

    uint8_t *writeptr = NULL;
    mirror_reass_seg_t *nextseg = NULL;
    size_t i;

    if (slot->first_ts.tv_sec == 0) {
        slot->first_ts = ts;
        slot->deadline = ts.tv_sec + 10;
    }

    if (offset == 0) {
        libtrace_udp_t *udp = (libtrace_udp_t *)content;
        uint16_t ulen = ntohs(udp->len);

        if (rem < sizeof(libtrace_udp_t) || ulen < sizeof(libtrace_udp_t)) {
            return -1;
        }
        if (rem > ulen) {
            rem = ulen;
        }

        slot->expected_tlen = ulen;
        if (slot->dynamic_buf) {
            slot->dynamic_buf = realloc(slot->dynamic_buf, slot->expected_tlen);
            if (!slot->dynamic_buf) {
                return -1;
            }
        } else if (slot->expected_tlen > 2048) {
            slot->dynamic_buf = malloc(slot->expected_tlen);
            if (!slot->dynamic_buf) {
                return -1;
            }
        }

        if (slot->seg_count > 0) {
            for (i = 0; i < slot->seg_count; i++) {
                uint32_t seg_start = (uint32_t)slot->segments[i].offset * 8;
                if (seg_start >= ulen) {
                    return -1;
                }
                if (seg_start + slot->segments[i].length > ulen) {
                    slot->segments[i].length = ulen - seg_start;
                }
            }
        }

    } else if (slot->expected_tlen == 0 && slot->dynamic_buf == NULL) {
        /* we haven't seen the first fragment yet, let's do some guess work */
        slot->dynamic_buf = malloc(MIRROR_REASS_PREALLOC_SIZE);
    }

    if (slot->expected_tlen > 0 && offset * 8 >= slot->expected_tlen) {
        logger(LOG_INFO, "OpenLI: received a UDP fragment that starts beyond the expected reassembled length -- ignoring");
        return -1;
    } else if (slot->expected_tlen > 0 &&
            offset * 8 + rem > slot->expected_tlen) {
        /* truncate to the original UDP length */
        logger(LOG_INFO, "OpenLI: received a UDP fragment that extends beyond the expected reassembled length -- truncating");
        rem = slot->expected_tlen - (offset * 8);

    } else if (slot->expected_tlen == 0 && offset * 8 >= MIRROR_REASS_PREALLOC_SIZE) {
        logger(LOG_INFO, "OpenLI: received a UDP fragment that starts beyond our pre-allocated buffer -- ignoring");
        return -1;
    } else if (slot->expected_tlen == 0 && offset * 8 + rem > MIRROR_REASS_PREALLOC_SIZE) {
        logger(LOG_INFO, "OpenLI: received a UDP fragment that extends beyond our pre-allocated buffer -- truncating");
        rem = MIRROR_REASS_PREALLOC_SIZE - (offset * 8);
    }

    if (slot->seg_count >= MIRROR_REASS_MAX_SEGMENTS) {
        logger(LOG_INFO, "OpenLI: cannot reassemble fragmented UDP due to there being too many fragments -- ignoring");
        return -1;
    }

    for (i = 0; i < slot->seg_count; i++) {
        if (slot->segments[i].offset == offset &&
                slot->segments[i].length == rem) {
            // duplicate fragment, can ignore
            return 0;
        }
    }

    nextseg = &(slot->segments[slot->seg_count]);
    nextseg->offset = offset;
    nextseg->length = rem;
    slot->seg_count ++;

    slot->received_bytes += rem;
    slot->in_use = 1;

    if (slot->dynamic_buf) {
        writeptr = slot->dynamic_buf + (offset * 8);
    } else {
        writeptr = slot->static_buf + (offset * 8);
    }
    memcpy(writeptr, content, rem);

    if (walk_segments(slot) == 1) {
        return 1;
    }

    return 0;
}

int mirror_reassembly_feed(mirror_reassembler_t *mr, const uint8_t *l3,
        uint32_t rem, uint32_t vlan_id, struct timeval ts, uint8_t **out_udp,
        uint32_t *out_len, struct timeval *out_ts) {

    libtrace_ip_t *as_ip;
    mirror_reass_key_t key;
    uint32_t bucketid;
    mirror_reass_bucket_t *bucket = NULL;
    mirror_reass_slot_t *slot = NULL;
    uint8_t *post_ip = NULL, proto = 0;
    int is_complete = 0;
    uint16_t offset = 0;
    uint32_t iplen;

    if (!mr) {
        return -1;
    }

    if (!l3 || rem < sizeof(libtrace_ip_t)) {
        return -1;
    }

    as_ip = (libtrace_ip_t *)l3;
    iplen = ntohs(as_ip->ip_len);

    if (rem < as_ip->ip_hl * 4 || as_ip->ip_v != 4 ||
            iplen < as_ip->ip_hl * 4 || rem < iplen || as_ip->ip_hl < 5) {
        return -1;
    }

    /* No need to byte swap as we don't care about the specific values for the
     * key lookup
     */
    memset(&key, 0, sizeof(key));
    key.context = vlan_id;
    key.src_addr = as_ip->ip_src.s_addr;
    key.dst_addr = as_ip->ip_dst.s_addr;
    key.ip_id = as_ip->ip_id;

    offset = (ntohs(as_ip->ip_off) & 0x1FFF);

    bucketid = (hashlittle(&key, sizeof(key), 6291469)) % \
            MIRROR_REASS_BUCKET_COUNT;
    bucket = &(mr->buckets[bucketid]);

    pthread_mutex_lock(&(bucket->lock));

    slot = lookup_reass_slot(bucket, &key, ts.tv_sec, offset);
    if (!slot) {
        pthread_mutex_unlock(&(bucket->lock));
        return -1;
    }

    post_ip = (uint8_t *)l3 + (as_ip->ip_hl * 4);
    rem = iplen - as_ip->ip_hl * 4;
    proto = as_ip->ip_p;

    if (proto != TRACE_IPPROTO_UDP ||
            (offset == 0 && rem < sizeof(libtrace_udp_t)) ||
            (offset > 0 && rem == 0)) {
        pthread_mutex_unlock(&(bucket->lock));
        return -1;
    }

    is_complete = update_reass_slot(slot, post_ip, rem, ts, offset);
    if (is_complete < 0) {
        clean_mirror_reassembly_slot(slot);
        pthread_mutex_unlock(&(bucket->lock));
        return -1;
    }

    if (is_complete) {
        produce_reassembled(slot, out_udp, out_len, out_ts);
    }

    pthread_mutex_unlock(&(bucket->lock));

    return is_complete;
}
