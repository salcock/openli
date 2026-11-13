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

#ifndef OPENLI_MIRROR_REASSEMBLY_H_
#define OPENLI_MIRROR_REASSEMBLY_H_

#define MIRROR_REASS_MAX_SEGMENTS 16
#define MIRROR_REASS_BUCKET_SLOT_COUNT 16
#define MIRROR_REASS_BUCKET_COUNT 256
#define MIRROR_REASS_PREALLOC_SIZE 9216

#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

typedef struct mirror_reass_key {
    uint32_t context;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t ip_id;
} mirror_reass_key_t;

typedef struct mirror_reass_segment {
    uint16_t offset;
    uint16_t length;
} mirror_reass_seg_t;

typedef struct mirror_reass_slot {
    mirror_reass_key_t key;
    struct timeval first_ts;
    time_t deadline;
    uint16_t expected_tlen;
    uint16_t received_bytes;
    uint8_t seg_count;
    uint8_t in_use;
    mirror_reass_seg_t segments[MIRROR_REASS_MAX_SEGMENTS];
    uint8_t static_buf[2048];
    uint8_t *dynamic_buf;
} mirror_reass_slot_t;


typedef struct mirror_reass_bucket {
    pthread_mutex_t lock;
    mirror_reass_slot_t slots[MIRROR_REASS_BUCKET_SLOT_COUNT];
} mirror_reass_bucket_t;

typedef struct mirror_reass_toplevel {
    mirror_reass_bucket_t buckets[MIRROR_REASS_BUCKET_COUNT];

} mirror_reassembler_t;

mirror_reassembler_t *mirror_reassembly_create(void);
void mirror_reassembly_destroy(mirror_reassembler_t *mr);
int mirror_reassembly_feed(mirror_reassembler_t *mr, const uint8_t *l3,
        uint32_t rem, uint32_t vlan_id, struct timeval ts, uint8_t **out_udp,
        uint32_t *out_len, struct timeval *out_ts);

#endif
