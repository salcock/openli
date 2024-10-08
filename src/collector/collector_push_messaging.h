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

#ifndef OPENLI_COLLECTOR_PUSH_MESSAGING_H_
#define OPENLI_COLLECTOR_PUSH_MESSAGING_H_

#include "collector.h"
#include "intercept.h"


void handle_push_mirror_intercept(colthread_local_t *loc,
        vendmirror_intercept_t *vmi);
void handle_halt_mirror_intercept(colthread_local_t *loc,
        vendmirror_intercept_t *vmi);
void handle_push_ipintercept(colthread_local_t *loc,
        ipsession_t *sess);
void handle_push_ipmmintercept(colthread_local_t *loc,
        rtpstreaminf_t *rtp);
void handle_halt_ipmmintercept(colthread_local_t *loc,
        char *streamkey);
void handle_halt_ipintercept(colthread_local_t *loc,
        ipsession_t *sess);
void handle_push_coreserver(colthread_local_t *loc,
        coreserver_t *cs);
void handle_remove_coreserver(colthread_local_t *loc,
        coreserver_t *cs);
void handle_iprange(colthread_local_t *loc,
        staticipsession_t *ipr);
void handle_remove_iprange(colthread_local_t *loc,
        staticipsession_t *ipr);
void handle_modify_iprange(colthread_local_t *loc,
        staticipsession_t *ipr);
void handle_change_voip_intercept(colthread_local_t *loc,
        rtpstreaminf_t *tochange);
void handle_change_vendmirror_intercept(colthread_local_t *loc,
        vendmirror_intercept_t *vend);
void handle_change_iprange_intercept(colthread_local_t *loc,
        staticipsession_t *ipr);
void handle_change_ipint_intercept(colthread_local_t *loc, ipsession_t *sess);
#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
