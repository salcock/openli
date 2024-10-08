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

#ifndef OPENLI_MEDIATOR_PROV_H_
#define OPENLI_MEDIATOR_PROV_H_

#include <inttypes.h>
#include "med_epoll.h"
#include "netcomms.h"
#include "openli_tls.h"

/** Global state for the mediator's connection to the provisioner */
typedef struct mediator_provisioner {

    /** Epoll event for the socket when the connection is active */
    med_epoll_ev_t *provev;

    /** Epoll timer event for attempting to reconnect to the provisioner
     *  when the connection has failed */
    med_epoll_ev_t *provreconnect;

    /** Netcomms buffer for sending messages to the provisioner */
    net_buffer_t *outgoing;

    /** Netcomms buffer for receiving messages from the provisioner */
    net_buffer_t *incoming;

    /** Flag indicating whether connection errors should be logged -- if true,
     *  logging is disabled.
     */
    uint8_t disable_log;

    /** Flag indicating if the mediator should attempt to connect to the
     *  provisioner at the next opportunity.
     */
    uint8_t tryconnect;

    /** Flag indicating if the provisioner connection has just been
     *  re-established, so that the mediator can let other threads
     *  know that the provisioner is back.
     */
    uint8_t just_connected;

    /** The SSL socket for the connection to the provisioner */
    SSL *ssl;

    /** The SSL context for this mediator instance */
    SSL_CTX **sslctxt;

    /** The global epoll fd for this mediator instance */
    int epoll_fd;

    /** If set to 1, the most recent connection attempt failed with an SSL
     *  error.
     */
    int lastsslerror;

    /** The IP address of the provisioner, derived from the config file */
    char *provaddr;

    /** The port number of the provisioner, derived from the config file */
    char *provport;
} mediator_prov_t;

/** Initialises the state for a provisioner instance
 *
 *  @param prov             The provisioner instance
 *  @param ctx              The SSL context object for the mediator
 */
void init_provisioner_instance(mediator_prov_t *prov, SSL_CTX **ctx);

/** Disconnects the TCP session to a provisioner and resets any state
 *  associated with that communication channel.
 *
 *  @param prov                 The provisioner instance to disconnect
 *  @param enable_reconnect     If not zero, we will set a timer to try and
 *                              reconnect to the provisioner in 1 second.
 */
void disconnect_provisioner(mediator_prov_t *prov, int enable_reconnect);

/** Releases all memory associated with a provisioner that this mediator
 *  was connected to.
 *
 *  @param prov         The provisioner to be released.
 */
void free_provisioner(mediator_prov_t *prov);

/** Sends any pending messages to the provisioner.
 *
 *  @param prov             The reference to the provisioner.
 *
 *  @return -1 if an error occurs, 1 otherwise.
 */
int transmit_provisioner(mediator_prov_t *prov);

/** Attempts to connect to the provisioner.
 *
 *  @param prov             The provisioner to connect to
 *  @param provfail         Set to 1 if the most recent connection attempt
 *                          failed, 0 otherwise.
 *
 *  @return 1 if the connection attempt fails for non-fatal reason, 0 if
 *            the attempt succeeded (or we were already connected), -1
 *            if the connection attempt failed for an unresolvable reason.
 */
int attempt_provisioner_connect(mediator_prov_t *prov, int provfail);

/** Sends the mediator details message to a connected provisioner.
 *  Mediator details include the port and IP that it is listening on for
 *  collector connections.
 *
 *  @param prov         The provisioner that is to receive the message.
 *  @param meddeets     The details to be included in the message.
 *  @param justcreated  A flag indicating whether the socket for the
 *                      provisioner connection has just been created.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int send_mediator_details_to_provisioner(mediator_prov_t *prov,
        openli_mediator_t *meddeets, int justcreated);

/** Applies any changes to the provisioner socket configuration following
 *  a user-triggered config reload.
 *
 *  @param currstate            The pre-reload provisioner state
 *  @param newstate             A provisioner instance containing the updated
 *                              configuration.
 *  @return 0 if the configuration is unchanged, 1 if it has changed.
 */
int reload_provisioner_socket_config(mediator_prov_t *currstate,
        mediator_prov_t *newstate);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
