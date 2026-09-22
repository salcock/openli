/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
 * research group. For further information about OpenLI, please see
 * https://openli.nz/
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

#ifndef OPENLI_COLLECTOR_CINSTATEDB_H_
#define OPENLI_COLLECTOR_CINSTATEDB_H_

#include "config.h"
#include <inttypes.h>

#if HAVE_SQLCIPHER
#include <sqlcipher/sqlite3.h>
typedef struct cinstate_db {
    sqlite3 *dbptr;
    sqlite3_stmt *update_stmt;
} openli_cinstatedb_t;
#else
typedef struct cinstate_db {
    void *dbptr;
    void *update_stmt;
} openli_cinstatedb_t;

#endif


struct cinstate_t {
    uint32_t iri_seqno;
    uint32_t cc_seqno;
};

uint8_t cinstate_db_connect(char *filepath, char *key, openli_cinstatedb_t *state);
void cinstate_db_close(openli_cinstatedb_t *dbptr);
void cinstate_db_lookup(openli_cinstatedb_t *dbptr, char *liid, uint32_t cin,
        struct cinstate_t *result);
int cinstate_db_update(openli_cinstatedb_t *dbptr, char *liid, uint32_t cin,
        struct cinstate_t *update);
int cinstate_db_remove_by_cin(openli_cinstatedb_t *dbptr, char *liid, uint32_t cin);
int cinstate_db_remove_by_liid(openli_cinstatedb_t *dbptr, char *liid);

#endif
