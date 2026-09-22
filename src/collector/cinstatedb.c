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
#define _GNU_SOURCE

#include "config.h"
#include "logger.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "cinstatedb.h"

#if HAVE_SQLCIPHER
#include <sqlcipher/sqlite3.h>
#endif

const char *select_cinstate_sql =
        "SELECT iriseqno, ccseqno FROM cinstate WHERE "
        "liid = ? AND cin = ?;";

const char *update_cinstate_sql =
        "INSERT INTO cinstate (liid, cin, iriseqno, ccseqno) "
        " VALUES (?, ?, ?, ?) ON CONFLICT (liid, cin) DO "
        "UPDATE SET iriseqno=excluded.iriseqno, ccseqno=excluded.ccseqno; ";

const char *remove_cinstate_liid_sql =
        "DELETE FROM cinstate WHERE liid = ?;";

const char *remove_cinstate_cin_sql =
        "DELETE FROM cinstate WHERE liid = ? AND cin = ?;";

uint8_t cinstate_db_connect(char *filepath, char *key,
        openli_cinstatedb_t *state) {
    int rc;

    if (state == NULL || filepath == NULL || key == NULL) {
        return 0;
    }

    state->dbptr = NULL;
    state->update_stmt = NULL;
#if HAVE_SQLCIPHER
    rc = sqlite3_open(filepath, (sqlite3 **)(&state->dbptr));
    if (rc != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: failed to open CIN state tracking database at %s: %s", filepath, sqlite3_errmsg(state->dbptr));
        rc = -1;
        goto endconnect;
    }

    sqlite3_key(state->dbptr, key, strlen(key));

    if (sqlite3_exec(state->dbptr, "PRAGMA journal_mode = WAL;", NULL, NULL,
            NULL) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: error while setting journal mode for CIN state tracking database: %s", sqlite3_errmsg(state->dbptr));
        rc = -1;
        goto endconnect;
    }

    if (sqlite3_exec(state->dbptr, "PRAGMA synchronous = normal;", NULL, NULL,
            NULL) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: error while setting synchronous mode for CIN state tracking database: %s", sqlite3_errmsg(state->dbptr));
        rc = -1;
        goto endconnect;
    }

    if (sqlite3_busy_timeout(state->dbptr, 5000) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: error while setting busy mode timeout for CIN state tracking database: %s", sqlite3_errmsg(state->dbptr));
        rc = -1;
        goto endconnect;
    }

    if (sqlite3_exec(state->dbptr, "CREATE TABLE IF NOT EXISTS cinstate (liid text, cin integer, iriseqno integer, ccseqno integer, iribegin boolean, iriend boolean, PRIMARY KEY (liid,cin));", NULL, NULL, NULL) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: error while validating table in CIN state tracking database: %s", sqlite3_errmsg(state->dbptr));
        rc = -1;
    }


endconnect:
    if (rc == -1) {
        sqlite3_close(state->dbptr);
        state->dbptr = NULL;
        return 0;
    }

    return 1;

#else
    return 0;
#endif

}

void cinstate_db_close(openli_cinstatedb_t *state) {
    if (state == NULL) return;
#if HAVE_SQLCIPHER
    if (state->update_stmt) {
        sqlite3_finalize(state->update_stmt);
    }
    if (state->dbptr) {
        sqlite3_close(state->dbptr);
    }
#endif
    state->dbptr = NULL;
    state->update_stmt = NULL;
}

void cinstate_db_lookup(openli_cinstatedb_t *state, char *liid, uint32_t cin,
        struct cinstate_t *result) {

    if (state->dbptr == NULL) {
        return;
    }

#if HAVE_SQLCIPHER
    sqlite3_stmt *sel_stmt;
    int rc, step;

    rc = sqlite3_prepare_v2(state->dbptr, select_cinstate_sql, -1, &sel_stmt,
            NULL);
    if (rc != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: error while preparing statement to perform lookup in CIN state tracking database: %s",
                sqlite3_errmsg(state->dbptr));
        return;
    }

    sqlite3_bind_text(sel_stmt, 1, liid, -1, SQLITE_STATIC);
    sqlite3_bind_int(sel_stmt, 2, cin);

    step = sqlite3_step(sel_stmt);
    if (step == SQLITE_ROW) {
        result->iri_seqno = sqlite3_column_int(sel_stmt, 0);
        result->cc_seqno = sqlite3_column_int(sel_stmt, 1);
    }

    sqlite3_finalize(sel_stmt);
#endif

}

int cinstate_db_update(openli_cinstatedb_t *state, char *liid, uint32_t cin,
        struct cinstate_t *update) {

    if (state->dbptr == NULL) {
        return 0;
    }
    if (liid == NULL || update == NULL) {
        return 0;
    }

#if HAVE_SQLCIPHER
    int rc;

    if (state->update_stmt == NULL) {
        sqlite3_stmt *upd_stmt;

        if (sqlite3_prepare_v2(state->dbptr, update_cinstate_sql, -1,
                &upd_stmt, 0) != SQLITE_OK) {
            logger(LOG_INFO, "OpenLI collector: failed to prepare upsert statement for CIN state database: %s", sqlite3_errmsg(state->dbptr));
            return -1;
        }
        state->update_stmt = upd_stmt;
    }

    sqlite3_clear_bindings(state->update_stmt);

    sqlite3_bind_text(state->update_stmt, 1, liid, -1, SQLITE_STATIC);
    sqlite3_bind_int(state->update_stmt, 2, cin);
    sqlite3_bind_int(state->update_stmt, 3, update->iri_seqno);
    sqlite3_bind_int(state->update_stmt, 4, update->cc_seqno);

    rc = sqlite3_step(state->update_stmt);
    if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
        sqlite3_reset(state->update_stmt);
        return 0;
    }
    if (rc != SQLITE_DONE) {
        logger(LOG_INFO, "OpenLI collector: failed to execute upsert statement for CIN state database: %s", sqlite3_errmsg(state->dbptr));
        sqlite3_reset(state->update_stmt);
        return -1;
    }

    sqlite3_reset(state->update_stmt);
    return 1;

#endif
    return 1;
}

int cinstate_db_remove_by_cin(openli_cinstatedb_t *state, char *liid,
        uint32_t cin) {

    if (state->dbptr == NULL || liid == NULL) {
        return 0;
    }

#if HAVE_SQLCIPHER
    sqlite3_stmt *del_stmt;
    int rc;

    if (sqlite3_prepare_v2(state->dbptr, remove_cinstate_cin_sql, -1,
            &del_stmt, 0) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: failed to prepare delete statement for CIN state database: %s", sqlite3_errmsg(state->dbptr));
        return -1;
    }

    sqlite3_bind_text(del_stmt, 1, liid, -1, SQLITE_STATIC);
    sqlite3_bind_int(del_stmt, 2, cin);

    if ((rc = sqlite3_step(del_stmt)) != SQLITE_DONE)  {
        logger(LOG_INFO, "OpenLI collector: failed to execute delete statement for CIN state database: %s", sqlite3_errmsg(state->dbptr));
        return -1;
    }

    sqlite3_finalize(del_stmt);
    return 1;

#endif
    return 0;

}

int cinstate_db_remove_by_liid(openli_cinstatedb_t *state, char *liid) {

    if (state->dbptr == NULL || liid == NULL) {
        return 0;
    }

#if HAVE_SQLCIPHER
    sqlite3_stmt *del_stmt;
    int rc;

    if (sqlite3_prepare_v2(state->dbptr, remove_cinstate_liid_sql, -1,
            &del_stmt, 0) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: failed to prepare delete statement for CIN state database: %s", sqlite3_errmsg(state->dbptr));
        return -1;
    }

    sqlite3_bind_text(del_stmt, 1, liid, -1, SQLITE_STATIC);
    if ((rc = sqlite3_step(del_stmt)) != SQLITE_DONE)  {
        logger(LOG_INFO, "OpenLI collector: failed to execute delete statement for CIN state database: %s", sqlite3_errmsg(state->dbptr));
        return -1;
    }

    sqlite3_finalize(del_stmt);
    return 1;

#endif
    return 0;

}
