/*
 * lc_app_entry.h — the v2 single entry point of the Line Crossing App.
 */
#ifndef LC_APP_ENTRY_H
#define LC_APP_ENTRY_H

#include <stdint.h>
#include "lc_app_abi_v2.h"

/* exit codes (distinct, loggable identities; 0 = clean cooperative stop) */
#define LC_APP_EXIT_OK            0
#define LC_APP_EXIT_BAD_API      (-1)  /* NULL api table                    */
#define LC_APP_EXIT_BAD_TABLE    (-2)  /* table_size != 48                  */
#define LC_APP_EXIT_BAD_ABI      (-3)  /* abi_version != 0x00020000         */
#define LC_APP_EXIT_BAD_FNPTR    (-4)  /* a required function is NULL       */
#define LC_APP_EXIT_UNAUTHORIZED (-5)  /* session/capability authorization  */
#define LC_APP_EXIT_HOST_FAULT   (-6)  /* persistent v2 contract violation  */
#define LC_APP_EXIT_RESOURCES    (-7)  /* persistent allocation exhaustion  */

int32_t app_entry(const lc_app_api_v2_t *api, uint32_t abi_version);

#endif
