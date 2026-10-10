
#ifndef LC_APP_ENTRY_H
#define LC_APP_ENTRY_H

#include <stdint.h>
#include "lc_app_abi_v2.h"

#define LC_APP_EXIT_OK            0
#define LC_APP_EXIT_BAD_API      (-1)
#define LC_APP_EXIT_BAD_TABLE    (-2)
#define LC_APP_EXIT_BAD_ABI      (-3)
#define LC_APP_EXIT_BAD_FNPTR    (-4)
#define LC_APP_EXIT_UNAUTHORIZED (-5)
#define LC_APP_EXIT_HOST_FAULT   (-6)
#define LC_APP_EXIT_RESOURCES    (-7)

int32_t app_entry(const lc_app_api_v2_t *api, uint32_t abi_version);

#endif
