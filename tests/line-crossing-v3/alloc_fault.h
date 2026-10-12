
#ifndef LC_ALLOC_FAULT_H
#define LC_ALLOC_FAULT_H

#include <stddef.h>
#include <stdlib.h>

extern int lc_alloc_fail_armed;

void *lc_test_alloc(size_t sz);

#endif
