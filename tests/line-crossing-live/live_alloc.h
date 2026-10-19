
#ifndef LIVE_ALLOC_H
#define LIVE_ALLOC_H

#include <stddef.h>

void *live_malloc(size_t sz);
void  live_free(void *p);

#endif
