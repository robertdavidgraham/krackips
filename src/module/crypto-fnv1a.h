#ifndef FNV1A_H
#define FNV1A_H
#include <stdio.h>

unsigned
fnv1a_32(unsigned hash, const void *input, size_t len);

#endif
