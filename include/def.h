#ifndef SURV_DEF_H
#define SURV_DEF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hashmap.h"

struct surv_map_entry_str {
  char *key;
  void *value;
};

int surv_map_entry_str_cmp(const void *a, const void *b, void *udata);

uint64_t surv_map_entry_str_hash(const void *item, uint64_t seed0, uint64_t seed1);

void surv_map_entry_str_free(void *item);

#ifdef __cplusplus
}
#endif

#endif // SURV_DEF_H
