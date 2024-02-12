#include "def.h"

int surv_map_entry_str_cmp(const void *a, const void *b, void *udata) {
  struct surv_map_entry_str *ea = (struct surv_map_entry_str *)a;
  struct surv_map_entry_str *eb = (struct surv_map_entry_str *)b;
  return strcmp(ea->key, eb->key);
}

uint64_t surv_map_entry_str_hash(const void *item, uint64_t seed0, uint64_t seed1) {
  struct surv_map_entry_str *entry = (struct surv_map_entry_str *)item;
  return hashmap_sip(entry->key, strlen(entry->key), seed0, seed1);
}

void surv_map_entry_str_free(void *item) {
  struct surv_map_entry_str *entry = (struct surv_map_entry_str *)item;
  free(entry->key);
  free(entry->value);
}
