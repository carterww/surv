#include <stdbool.h>
#include <stdlib.h>

#include "def.h"
#include "hashmap.h"
#include "parsers.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// TODO: Performance test this to strtok_r to make sure it's comparable at
// least
char *strtok_r_nullable(char *str, const char delim, char **saveptr) {
  if (str == NULL) {
    str = *saveptr;
  }
  if (str == NULL) {
    return NULL;
  }
  char *end = strchr(str, delim);
  if (end == NULL) {
    *saveptr = NULL;
  } else {
    *saveptr = end + 1;
    *end = '\0';
  }
  return str;
}

static int method_str_to_enum(const char *method, size_t len) {
  // These should be in a hash table do later
  if (strncmp(method, "GET", len) == 0) {
    return GET;
  } else if (strncmp(method, "POST", len) == 0) {
    return POST;
  } else if (strncmp(method, "PUT", len) == 0) {
    return PUT;
  } else if (strncmp(method, "DELETE", len) == 0) {
    return DELETE;
  } else if (strncmp(method, "PATCH", len) == 0) {
    return PATCH;
  }
  return -1;
}

/* Combine the carry from last recv with the current buffer.
 * If there is no carry, return the buffer and set should_free to 0.
 * If there is a carry, combine the carry and buffer and set should_free to 1.
 * This action allocates memory, so the caller should free the result if
 * should_free is 1.
 * On error, NULL is returned and should_free is set to 0.
 */
static char *combine_carry(struct parse_state *state, int *should_free,
                           char *read) {
  if (!state->carry) {
    *should_free = 0;
    return read;
  }
  size_t carry_len = strlen(state->carry);
  size_t read_len = strnlen(read, state->buff_size);
  char *combined = malloc(carry_len + read_len + 1);
  if (combined == NULL) {
    log_error("malloc() failed: %s", strerror(errno));
    *should_free = 0;
    return NULL;
  }
  strcpy(combined, state->carry);
  combined[carry_len] = '\0';
  strncat(combined, read, state->buff_size);
  combined[carry_len + read_len] = '\0';
  free(state->carry);
  state->carry = NULL;
  *should_free = 1;
  return combined;
}

/* Save the carry from the buffer before calling recv again.
 * Returns 0 on success, -1 on error.
 */
static int realloc_carry(struct parse_state *state) {
  size_t buff_len = strlen(state->buff);
  size_t carry_len = 0;
  if (state->carry)
    carry_len = strlen(state->carry);
  state->carry = realloc(state->carry, carry_len + buff_len + 1);
  if (carry_len == 0)
    memset(state->carry, 0, carry_len + buff_len + 1);
  if (state->carry == NULL) {
    log_error("realloc() of carry failed: %s", strerror(errno));
    return -1;
  }
  strncat(state->carry, state->buff, state->buff_size);
  state->carry[carry_len + buff_len] = '\0';
  return 0;
}

static int get_method(struct parse_state *state,
                      struct surv_http_context *ctx) {
  char *method =
      strtok_r_nullable(state->buff, state->next_delim, &state->saveptr);
  // Method is partial, save carry
  if (state->saveptr == NULL && strlen(method) != 0) {
    return realloc_carry(state);
  }
  int should_free = 0;
  char *combined = combine_carry(state, &should_free, method);
  if (combined == NULL)
    return -1;

  size_t len = strlen(combined);
  int method_enum = method_str_to_enum(combined, MIN(state->buff_size, len));
  if (method_enum < 0) {
    log_error("Invalid method: %s", combined);
    return -1;
  }
  ctx->method = method_enum;
  log_debug("Method is %s", combined);
  if (should_free) {
    free(combined);
  }
  return 1;
}

static void get_query_from_path(struct surv_http_context *ctx) {
  // sizeof, initial size, seed0, seed1, hash, cmp, free, userdata
  char *saveptr = NULL;
  char *key = strtok_r(ctx->path, "?", &saveptr);
  if (key == NULL) {
    log_debug("No query params");
    return;
  }
  ctx->query_params =
      hashmap_new(sizeof(struct surv_map_entry_str), 0, 0, 0,
                  surv_map_entry_str_hash, surv_map_entry_str_cmp, NULL, NULL);

  while ((key = strtok_r(NULL, "=", &saveptr)) != NULL) {
    if (key == NULL) {
      return;
    }
    char *value = strtok_r(NULL, "&", &saveptr);
    if (value == NULL) {
      return;
    }

    struct surv_map_entry_str kv = {0};
    // ctx->path has same lifetime as this hashmap,
    // so we can just use the pointers directly
    kv.key = key;
    kv.value = value;
    if (hashmap_set(ctx->query_params, &kv) == NULL &&
        hashmap_oom(ctx->query_params)) {
      log_error("hashmap_set() failed: %s", strerror(errno));
      return;
    }
  }
}

static int get_path(struct parse_state *state, struct surv_http_context *ctx) {
  if (state->saveptr == NULL) {
    state->saveptr = state->buff;
  }
  char *path = strtok_r_nullable(NULL, state->next_delim, &state->saveptr);
  if (state->saveptr == NULL && strlen(path) != 0) {
    return realloc_carry(state);
  }
  int should_free = 0;
  char *combined = combine_carry(state, &should_free, path);
  if (combined == NULL)
    return -1;

  size_t len = strlen(combined);
  ctx->path = malloc(len + 1);
  if (ctx->path == NULL) {
    log_error("malloc() failed: %s", strerror(errno));
    return -1;
  }
  strcpy(ctx->path, combined);
  if (should_free)
    free(combined);

  ctx->path[len] = '\0';
  log_debug("Path is %s", ctx->path);
  get_query_from_path(ctx);
  return 1;
}

static int get_version(struct parse_state *state,
                       struct surv_http_context *ctx) {
  if (state->saveptr == NULL) {
    state->saveptr = state->buff;
  }
  char *version = strtok_r_nullable(NULL, state->next_delim, &state->saveptr);
  size_t len = strlen(version);
  // If no next char and returned string does not have delim
  if (state->saveptr == NULL && len != 0) {
    return realloc_carry(state);
  } else if (state->saveptr == NULL && len == 0) {
    if (state->next_delim == '\r') {
      state->next_delim = '\n';
      return 0;
    }
  }
  int should_free = 0;
  char *combined = combine_carry(state, &should_free, version);
  if (combined == NULL)
    return -1;

  log_debug("Version is %s", combined);
  if (should_free)
    free(combined);
  return 1;
}

static int get_headers(struct parse_state *state,
                       struct surv_http_context *ctx) {

  // TODO: Move to worker function, this should not be done here
  if (ctx->headers == NULL) {
    // sizeof, initial size, seed0, seed1, hash, cmp, free, userdata
    ctx->headers = hashmap_new(sizeof(struct surv_map_entry_str), 0, 0, 0,
                               surv_map_entry_str_hash, surv_map_entry_str_cmp,
                               surv_map_entry_str_free, NULL);
  }

  if (state->saveptr == NULL) {
    state->saveptr = state->buff;
  }
  char *header = strtok_r_nullable(NULL, state->next_delim, &state->saveptr);
  if (state->saveptr == NULL && strlen(header) != 0) {
    return realloc_carry(state);
  } else if (state->saveptr == NULL && strlen(header) == 0) {
    if (state->next_delim == '\r') {
      state->next_delim = '\n';
      return 0;
    }
  }
  char *after_r;
  while ((after_r = strtok_r_nullable(NULL, state->next_delim,
                                      &state->saveptr)) != NULL) {
    if (strlen(after_r) != 0) {
      break;
    }

    char *loop_saveptr = NULL;
    char *key = strtok_r(header, ":", &loop_saveptr);
    char *value = strtok_r(NULL, "\0", &loop_saveptr);
    if (!key || !value) {
      log_error("strtok_r() failed to parse header %s", header);
      return -1;
    }
    while (*value == ' ' && *value != '\0') {
      value++;
    }
    struct surv_map_entry_str kv = {0};
    int key_len = strlen(key);
    // TODO: fix these strlens, just calculate them from pointers
    kv.key = malloc(sizeof(char) * key_len + 1);
    if (kv.key == NULL) {
      log_error("malloc() failed: %s", strerror(errno));
      return -1;
    }
    int value_len = strlen(value);
    kv.value = malloc(sizeof(char) * value_len + 1);
    if (kv.value == NULL) {
      log_error("malloc() failed: %s", strerror(errno));
      return -1;
    }
    strcpy(kv.key, key);
    strcpy(kv.value, value);
    kv.key[key_len] = '\0';
    // kv.value[value_len] = '\0';
    if (hashmap_set(ctx->headers, &kv) == NULL && hashmap_oom(ctx->headers)) {
      log_error("hashmap_set() failed: %s", strerror(errno));
      return -1;
    }
  }
  return 1;
}

static int get_body(size_t buff_size, struct surv_http_context *ctx,
                    char **saveptr) {
  long long content_length = -1;
  struct surv_map_entry_str kv = {0};
  kv.key = "Content-Length";

  const void *item;
  if ((item = hashmap_get(ctx->headers, &kv)) != NULL) {
    const struct surv_kv *kv_get = (const struct surv_kv *)item;
    // content_length = atoll(kv_get->value);
  }
  if (content_length < 0) {
    log_debug("No content");
    return 1;
  }

  ctx->body = malloc(content_length + 1);
  if (ctx->body == NULL) {
    log_error("malloc() failed: %s", strerror(errno));
    return -1;
  }
  strncpy(ctx->body, *saveptr, MIN(content_length, buff_size));
  ctx->body[content_length] = '\0';
  return 1;
}

static int should_continue_parsing(struct parse_state *state, int res,
                                   const char next_state_delim) {
  if (res < 0) {
    log_error("parse_request() failed in state %d", state->state);
    return -1;
  }
  if (res == 0)
    return 0;

  if ((res && state->saveptr == NULL) ||
      (res && state->saveptr &&
       state->buff + state->buff_size <= state->saveptr)) {
    ++state->state;
    state->next_delim = next_state_delim;
    return 0;
  } else if (res) {
    ++state->state;
    state->next_delim = next_state_delim;
    return 1;
  }
  return 0;
}

int parse_request(struct surv_http_context *ctx, struct parse_state *state) {
  int res = 0;
  switch (state->state) {
  case METHOD:
    res = get_method(state, ctx);
    res = should_continue_parsing(state, res, ' ');
    if (res != 1) {
      return res;
    }
  case PATH:
    res = get_path(state, ctx);
    res = should_continue_parsing(state, res, '\n');
    if (res != 1) {
      return res;
    }
  case VERSION:
    res = get_version(state, ctx);
    res = should_continue_parsing(state, res, '\n');
    if (res != 1) {
      return res;
    }
  case HEADER:
    res = get_headers(state, ctx);
    res = should_continue_parsing(state, res, '\n');
    if (res != 1) {
      return res;
    }
  case BODY:
    res = get_body(state->buff_size, ctx, &state->saveptr);
    res = should_continue_parsing(state, res, '\n');
    if (res != 1) {
      return res;
    }
  case DONE:
    return 1;
  }
  return 0;
}

#undef MIN
