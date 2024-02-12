#include <stdbool.h>
#include <stdlib.h>

#include "def.h"
#include "hashmap.h"
#include "parsers.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// Definitions for parsing return flags
#define PARSE_ERROR -1
#define PARSE_READ_MORE 0
#define PARSE_DONE 1

static int more_in_buffer(struct parse_state *state) {
  if (state->saveptr == NULL) {
    return 0;
  }
  if (state->buff + state->buff_size <= state->saveptr) {
    return 0;
  }
  return 1;
}

// TODO: Performance test this to strtok_r to make sure it's comparable at
// least
char *strtok_r_nullable(char *str, const char delim, char **saveptr,
                        int *reached_delim) {
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
  if (reached_delim) {
    *reached_delim = end != NULL;
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
  size_t read_len = 0;
  if (read) {
    read_len = strnlen(read, state->buff_size);
  }
  size_t carry_len = strlen(state->carry);
  char *combined = malloc(carry_len + read_len + 1);
  if (combined == NULL) {
    log_error("malloc() failed: %s", strerror(errno));
    *should_free = 0;
    return NULL;
  }
  strcpy(combined, state->carry);
  combined[carry_len] = '\0';
  if (read)
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
static int realloc_carry(struct parse_state *state, char *read) {
  if (!read)
    return PARSE_READ_MORE;
  size_t read_len = strlen(read);
  size_t carry_len = 0;
  if (state->carry)
    carry_len = strlen(state->carry);
  state->carry = realloc(state->carry, carry_len + read_len + 1);
  if (carry_len == 0)
    memset(state->carry, 0, carry_len + read_len + 1);
  if (state->carry == NULL) {
    log_error("realloc() of carry failed: %s", strerror(errno));
    return PARSE_ERROR;
  }
  strncat(state->carry, read, read_len);
  state->carry[carry_len + read_len] = '\0';
  return PARSE_READ_MORE;
}

static int get_method(struct parse_state *state,
                      struct surv_http_context *ctx) {
  int reached_delim;
  char *method = strtok_r_nullable(state->buff, state->next_delim,
                                   &state->saveptr, &reached_delim);
  if (!reached_delim) {
    return realloc_carry(state, method);
  }
  int should_free = 0;
  char *combined = combine_carry(state, &should_free, method);
  if (combined == NULL)
    return PARSE_ERROR;

  size_t len = strlen(combined);
  int method_enum = method_str_to_enum(combined, MIN(state->buff_size, len));
  if (method_enum < 0) {
    log_error("Invalid method: %s", combined);
    return PARSE_ERROR;
  }
  ctx->method = method_enum;
  log_debug("Method is %s", combined);
  if (should_free)
    free(combined);
  return PARSE_DONE;
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
  int reached_delim;
  char *path = strtok_r_nullable(NULL, state->next_delim, &state->saveptr,
                                 &reached_delim);
  if (!reached_delim) {
    return realloc_carry(state, path);
  }
  int should_free = 0;
  char *combined = combine_carry(state, &should_free, path);
  if (combined == NULL)
    return PARSE_ERROR;

  size_t len = strlen(combined);
  ctx->path = malloc(len + 1);
  if (ctx->path == NULL) {
    log_error("malloc() failed: %s", strerror(errno));
    return PARSE_ERROR;
  }
  strcpy(ctx->path, combined);
  if (should_free)
    free(combined);

  ctx->path[len] = '\0';
  log_debug("Path is %s", ctx->path);
  get_query_from_path(ctx);
  return PARSE_DONE;
}

static int parse_rton(struct parse_state *state, char **result,
                      int *should_free) {
  if (state->saveptr == NULL) {
    state->saveptr = state->buff;
  }
  char *str = NULL;
  if (state->next_delim == '\r') {
    int reached_delim;
    str = strtok_r_nullable(NULL, state->next_delim, &state->saveptr,
        &reached_delim);
    if (reached_delim && !more_in_buffer(state)) {
      state->next_delim = '\n';
      return realloc_carry(state, str);
    } else if (reached_delim && more_in_buffer(state)) {
      state->next_delim = '\n';
    } else {
      return realloc_carry(state, str);
    }
  }

  int reached_delim;
  char *rton = strtok_r_nullable(NULL, state->next_delim, &state->saveptr,
      &reached_delim);
  if (!reached_delim || !rton || rton[0] != '\0') {
    return PARSE_ERROR;
  }
  *result = combine_carry(state, should_free, str);
  return PARSE_DONE;
}

static int get_version(struct parse_state *state,
                       struct surv_http_context *ctx) {
  int should_free = 0;
  char *version = NULL;
  int res = parse_rton(state, &version, &should_free);
  if (should_free)
    free(version);
  return res;
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

  int should_free = 0;
  char *header = NULL;
  int res;
  while ((res = parse_rton(state, &header, &should_free)) == PARSE_DONE) {
    if (strlen(header) == 0) {
      return PARSE_DONE;
    }
    char *saveptr = NULL;
    // End of headers
    struct surv_map_entry_str kv = {0};
    char *key = strtok_r(header, ":", &saveptr);
    if (key == NULL) {
      log_error("Invalid key: %s", key);
      return PARSE_ERROR;
    }
    char *value = strtok_r(NULL, " ", &saveptr);
    if (*value == '\0') {
      log_error("Invalid header value: %s", value);
      return PARSE_ERROR;
    }
    kv.key = malloc(strlen(key) + 1);
    kv.value = malloc(strlen(value) + 1);
    char *v = (char *)kv.value;
    if (kv.key == NULL || kv.value == NULL) {
      log_error("malloc() failed: %s", strerror(errno));
      return PARSE_ERROR;
    }
    strcpy(kv.key, key);
    strcpy(v, value);
    kv.key[strlen(key)] = '\0';
    v[strlen(value)] = '\0';
    if (hashmap_set(ctx->headers, &kv) == NULL &&
        hashmap_oom(ctx->headers)) {
      if (should_free)
        free(header);
      log_error("hashmap_set() failed: %s", strerror(errno));
      return PARSE_ERROR;
    }
    if (should_free)
      free(header);
    state->next_delim = '\r';
  }
  return res;
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
    res = should_continue_parsing(state, res, '\r');
    if (res != 1) {
      return res;
    }
  case VERSION:
    res = get_version(state, ctx);
    res = should_continue_parsing(state, res, '\r');
    if (res != 1) {
      return res;
    }
  case HEADER:
    res = get_headers(state, ctx);
    res = should_continue_parsing(state, res, '\r');
    if (res != 1) {
      return res;
    }
  case BODY:
    res = get_body(state->buff_size, ctx, &state->saveptr);
    res = should_continue_parsing(state, res, '\r');
    if (res != 1) {
      return res;
    }
  case DONE:
    return 1;
  }
  return 0;
}

#undef MIN
