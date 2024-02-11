#include "parsers.h"
#include "hashmap.h"
#include <stdlib.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

static int surv_kv_cmp(const void *a, const void *b, void *ud) {
  struct surv_kv *kv_a = (struct surv_kv *)a;
  struct surv_kv *kv_b = (struct surv_kv *)b;
  return strcmp(kv_a->key, kv_b->key);
}

static uint64_t surv_kv_hash(const void *item, uint64_t seed0, uint64_t seed1) {
  struct surv_kv *kv = (struct surv_kv *)item;
  return hashmap_sip(kv->key, strlen(kv->key), seed0, seed1);
}

static void surv_kv_free(void *item) {
  if (item == NULL)
    return;
  struct surv_kv *kv = (struct surv_kv *)item;
  free(kv->key);
  free(kv->value);
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

static int get_method(char *buff, size_t buff_size,
                      struct surv_http_context *ctx, char **saveptr) {
  char *method = strtok_r(buff, " ", saveptr);
  int method_enum = method_str_to_enum(method, 8);
  if (method_enum < 0) {
    log_error("Invalid method: %s", method);
    return -1;
  }
  ctx->method = method_enum;
  return 1;
}

static int get_query_from_path(const char *buff, size_t buff_size,
                               struct surv_http_context *ctx, int *read_bytes) {
  // sizeof, initial size, seed0, seed1, hash, cmp, free, userdata
  ctx->query_params = hashmap_new(sizeof(struct surv_kv), 0, 0, 0, surv_kv_hash,
                                  surv_kv_cmp, surv_kv_free, NULL);
  return 1;
}

static int get_path(char *buff, size_t buff_size, struct surv_http_context *ctx,
                    char **saveptr) {
  char *first = *saveptr;
  char *path = strtok_r(NULL, " ", saveptr);
  if (path == NULL) {
    log_error("strtok_r() failed to find path");
    return -1;
  }
  size_t len = *saveptr - first;
  ctx->path = calloc(len, sizeof(char));
  if (ctx->path == NULL) {
    log_error("calloc() failed: %s", strerror(errno));
    return -1;
  }
  strncpy(ctx->path, path, len);
  return 1;
}

// I will implement this later
static int get_version(char *buff, size_t buff_size,
                       struct surv_http_context *ctx, char **saveptr) {
  strtok_r(NULL, "\r\n", saveptr);
  return 1;
}

static int get_headers(char *buff, size_t buff_size,
                       struct surv_http_context *ctx, char **saveptr) {

  // TODO: Move to worker function, this should not be done here
  if (ctx->headers == NULL) {
    // sizeof, initial size, seed0, seed1, hash, cmp, free, userdata
    ctx->headers = hashmap_new(sizeof(struct surv_kv), 0, 0, 0, surv_kv_hash,
                               surv_kv_cmp, surv_kv_free, NULL);
  }

  char *header = NULL;
  while ((header = strtok_r(NULL, "\r\n", saveptr)) != NULL) {
    // TODO: Fix detecting end of headers
    log_debug("Header: %s", header);
    if (header[0] == '\0') {
      return 1; // Reached two successive \r\n
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
    struct surv_kv kv = {0};
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
    strncpy(kv.key, key, key_len);
    strncpy(kv.value, value, value_len);
    kv.key[key_len] = '\0';
    kv.value[value_len] = '\0';
    if (hashmap_set(ctx->headers, &kv) == NULL && hashmap_oom(ctx->headers)) {
      log_error("hashmap_set() failed: %s", strerror(errno));
      return -1;
    }
  }
  return 1;
}

static int get_body(const char *buff, size_t buff_size,
                    struct surv_http_context *ctx, int *read_bytes) {
  long long content_length = -1;
  struct surv_kv kv = {0};
  kv.key = "Content-Length";

  const void *item;
  if ((item = hashmap_get(ctx->headers, &kv)) != NULL) {
    const struct surv_kv *kv_get = (const struct surv_kv *)item;
    content_length = atoll(kv_get->value);
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
  strncpy(ctx->body, buff, MIN(content_length, buff_size));
  ctx->body[content_length] = '\0';
  return 1;
}

int parse_request(struct surv_http_context *ctx, struct parse_state *state,
                  char **saveptr) {
  int res = 0;
  int read = 0;
  switch (state->state) {
  case METHOD:
    res = get_method(state->buff, state->buff_size, ctx, saveptr);
    if (res < 0) {
      log_error("get_method() failed");
      return -1;
    }
    state->state = PATH;
  case PATH:
    if (state->buff_size <= read)
      return 0;
    res = get_path(state->buff, state->buff_size, ctx, saveptr);
    if (res < 0) {
      log_error("get_path() failed");
      return -1;
    }
    if (res)
      state->state = VERSION;
  case VERSION:
    if (state->buff_size <= read)
      return 0;
    res = get_version(state->buff, state->buff_size, ctx, saveptr);
    if (res < 0) {
      log_error("get_version() failed");
      return -1;
    }
    if (res)
      state->state = HEADER;
  case HEADER:
    if (state->buff_size <= read)
      return 0;
    res = get_headers(state->buff, state->buff_size, ctx, saveptr);
    if (res < 0) {
      log_error("get_headers() failed");
      return -1;
    }
    if (res)
      state->state = BODY;
  case BODY:
    if (state->buff_size <= read)
      return 0;
    res = get_body(state->buff, state->buff_size, ctx, &read);
    if (res < 0) {
      log_error("get_body() failed");
      return -1;
    }
    if (res)
      state->state = DONE;
  case DONE:
    return 1;
  }
  return 0;
}

#undef MIN
