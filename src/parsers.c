#include "parsers.h"
#include "hashmap.h"
#include <stdlib.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// TODO: Performance test this to strtok_r to make sure it's comparable at
// least
char *strtok_r_nullable(char *str, const char *delim, char **saveptr) {
  if (str == NULL) {
    str = *saveptr;
  }
  if (str == NULL) {
    return NULL;
  }
  int delim_len = strlen(delim);
  if (delim_len == 0) {
    return NULL; // What?
  }
  char *end = strstr(str, delim);
  if (end == NULL) {
    *saveptr = NULL;
    return str;
  }
  *saveptr = end + delim_len;
  while (end != *saveptr) {
    *end = '\0';
    end++;
  }
  return str;
}

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

static int get_method(char *buff, struct surv_http_context *ctx,
                      char **saveptr) {
  char *method = strtok_r(buff, " ", saveptr);
  int method_enum = method_str_to_enum(method, 8);
  if (method_enum < 0) {
    log_error("Invalid method: %s", method);
    return -1;
  }
  ctx->method = method_enum;
  return 1;
}

static void get_query_from_path(struct surv_http_context *ctx) {
  // sizeof, initial size, seed0, seed1, hash, cmp, free, userdata
  if (ctx->query_params == NULL) {
    ctx->query_params = hashmap_new(sizeof(struct surv_kv), 0, 0, 0, surv_kv_hash,
        surv_kv_cmp, surv_kv_free, NULL);
  }
  char *saveptr = NULL;
  char *key = strtok_r(ctx->path, "?", &saveptr);
  if (key == NULL) {
    log_debug("No query params");
    return;
  }
  while ((key = strtok_r(NULL, "=", &saveptr)) != NULL) {
    if (key == NULL) {
      return;
    }
    char *value = strtok_r(NULL, "&", &saveptr);
    if (value == NULL) {
      return;
    }
    size_t key_len = strlen(key);
    size_t val_len = strlen(value);

    struct surv_kv kv = {0};
    kv.key = malloc(key_len + 1);
    if (kv.key == NULL) {
      log_error("malloc() failed: %s", strerror(errno));
      return;
    }
    kv.value = malloc(val_len + 1);
    if (kv.value == NULL) {
      log_error("malloc() failed: %s", strerror(errno));
      return;
    }
    strncpy(kv.key, key, key_len);
    strncpy(kv.value, value, val_len);
    kv.key[key_len] = '\0';
    kv.value[val_len] = '\0';
    if (hashmap_set(ctx->query_params, &kv) == NULL && hashmap_oom(ctx->query_params)) {
      log_error("hashmap_set() failed: %s", strerror(errno));
      return;
    }
  }
  char *end_path = strchr(ctx->path, '?');
  if (end_path != NULL) {
    ctx->path = realloc(ctx->path, end_path - ctx->path + 1);
    if (ctx->path == NULL) {
      log_error("realloc() failed: %s", strerror(errno));
      return;
    }
    ctx->path[end_path - ctx->path] = '\0';
  }
}

static int get_path(struct surv_http_context *ctx, char **saveptr) {
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
  get_query_from_path(ctx);
  return 1;
}

// I will implement this later
static int get_version(struct surv_http_context *ctx, char **saveptr) {
  strtok_r(NULL, "\n", saveptr);
  return 1;
}

static int get_headers(struct surv_http_context *ctx, char **saveptr) {

  // TODO: Move to worker function, this should not be done here
  if (ctx->headers == NULL) {
    // sizeof, initial size, seed0, seed1, hash, cmp, free, userdata
    ctx->headers = hashmap_new(sizeof(struct surv_kv), 0, 0, 0, surv_kv_hash,
                               surv_kv_cmp, surv_kv_free, NULL);
  }

  char *header = NULL;
  while ((header = strtok_r_nullable(NULL, "\r\n", saveptr)) != NULL) {
    // TODO: Fix detecting end of headers
    if (header[0] == '\0') {
      return 1;
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

static int get_body(size_t buff_size, struct surv_http_context *ctx,
                    char **saveptr) {
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
  strncpy(ctx->body, *saveptr, MIN(content_length, buff_size));
  ctx->body[content_length] = '\0';
  return 1;
}

int parse_request(struct surv_http_context *ctx, struct parse_state *state,
                  char **saveptr) {
  int res = 0;
  switch (state->state) {
  case METHOD:
    res = get_method(state->buff, ctx, saveptr);
    if (res < 0) {
      log_error("get_method() failed");
      return -1;
    }
    state->state = PATH;
  case PATH:
    res = get_path(ctx, saveptr);
    if (res < 0) {
      log_error("get_path() failed");
      return -1;
    }
    if (res)
      state->state = VERSION;
  case VERSION:
    res = get_version(ctx, saveptr);
    if (res < 0) {
      log_error("get_version() failed");
      return -1;
    }
    if (res)
      state->state = HEADER;
  case HEADER:
    res = get_headers(ctx, saveptr);
    if (res < 0) {
      log_error("get_headers() failed");
      return -1;
    }
    if (res)
      state->state = BODY;
  case BODY:
    res = get_body(state->buff_size, ctx, saveptr);
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
