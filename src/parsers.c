#include "parsers.h"
#include "hashmap.h"

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

static int get_method(const char *buff, size_t buff_size,
                      struct surv_http_context *ctx, int *read_bytes) {
  // 8 is lowest len of method
  int upper_bound = MIN(buff_size, 8);
  while (*read_bytes < upper_bound) {
    if (buff[*read_bytes] != ' ') {
      ++(*read_bytes);
      continue;
    }
    int method = method_str_to_enum(buff, *read_bytes);
    if (method < 0) {
      log_error("Invalid method: %s", *read_bytes, buff);
      return -1;
    }
    ctx->method = method;
    ++(*read_bytes);
    return 1;
  }
  return -1;
}

static int get_query_from_path(const char *buff, size_t buff_size,
                               struct surv_http_context *ctx, int *read_bytes) {
  // sizeof, initial size, seed0, seed1, hash, cmp, free, userdata
  ctx->query_params = hashmap_new(sizeof(struct surv_kv), 0, 0, 0, surv_kv_hash,
                                  surv_kv_cmp, surv_kv_free, NULL);
  return 1;
}

static int get_path(const char *buff, size_t buff_size,
                    struct surv_http_context *ctx, int *read_bytes) {
  int first_byte = *read_bytes;
  int is_done = 0;
  while (*read_bytes < buff_size) {
    if (buff[*read_bytes] == ' ') {
      is_done = 1;
      break;
    }
    ++(*read_bytes);
    continue;
  }
  size_t len = *read_bytes - first_byte;
  if (ctx->path == NULL) {
    ctx->path = calloc(len + 1, sizeof(char));
    if (ctx->path == NULL) {
      log_error("calloc() failed: %s", strerror(errno));
      return -1;
    }
  } else {
    size_t old_len = strlen(ctx->path);
    len += old_len;
    ctx->path = realloc(ctx->path, len + 1);
    if (ctx->path == NULL) {
      log_error("realloc() failed: %s", strerror(errno));
      return -1;
    }
    ctx->path[old_len + 1] = '\0';
  }

  strncat(ctx->path, &(buff[first_byte]), *read_bytes - first_byte);
  ctx->path[len] = '\0';
  ++(*read_bytes);
  return is_done;
}

// I will implement this later
static int get_version(const char *buff, size_t buff_size,
                       struct surv_http_context *ctx, int *read_bytes) {
  int first_byte = *read_bytes;
  int is_done = 0;
  int reached_r = 0;
  while (*read_bytes < buff_size - 1 && !is_done) {
    if (buff[*read_bytes] == '\r') {
      reached_r = 1;
      ++(*read_bytes);
    }
    if (buff[*read_bytes] == '\n' && reached_r) {
      is_done = 1;
    }
    ++(*read_bytes);
  }
  return is_done;
}

static int parse_indv_header(const char *buff, size_t buff_size,
                             struct surv_kv *kv, int first_byte, int last_byte,
                             struct hashmap *map) {

  int len = last_byte - first_byte;
  int colon = -1;
  int start_value = -1;
  for (int i = first_byte; i < last_byte; ++i) {
    if (buff[i] == ':') {
      colon = i;
      continue;
    }
    if (colon != -1 && buff[i] != ' ' && start_value == -1) {
      start_value = i;
      break;
    }
  }
  if (colon < 0) {
    char *bytes = calloc(last_byte - first_byte + 1, sizeof(char));
    strncpy(bytes, &(buff[first_byte]), last_byte - first_byte);
    log_error("Invalid header: %s", bytes);
    free(bytes);
    return 0;
  }
  kv->key = calloc(colon - first_byte + 1, sizeof(char));
  kv->value = calloc(last_byte - start_value + 1, sizeof(char));
  strncpy(kv->key, &(buff[first_byte]), colon - first_byte);
  strncpy(kv->value, &(buff[start_value]), last_byte - start_value);
  kv->key[colon - first_byte] = '\0';
  kv->value[last_byte - start_value] = '\0';

  // set copies the data so don't need to alloc
  if (hashmap_set(map, kv) == NULL && hashmap_oom(map)) {
    log_error("hashmap_set() is oom?");
    return -1;
  }
  return 0;
}

static int parse_indv_with_incomplete(const char *buff, size_t buff_size,
                                      struct surv_kv *kv, int first_byte,
                                      int last_byte, struct hashmap *map,
                                      char **incomplete_header) {
  // This case is so much easier and way more common
  // so I will handle it in a more efficient manner
  if (*incomplete_header == NULL)
    return parse_indv_header(buff, buff_size, kv, first_byte, last_byte, map);

  // This case is rare and ugly, please don't even
  // look unless there's a bug
  int colon = -1;
  int start_value = -1;
  int start_value_in_buff = 1;

  size_t len = strlen(*incomplete_header);
  for (int i = 0; i < len; ++i) {
    if ((*incomplete_header)[i] == ':') {
      colon = i;
      continue;
    }
    if (colon != -1 && (*incomplete_header)[i] != ' ') {
      start_value = i;
      start_value_in_buff = 0;
      break;
    }
  }

  size_t incomplete_len = strlen(*incomplete_header);
  if (colon != -1) {
    kv->key = calloc(colon + 1, sizeof(char));
    strncpy(kv->key, *incomplete_header, colon);
    kv->key[colon] = '\0';
  } else {
    for (int i = first_byte; i < last_byte; ++i) {
      if (buff[i] == ':') {
        colon = i;
        continue;
      }
      if (colon != -1 && buff[i] != ' ' && start_value == -1) {
        start_value = i;
        start_value_in_buff = 1;
        break;
      }
    }
    if (colon < 0) {
      return -1;
    }
    kv->key = calloc(incomplete_len + colon - first_byte + 1, sizeof(char));
    strncpy(kv->key, *incomplete_header, incomplete_len);
    strncat(kv->key, &(buff[first_byte]), colon - first_byte);
    kv->key[incomplete_len + colon - first_byte] = '\0';
  }
  // KEY IS TAKEN CARE OF

  if (start_value_in_buff) {
    kv->value = calloc(last_byte - start_value + 1, sizeof(char));
    strncpy(kv->value, &(buff[start_value]), last_byte - start_value);
    kv->value[last_byte - start_value] = '\0';
  } else {
    kv->value =
        calloc(incomplete_len - start_value + 1 + last_byte - first_byte,
               sizeof(char));
    strncpy(kv->value, &((*incomplete_header)[start_value]),
            incomplete_len - start_value);
    strncat(kv->value, &(buff[first_byte]), last_byte - first_byte);
    kv->value[incomplete_len - start_value + last_byte - first_byte] = '\0';
  }
  hashmap_set(map, kv);

  *incomplete_header = NULL;
  return 0;
}

static int get_headers(const char *buff, size_t buff_size,
                       struct surv_http_context *ctx, int *read_bytes,
                       char **incomplete_header) {

  if (ctx->headers == NULL) {
    // sizeof, initial size, seed0, seed1, hash, cmp, free, userdata
    ctx->headers = hashmap_new(sizeof(struct surv_kv), 0, 0, 0, surv_kv_hash,
                               surv_kv_cmp, surv_kv_free, NULL);
  }
  int first_byte = *read_bytes;
  int is_done = 0;
  int reached_r = 0;
  while (*read_bytes < buff_size - 1 && !is_done) {
    if (buff[*read_bytes] == '\r') {
      ++(*read_bytes);
      reached_r = 1;
    }
    if (buff[*read_bytes] == '\n' && reached_r) {
      is_done = 1;
    }
    ++(*read_bytes);

    if (is_done) {
      if (*read_bytes - first_byte == 2) {
        // Empty line, end of headers
        break;
      }
      int last_byte = *read_bytes - 2;
      struct surv_kv kv = {0};

      if (parse_indv_with_incomplete(buff, buff_size, &kv, first_byte,
                                     last_byte, ctx->headers,
                                     incomplete_header) < 0) {
        log_error("parse_indv_with_incomplete() failed");
        return -1;
      }

      is_done = 0;
      first_byte = *read_bytes;
    }
  }
  if (is_done == 0) {
    // Save what got halfway read
    *incomplete_header = calloc(buff_size - first_byte + 1, sizeof(char));
    strncpy(*incomplete_header, &(buff[first_byte]), buff_size - first_byte);
    (*incomplete_header)[buff_size - first_byte] = '\0';
  }

  return is_done;
}

static int get_body(const char *buff, size_t buff_size,
                    struct surv_http_context *ctx, int *read_bytes) {
  return 1;
}

int parse_request(struct surv_http_context *ctx, struct parse_state *state) {
  int res = 0;
  int read = 0;
  switch (state->state) {
  case METHOD:
    res = get_method(state->buff, state->buff_size, ctx, &read);
    if (res < 0) {
      log_error("get_method() failed");
      return -1;
    }
    state->state = PATH;
  case PATH:
    if (state->buff_size <= read)
      return 0;
    res = get_path(state->buff, state->buff_size, ctx, &read);
    if (res < 0) {
      log_error("get_path() failed");
      return -1;
    }
    if (res)
      state->state = VERSION;
  case VERSION:
    if (state->buff_size <= read)
      return 0;
    res = get_version(state->buff, state->buff_size, ctx, &read);
    if (res < 0) {
      log_error("get_version() failed");
      return -1;
    }
    if (res)
      state->state = HEADER;
  case HEADER:
    if (state->buff_size <= read)
      return 0;
    res = get_headers(state->buff, state->buff_size, ctx, &read,
                      &state->incomplete_header);
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
