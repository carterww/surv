#include "surv.h"

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define REQUEST_BUFFER_SIZE 8192

struct callback_info {
  char *path;
  surv_http_handler cb;
};

struct parse_state {
  enum { METHOD, PATH, VERSION, HEADER, BODY, DONE } state;
  char *buff;
  size_t buff_size;
};

// Temporary data structures. I will replace these with a hash table later.
static struct callback_info get_cbs[10];
static struct callback_info post_cbs[10];
static struct callback_info put_cbs[10];
static struct callback_info delete_cbs[10];
static struct callback_info patch_cbs[10];

// Server socket file descriptor
static int sockfd = -1;

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
    return 0;
  }
  return -1;
}

static int get_path(const char *buff, size_t buff_size,
                    struct surv_http_context *ctx, int *read_bytes) {
  int first_byte = *read_bytes;
  int should_continue = 1;
  while (*read_bytes < buff_size) {
    if (buff[*read_bytes] != ' ') {
      ++(*read_bytes);
      continue;
    } else {
      should_continue = 0;
      break;
    }
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
  return should_continue;
}

// I will implement this later
static int get_version(const char *buff, size_t buff_size,
                       struct surv_http_context *ctx, int *read_bytes) {
  int first_byte = *read_bytes;
  int should_continue = 1;
  int reached_r = 0;
  while (*read_bytes < buff_size - 1) {
    if (buff[*read_bytes] == '\r') {
      reached_r = 1;
    }
    if (buff[*read_bytes] == '\n' && reached_r) {
      should_continue = 0;
      break;
    }
    ++(*read_bytes);
  }
  return should_continue;
}

static int get_headers(const char *buff, size_t buff_size,
                      struct surv_http_context *ctx, int *read_bytes) {
  return 0;
}

static int get_body(const char *buff, size_t buff_size,
                    struct surv_http_context *ctx, int *read_bytes) {
  return 0;
}

static int parse_request(struct surv_http_context *ctx,
                         struct parse_state *state) {
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
    if (!res) state->state = VERSION;
  case VERSION:
    if (state->buff_size <= read)
      return 0;
    res = get_version(state->buff, state->buff_size, ctx, &read);
    if (res < 0) {
      log_error("get_version() failed");
      return -1;
    }
    if (!res) state->state = HEADER;
  case HEADER:
    if (state->buff_size <= read)
      return 0;
    res = get_headers(state->buff, state->buff_size, ctx, &read);
    if (res < 0) {
      log_error("get_headers() failed");
      return -1;
    }
    if (!res) state->state = BODY;
  case BODY:
    if (state->buff_size <= read)
      return 0;
    res = get_body(state->buff, state->buff_size, ctx, &read);
    if (res < 0) {
      log_error("get_body() failed");
      return -1;
    }
    if (!res) state->state = DONE;
  case DONE:
    break;
  }
  return 0;
}

static void log_client_connection(const struct sockaddr_in *addr) {
  char addr_str[22];
  surv_addr_to_str((struct sockaddr *)addr, addr_str, sizeof(addr_str));
  log_info("accept() succeeded. Connection from %s", addr_str);
}

static void *accept_worker(void *client) {
  struct surv_sock_client *c = (struct surv_sock_client *)client;
  log_client_connection((struct sockaddr_in *)&c->addr);

  struct surv_http_context *ctx = calloc(1, sizeof(struct surv_http_context));
  if (ctx == NULL) {
    log_error("calloc() failed: %s", strerror(errno));
    goto cleanup;
  }
  ctx->client = c;

  struct parse_state state = {0};
  state.state = METHOD;
  state.buff = malloc(REQUEST_BUFFER_SIZE);
  state.buff_size = REQUEST_BUFFER_SIZE;
  if (state.buff == NULL) {
    log_error("malloc() failed: %s", strerror(errno));
    free(ctx);
    goto cleanup;
  }

  for (;;) {
    ssize_t bytes_read =
        recv(c->client_sockfd, state.buff, REQUEST_BUFFER_SIZE, 0);
    if (bytes_read < 0) {
      log_error("recv() failed: %s", strerror(errno));
      goto free_ctx;
    }
    if (bytes_read == 0) {
      log_info("No more data to read.");
      break;
    }

    int res;
    if ((res = parse_request(ctx, &state)) < 0) {
      goto free_ctx;
    }
    break;
  }

  log_info("Client requesting resource:\n%s", ctx->path);

  char helloworld[] = "HTTP/1.1 200 OK\r\n"
                      "Content-Type: text/plain\r\n"
                      "Content-Length: 13\r\n"
                      "\r\n"
                      "Hello, World!";
  send(c->client_sockfd, helloworld, sizeof(helloworld), 0);


free_ctx:
  free(state.buff);
  switch (state.state) {
  case DONE:
  case BODY:
    free(ctx->body);
  case HEADER:
    free(ctx->headers);
  case VERSION:
  case PATH:
    free(ctx->path);
  default:
    free(ctx);
  }
  log_debug("Freed context for %d", c->client_sockfd);
cleanup:
  close(c->client_sockfd);
  free(c);
  log_debug("Closed client socket");
  return NULL;
}

void surv_addr_to_str(const struct sockaddr *addr, char *str, size_t len) {
  const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;

  snprintf(str, len, "%d.%d.%d.%d:%d",
           ((ntohl(addr_in->sin_addr.s_addr) & 0xFF000000) >> 24),
           ((ntohl(addr_in->sin_addr.s_addr) & 0x00FF0000) >> 16),
           ((ntohl(addr_in->sin_addr.s_addr) & 0x0000FF00) >> 8),
           (ntohl(addr_in->sin_addr.s_addr) & 0x000000FF),
           ntohs(addr_in->sin_port));
}

int surv_setup(struct surv_server *server) {
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    log_fatal("socket() failed: %s", strerror(errno));
    return SURV_ERR_SOCKET;
  }
  log_trace("socket() succeeded. sockfd=%d", sockfd);

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(server->port);
  server_addr.sin_addr.s_addr = htonl(server->address);

  {
    char addr_str[22];
    surv_addr_to_str((struct sockaddr *)&server_addr, addr_str,
                     sizeof(addr_str));
    log_debug("Binding to %s", addr_str);
  }

  if (bind(sockfd, (void *)&server_addr, sizeof(server_addr)) < 0) {
    log_error("bind() failed: %s", strerror(errno));
    close(sockfd);
    return SURV_ERR_BIND;
  }
  log_trace("bind() succeeded");

  if (listen(sockfd, server->backlog) < 0) {
    log_error("listen() failed: %s", strerror(errno));
    close(sockfd);
    return SURV_ERR_LISTEN;
  }
  log_trace("listen() succeeded");
  return sockfd;
}

void surv_run() {
  for (;;) {
    struct surv_sock_client *client = malloc(sizeof(struct surv_sock_client));
    if (client == NULL) {
      log_error("malloc() failed: %s", strerror(errno));
      continue;
    }
    socklen_t client_addr_len = sizeof(client->addr);

    client->client_sockfd =
        accept(sockfd, (void *)&client->addr, &client_addr_len);
    if (client->client_sockfd < 0) {
      log_error("accept() failed: %s. Listening for other connections...",
                strerror(errno));
      free(client);
      continue;
    }

    pthread_t thread;
    pthread_create(&thread, NULL, accept_worker, client);
    pthread_detach(thread);
  }
}

int surv_close() {
  if (sockfd < 0) {
    log_warn("sockfd is already closed");
    return EBADF; // Bad file descriptor
  }
  log_info("Closing sockfd=%d", sockfd);
  int i = 0;
  int res;
  while ((res = close(sockfd)) == EINTR && i < 100) {
    log_warn("close() was interrupted by a signal. Retrying...");
    ++i;
  }
  if (res < 0) {
    log_error("close() failed after %d tries: %s", i, strerror(errno));
    return errno;
  }
  sockfd = -1;
  return 0;
}
