#include "surv.h"

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "parsers.h"
#include "log.h"
#include "hashmap.h"

#define REQUEST_BUFFER_SIZE 8192

struct callback_info {
  char *path;
  surv_http_handler cb;
};

// Temporary data structures. I will replace these with a hash table later.
static struct callback_info get_cbs[10];
static struct callback_info post_cbs[10];
static struct callback_info put_cbs[10];
static struct callback_info delete_cbs[10];
static struct callback_info patch_cbs[10];

// Server socket file descriptor
static int sockfd = -1;

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
  if (state.buff == NULL) {
    log_error("malloc() failed: %s", strerror(errno));
    goto free_ctx;
  }

  for (;;) {
    ssize_t bytes_read =
        recv(c->client_sockfd, state.buff, REQUEST_BUFFER_SIZE - 1, 0);
    // Make sure the buffer is null-terminated
    state.buff[bytes_read] = '\0';
    if (bytes_read < 0) {
      log_error("recv() failed: %s", strerror(errno));
      goto free_ctx;
    }
    if (bytes_read == 0) {
      break;
    }

    state.buff_size = bytes_read;
    log_trace("Received %ld bytes", bytes_read);
    log_trace("Request:\n%s", state.buff);
    int res;
    char *saveptr;
    if ((res = parse_request(ctx, &state, &saveptr)) < 0) {
      goto free_ctx;
    } else if (res == 1) {
      break; // Done parsing, no more data in this request
    } else if (res == 0 && state.state == BODY) {
      // Haven't implemented body parsing yet
      break;
    }
  }

  log_debug("Method: %d", ctx->method);
  log_debug("Path: %s", ctx->path);
  void *item;
  size_t iter = 0;
  while (hashmap_iter(ctx->query_params, &iter, &item)) {
    struct surv_kv *kv = (struct surv_kv *)item;
    log_debug("Param: %s:%s", kv->key, kv->value);
  }
  iter = 0;
  item = NULL;
  while (hashmap_iter(ctx->headers, &iter, &item)) {
    struct surv_kv *kv = (struct surv_kv *)item;
    log_debug("Header: %s:%s", kv->key, kv->value);
  }
  log_debug("Content: %s", ctx->body);

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
    hashmap_free(ctx->headers);
  case VERSION:
  case PATH:
    free(ctx->path);
    hashmap_free(ctx->query_params);
  default:
    free(ctx);
  }
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
  log_debug("socket() succeeded. sockfd=%d", sockfd);

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
  log_debug("bind() succeeded");

  if (listen(sockfd, server->backlog) < 0) {
    log_error("listen() failed: %s", strerror(errno));
    close(sockfd);
    return SURV_ERR_LISTEN;
  }
  log_debug("listen() succeeded");
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
  log_debug("Closing sockfd=%d", sockfd);
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
