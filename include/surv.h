#ifndef SURV_H
#define SURV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/socket.h>

#include "hashmap.h"

// Callback function type for HTTP methods. These should be registered
// with the surv_register_* functions.
typedef struct surv_http_response* (*surv_http_handler)(void *context);

struct surv_sock_client {
  int client_sockfd;
  struct sockaddr addr;
};

// Context for HTTP requests. This will be passed to the handler
// functions.
struct surv_http_context {
  struct surv_sock_client *client;
  enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
  } method;
  char *path;
  struct hashmap* headers;
  struct hashmap* query_params;
  char *body;
  size_t body_len;
};

// Response to an HTTP request that will be sent back to the client.
// TODO: Add headers
struct surv_http_response {
  int status;
  char *body;
  size_t body_len;
};

// Return values for surv_setup that indicate where
// the error occurred. A valid socket file descriptor (greater than 0)
// will be returned on success. Otherwise, a negative value will be
// returned and errno will be set.
enum surv_setup_err {
  SURV_ERR_SOCKET = -3,
  SURV_ERR_BIND = -2,
  SURV_ERR_LISTEN = -1,
};

struct surv_server {
  in_addr_t address;
  in_port_t port;
  unsigned int backlog;
};

void surv_addr_to_str(const struct sockaddr *addr, char *str, size_t len);

int surv_setup(struct surv_server *server);

// Covers 90% of use cases. Doing these first
int surv_register_get();
int surv_register_post();
int surv_register_put();
int surv_register_delete();
int surv_register_patch();

void surv_run();

int surv_close();

#ifdef __cplusplus
}
#endif
#endif // SURV_H
