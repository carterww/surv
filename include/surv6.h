#ifndef SURV6_H
#define SURV6_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/socket.h>
#include <stdint.h>

struct surv_server_in6 {
  struct in6_addr address;
  in_port_t port;

  uint32_t flowinfo;
  uint32_t scope_id;
  
  unsigned int backlog;
};

#ifdef __cplusplus
}
#endif
#endif // SURV6_H
