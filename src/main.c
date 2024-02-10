#include "surv.h"

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"

#define LAN_ADDRESS (10 << 24 | 150 << 16 | 1 << 8 | 241)
#define LOCALHOST_ADDRESS (127 << 24 | 0 << 16 | 0 << 8 | 1)
#define BACKLOG 5
#define PORT 8080

void sigint_handler(int signum) {
  log_info("Received SIGINT. Exiting...");
  surv_close();
  exit(1);
}

int main(int argc, char *argv[]) {
  signal(SIGINT, sigint_handler);

  struct surv_server server = {
    .address = LOCALHOST_ADDRESS,
    .port = PORT,
    .backlog = BACKLOG,
  };

  int sockfd = surv_setup(&server);
  if (sockfd < 0) {
    return 1;
  }
  surv_run();

  surv_close();

  return 0;
}
