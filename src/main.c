#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"

#define ADDRESS (127 << 24 | 1)
#define MAX_PENDING 5
#define PORT 8080

struct client_info {
  int sockfd;
  struct sockaddr_in addr;
};

int sockfd = -1;

void addr_to_string(unsigned int addr, char *buff, size_t buff_size) {
  snprintf(buff, buff_size, "%d.%d.%d.%d", ((addr & 0xFF000000) >> 24),
           ((addr & 0x00FF0000) >> 16), ((addr & 0x0000FF00) >> 8),
           (addr & 0x000000FF));
}

void handle_client(void *client_info) {
  struct client_info *info = (struct client_info *)client_info;

  char longBuff[4096];
  read(info->sockfd, longBuff, sizeof(longBuff));
  log_info("Received %s", longBuff);

  char content[] = "<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Test</h1></body></html>";
  char msg[] = "HTTP/1.1 200 OK\r\nContent-Length: 86\r\n\r\n";
  size_t len = strlen(msg) + strlen(content) + 1;
  char *response = malloc(len);
  strcpy(response, msg);
  strcat(response, content);
  write(info->sockfd, response, len - 1);
  free(response);

  char addr_str[16];
  addr_to_string(ntohl(info->addr.sin_addr.s_addr), addr_str,
                 sizeof(addr_str));
  log_info("Done serving client %s:%d exiting thread",
            addr_str,
            ntohs(info->addr.sin_port));
  close(info->sockfd);
  free(client_info);
}

void sigint_handler(int signum) {
  log_info("Received SIGINT. Exiting...");
  if (sockfd != -1) {
    log_info("Closing sockfd=%d", sockfd);
    close(sockfd);
  }
  exit(1);
}

void log_client_connection(struct sockaddr_in *client) {
  char client_addr_str[16];
  addr_to_string(ntohl(client->sin_addr.s_addr), client_addr_str,
                 sizeof(client_addr_str));
  log_info("accept() succeeded. Connection from %s:%d", client_addr_str,
           ntohs(client->sin_port));
}

int main(int argc, char *argv[]) {
  signal(SIGINT, sigint_handler);
  sockfd = socket(AF_INET, SOCK_STREAM, 6);
  if (sockfd < 0) {
    log_error("socket() failed: %s", strerror(errno));
    return 1;
  }
  log_info("socket() succeeded. sockfd=%d", sockfd);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = htonl(ADDRESS);

  if (bind(sockfd, (void *)&addr, sizeof(addr)) < 0) {
    log_error("bind() failed: %s", strerror(errno));
    close(sockfd);
    return 1;
  }
  log_info("bind() succeeded");

  if (listen(sockfd, MAX_PENDING) < 0) {
    log_error("listen() failed: %s", strerror(errno));
    close(sockfd);
    return 1;
  }
  char addr_str[16];
  addr_to_string(ADDRESS, addr_str, sizeof(addr_str));
  log_info("listen() succeeded. Listening on %s:%d", addr_str, PORT);

  for (;;) {
    struct client_info *info = malloc(sizeof(struct client_info));
    socklen_t client_addr_len = sizeof(info->addr);

    int connfd = accept(sockfd, (void *)&info->addr, &client_addr_len);
    if (connfd < 0) {
      log_error("accept() failed: %s. Listening for other connections...",
                strerror(errno));
      free(info);
      continue;
    }
    log_client_connection(&info->addr);
    info->sockfd = connfd;

    pthread_t thread;
    pthread_create(&thread, NULL, (void *)handle_client, info);
    pthread_detach(thread);
  }

  return 0;
}
