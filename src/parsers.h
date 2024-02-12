#ifndef PARSERS_H
#define PARSERS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "surv.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

struct parse_state {
  enum { METHOD, PATH, VERSION, HEADER, BODY, DONE } state;
  char *buff;
  size_t buff_size;
  char *carry;

  char next_delim;

  char *saveptr;
};

int parse_request(struct surv_http_context *ctx, struct parse_state *state);

char *strtok_r_nullable(char *str, const char delim, char **saveptr,
                        int *reached_delim);

#ifdef __cplusplus
}
#endif
#endif // PARSERS_H
