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

  char *incomplete_header;
};

int parse_request(struct surv_http_context *ctx, struct parse_state *state);

#ifdef __cplusplus
}
#endif
#endif // PARSERS_H
