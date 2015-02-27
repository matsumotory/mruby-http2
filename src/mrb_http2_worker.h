/*
// mrb_http2_worker.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_WORKER_H
#define MRB_HTTP2_WORKER_H

#include "mruby.h"

typedef struct {

  // the number of complete request per child
  // MAX 18446744073709551615
  uint64_t stream_requests_per_worker;
  uint64_t session_requests_per_worker;

} mrb_http2_worker_t;

mrb_http2_worker_t *mrb_http2_worker_init(mrb_state *);
void mrb_http2_worker_free(mrb_state *mrb, mrb_http2_worker_t *);

#endif
