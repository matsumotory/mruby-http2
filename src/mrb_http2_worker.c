#include "mrb_http2_worker.h"

mrb_http2_worker_t *mrb_http2_worker_init(mrb_state *mrb)
{
  mrb_http2_worker_t *worker =
      (mrb_http2_worker_t *)mrb_malloc(mrb, sizeof(mrb_http2_worker_t));

  worker->session_requests_per_worker = 0;
  worker->stream_requests_per_worker = 0;
  worker->connected_sessions = 0;
  worker->active_stream = 0;

  return worker;
}

void mrb_http2_worker_free(mrb_state *mrb, mrb_http2_worker_t *worker)
{
  mrb_free(mrb, worker);
}
