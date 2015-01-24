/*
// mrb_http2_data.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_DATA_H
#define MRB_HTTP2_DATA_H

#include "mrb_http2_request.h"
#include "mrb_http2_server.h"

typedef struct {
  mrb_http2_server_t *s;
  mrb_http2_request_rec *r;
} mrb_http2_data_t;

#endif
