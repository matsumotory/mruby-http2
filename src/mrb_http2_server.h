/*
// mrb_http2_server.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_SERVER_H
#define MRB_HTTP2_SERVER_H

#include "mruby.h"
#include "mrb_http2_config.h"
#include "mrb_http2_worker.h"

#define MRB_HTTP2_READ_LENGTH_MAX ((1 << 16) - 1)

typedef struct {
  const char *service;
  mrb_value args;
  mrb_http2_config_t *config;
  mrb_state *mrb;

  // callback Ruby block hash table
  mrb_value cb_hash;

  mrb_http2_worker_t *worker;
} mrb_http2_server_t;

void mrb_http2_server_class_init(mrb_state *mrb, struct RClass *http2);

#endif
