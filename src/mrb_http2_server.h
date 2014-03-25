/*
// mrb_http2_server.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_SERVER_H
#define MRB_HTTP2_SERVER_H

#include "mrb_http2_request.h"

typedef struct {
  // set callbacked block at map_to_storage
  const char *map_to_strage_cb;

  const char *logging_cb;

} mruby_cb_list;

typedef struct {
  unsigned int daemon;
  unsigned int debug;
  unsigned int tls;
  unsigned int callback;
  const char *key;
  const char *cert;
  const char *service;
  const char *document_root;
  const char *server_name;
  mruby_cb_list *cb_list;
} mrb_http2_config_t;

typedef struct {
  const char *service;
  mrb_value args;
  mrb_http2_config_t *config;
  mrb_state *mrb;

  // callback Ruby block hash table
  mrb_value cb_hash;
} mrb_http2_server_t;

typedef struct {
  mrb_http2_server_t *s;
  mrb_http2_request_rec *r;
} mrb_http2_data_t;

void mrb_http2_server_class_init(mrb_state *mrb, struct RClass *http2);

#endif
