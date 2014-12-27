/*
// mrb_http2_server.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_SERVER_H
#define MRB_HTTP2_SERVER_H

#include "mrb_http2.h"
#include "mrb_http2_request.h"

// callback block symbol literal list
typedef struct {

  // callback block at a phase of mapping uri to filename
  const char *map_to_strage_cb;

  // callback block at a phase of creating content
  const char *content_cb;

  // callback block after send response
  const char *logging_cb;

} mruby_cb_list;

// mruby-http2 config parameter getting from HTTP2::Server#init
typedef struct {

  unsigned int daemon;
  unsigned int debug;
  unsigned int tls;
  unsigned int callback;

  // connection record option
  // default enabled and can use connection methods
  unsigned int connection_record;

  const char *key;
  const char *cert;
  const char *service;
  mrb_http2_str *document_root;

  // server response header
  const char *server_name;

  // server listen hostname
  const char *server_host;

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
