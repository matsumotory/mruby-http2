/*
// mrb_http2_upstream.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_UPSTREAM_H
#define MRB_HTTP2_UPSTREAM_H

#include "mruby.h"

typedef struct {
  // 127.0.0.1
  char *host;

  // 127.0.0.1:8080
  char *unparsed_host;

  // 8080
  int port;

  // upstream uri like "/css/base.css"
  char *uri;

  // connection timeout
  unsigned int timeout;

  // upstream protocol HTTP/1.1 or HTTP/1.0
  unsigned int proto_major;
  unsigned int proto_minor;

  unsigned int keepalive:1;
} mrb_http2_upstream;

#endif
