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

  unsigned int timeout;

} mrb_http2_upstream;

#endif
