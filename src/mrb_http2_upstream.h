/*
// mrb_http2_upstream.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_UPSTREAM_H
#define MRB_HTTP2_UPSTREAM_H

typedef enum {
  MRB_HTTP_PROXY_REVERSE,
  MRB_HTTP_PROXY_NONE
} upstream_type;

typedef struct {
  // upstrema type
  upstream_type type;

  // upstream server
  char *upstream;

  // upstream url
  char *url;

} mrb_http2_upstream;

#endif
