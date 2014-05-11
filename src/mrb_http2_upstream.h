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

  // response data
  char *data;                                                                        

  // response length
  size_t len;                                                                        

  // response header object
  mrb_value headers;

  // response body object
  mrb_value body;

  // response status code
  int status_code;

  // response status code
  uint64_t content_length;

} upstream_response;                                                                 

typedef struct {
  // upstrema type
  upstream_type type;

  // upstream server like "http://127.0.0.1:8080/"
  char *server;

  // upstream uri like "/css/base.css"
  char *uri;

  // response data from upstream server
  upstream_response *res;

} mrb_http2_upstream;

#endif
