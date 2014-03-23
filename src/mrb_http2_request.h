/*
// mrb_http2_request.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_REQUEST_H
#define MRB_HTTP2_REGUEST_H

#include <sys/types.h> 
#include <sys/stat.h> 
#include <unistd.h>

typedef struct {
  // request uri
  char *uri;

  // filename is mapped from uri
  char *filename;

  // file stat infomation from fstat
  struct stat *finfo;

} mrb_http2_request_rec;

#endif
