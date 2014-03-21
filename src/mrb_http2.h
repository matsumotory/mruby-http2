/*
// mrb_http2.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_H
#define MRB_HTTP2_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <err.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <nghttp2/nghttp2.h>

#include "mruby.h"
#include "mruby/data.h"
#include "mruby/variable.h"
#include "mruby/array.h"
#include "mruby/hash.h"
#include "mruby/string.h"
#include "mruby/class.h"
#include "mrb_http2.h"
#include "mruby/numeric.h"

#define DONE mrb_gc_arena_restore(mrb, 0);
#define MRUBY_HTTP2_NAME "mruby-http2"
#define MRUBY_HTTP2_VERSION "0.0.1"
#define MRUBY_HTTP2_SERVER MRUBY_HTTP2_NAME "/" MRUBY_HTTP2_VERSION

#ifdef MRB_HTTP2_TRACER
#define TRACER printf("    >>>> %s:%d\n", __func__, __LINE__)
#else
#define TRACER 
#endif
#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)
#define MRB_HTTP2_CONFIG_ENABLED 1
#define MRB_HTTP2_CONFIG_DISABLED 0
#define ARRLEN(x) (sizeof(x)/sizeof(x[0]))
#define MAKE_NV(NAME, VALUE)                                           \
  {(uint8_t*)NAME, (uint8_t*)VALUE,                                    \
    (uint16_t)(sizeof(NAME) - 1), (uint16_t)(sizeof(VALUE) - 1) }
#define MAKE_NV_CS(NAME, VALUE)                                        \
  {(uint8_t*)NAME, (uint8_t*)VALUE,                                    \
    (uint16_t)(sizeof(NAME) - 1), (uint16_t)(strlen(VALUE)) }

char *strcopy(const char *s, size_t len);
void mrb_mruby_http2_gem_init(mrb_state *mrb);

#endif
