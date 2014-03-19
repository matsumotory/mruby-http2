/*
** mrb_http2 - http2 class for mruby
**
** Copyright (c) mod_mruby developers 2012-
**
** Permission is hereby granted, free of charge, to any person obtaining
** a copy of this software and associated documentation files (the
** "Software"), to deal in the Software without restriction, including
** without limitation the rights to use, copy, modify, merge, publish,
** distribute, sublicense, and/or sell copies of the Software, and to
** permit persons to whom the Software is furnished to do so, subject to
** the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
** SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**
** [ MIT license: http://www.opensource.org/licenses/mit-license.php ]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

enum {
  IO_NONE,
  WANT_READ,
  WANT_WRITE
};

#define TRACER printf("%s:%d\n", __func__, __LINE__)
#define MAKE_NV(NAME, VALUE)                                           \
  {(uint8_t*)NAME, (uint8_t*)VALUE,                                    \
    (uint16_t)(sizeof(NAME) - 1), (uint16_t)(sizeof(VALUE) - 1) }

#define MAKE_NV_CS(NAME, VALUE)                                        \
  {(uint8_t*)NAME, (uint8_t*)VALUE,                                    \
    (uint16_t)(sizeof(NAME) - 1), (uint16_t)(strlen(VALUE)) }

typedef struct {
  SSL_CTX *ssl_ctx;
  struct event_base *evbase;
} app_context_t;

typedef struct {
  const char *service;
  app_context_t app_ctx;
} mrb_http2_server_t;

typedef struct {
  struct mrb_http2_conn_t *conn;
  struct mrb_http2_request_t *req;
  struct mrb_http2_uri_t *uri;

  // HTTP2::Server class only
  mrb_http2_server_t *server;
} mrb_http2_context_t;

struct mrb_http2_conn_t {
  SSL *ssl;
  nghttp2_session *session;
  int want_io;
  mrb_state *mrb;
  mrb_value response;
  mrb_value cb_block_hash;
};

struct mrb_http2_request_t {
  char *host;
  uint16_t port;
  char *path;
  char *hostport;
  int32_t stream_id;
  nghttp2_gzip *inflater;
};

struct mrb_http2_uri_t {
  const char *host;
  size_t hostlen;
  uint16_t port;
  const char *path;
  size_t pathlen;
  const char *hostport;
  size_t hostportlen;
};

static char CONTENT_LENGTH[] = "content-encoding";
static size_t CONTENT_LENGTH_LEN = sizeof(CONTENT_LENGTH) - 1;
static char GZIP[] = "gzip";
static size_t GZIP_LEN = sizeof(GZIP) - 1;
static pthread_mutex_t mutex;

static void mrb_http2_request_free(mrb_state *mrb, struct mrb_http2_request_t *req)
{
  free(req->host);
  free(req->path);
  free(req->hostport);
  nghttp2_gzip_inflate_del(req->inflater);
}

static void mrb_http2_context_free(mrb_state *mrb, void *p)
{
  TRACER;
  mrb_http2_context_t *ctx = (mrb_http2_context_t *)p;
  mrb_http2_request_free(mrb, ctx->req);
  TRACER;
  if (ctx->server) {
    TRACER;
    event_base_free(ctx->server->app_ctx.evbase);
    SSL_CTX_free(ctx->server->app_ctx.ssl_ctx);
  }
  pthread_mutex_destroy(&mutex);
}

static const struct mrb_data_type mrb_http2_context_type = {
  "mrb_http2_context_t", mrb_http2_context_free,
};

static char *strcopy(const char *s, size_t len)
{
  char *dst;
  dst = malloc(len+1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

//TODO: use mruby-http
static int parse_uri(struct mrb_http2_uri_t *res, const char *uri)
{
  size_t len, i, offset;
  int ipv6addr = 0;
  memset(res, 0, sizeof(struct mrb_http2_uri_t));
  len = strlen(uri);
  if(len < 9 || memcmp("https://", uri, 8) != 0) {
    return -1;
  }
  offset = 8;
  res->host = res->hostport = &uri[offset];
  res->hostlen = 0;
  if(uri[offset] == '[') {
    ++offset;
    ++res->host;
    ipv6addr = 1;
    for(i = offset; i < len; ++i) {
      if(uri[i] == ']') {
        res->hostlen = i-offset;
        offset = i+1;
        break;
      }
    }
  } else {
    const char delims[] = ":/?#";
    for(i = offset; i < len; ++i) {
      if(strchr(delims, uri[i]) != NULL) {
        break;
      }
    }
    res->hostlen = i-offset;
    offset = i;
  }
  if(res->hostlen == 0) {
    return -1;
  }
  res->port = 443;
  if(offset < len) {
    if(uri[offset] == ':') {
      const char delims[] = "/?#";
      int port = 0;
      ++offset;
      for(i = offset; i < len; ++i) {
        if(strchr(delims, uri[i]) != NULL) {
          break;
        }
        if('0' <= uri[i] && uri[i] <= '9') {
          port *= 10;
          port += uri[i]-'0';
          if(port > 65535) {
            return -1;
          }
        } else {
          return -1;
        }
      }
      if(port == 0) {
        return -1;
      }
      offset = i;
      res->port = port;
    }
  }
  res->hostportlen = uri+offset+ipv6addr-res->host;
  for(i = offset; i < len; ++i) {
    if(uri[i] == '#') {
      break;
    }
  }
  if(i-offset == 0) {
    res->path = "/";
    res->pathlen = 1;
  } else {
    res->path = &uri[offset];
    res->pathlen = i-offset;
  }
  return 0;
}


static void mrb_http2_check_gzip(mrb_state *mrb, struct mrb_http2_request_t *req, nghttp2_nv *nva, size_t nvlen)
{
  size_t i;
  if(req->inflater) {
    return;
  }
  for(i = 0; i < nvlen; ++i) {
    if(CONTENT_LENGTH_LEN == nva[i].namelen &&
       memcmp(CONTENT_LENGTH, nva[i].name, nva[i].namelen) == 0 &&
       GZIP_LEN == nva[i].valuelen &&
       memcmp(GZIP, nva[i].value, nva[i].valuelen) == 0) {
      int rv;
      rv = nghttp2_gzip_inflate_new(&req->inflater);
      if(rv != 0) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "Can't allocate inflate stream.");
      }
      break;
    }
  }
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
  struct mrb_http2_conn_t *conn;
  ssize_t rv;
  conn = (struct mrb_http2_conn_t*)user_data;
  conn->want_io = IO_NONE;
  ERR_clear_error();
  rv = SSL_write(conn->ssl, data, length);
  if(rv < 0) {
    int err = SSL_get_error(conn->ssl, rv);
    if(err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      conn->want_io = (err == SSL_ERROR_WANT_READ ?
                             WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  if (!mrb_nil_p(conn->cb_block_hash)) {
    mrb_value cb_block = mrb_hash_get(conn->mrb, conn->cb_block_hash, mrb_str_new_cstr(conn->mrb, "send_callback"));
    if (!mrb_nil_p(cb_block)) {
      mrb_yield_argv(conn->mrb, cb_block, 0, NULL);
    }
  }
  return rv;
}

static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data)
{
  struct mrb_http2_conn_t *conn;
  ssize_t rv;
  conn = (struct mrb_http2_conn_t*)user_data;
  conn->want_io = IO_NONE;
  ERR_clear_error();
  rv = SSL_read(conn->ssl, buf, length);
  if(rv < 0) {
    int err = SSL_get_error(conn->ssl, rv);
    if(err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      conn->want_io = (err == SSL_ERROR_WANT_READ ?
                             WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else if(rv == 0) {
    rv = NGHTTP2_ERR_EOF;
  }
  if (!mrb_nil_p(conn->cb_block_hash)) {
    mrb_value cb_block = mrb_hash_get(conn->mrb, conn->cb_block_hash, mrb_str_new_cstr(conn->mrb, "recv_callback"));
    if (!mrb_nil_p(cb_block)) {
      mrb_yield_argv(conn->mrb, cb_block, 0, NULL);
    }
  }
  return rv;
}

static int before_frame_send_callback(nghttp2_session *session, 
    const nghttp2_frame *frame, void *user_data)
{
  struct mrb_http2_conn_t *conn;
  conn = (struct mrb_http2_conn_t*)user_data;

  if(frame->hd.type == NGHTTP2_HEADERS &&
     frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    struct mrb_http2_request_t *req;
    int32_t stream_id = frame->hd.stream_id;
    req = nghttp2_session_get_stream_user_data(session, stream_id);
    if(req && req->stream_id == -1) {
      req->stream_id = stream_id;
      mrb_hash_set(conn->mrb, conn->response, 
          mrb_symbol_value(mrb_intern_cstr(conn->mrb, "stream_id")), mrb_fixnum_value(stream_id));
    }
  }
  if (!mrb_nil_p(conn->cb_block_hash)) {
    mrb_value cb_block = mrb_hash_get(conn->mrb, conn->cb_block_hash, 
        mrb_str_new_cstr(conn->mrb, "before_frame_send_callback"));
    if (!mrb_nil_p(cb_block)) {
      mrb_yield_argv(conn->mrb, cb_block, 0, NULL);
    }
  }
  return 0;
}

static int on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  struct mrb_http2_conn_t *conn;
  mrb_value req_headers;
  size_t i;
  conn = (struct mrb_http2_conn_t*)user_data;
  switch(frame->hd.type) {
  case NGHTTP2_HEADERS:
    if(nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
      const nghttp2_nv *nva = frame->headers.nva;
      req_headers = mrb_hash_new(conn->mrb);
      for(i = 0; i < frame->headers.nvlen; ++i) {
        mrb_hash_set(conn->mrb, req_headers, 
            mrb_str_new(conn->mrb, (char *)nva[i].name, nva[i].namelen), 
            mrb_str_new(conn->mrb, (char *)nva[i].value, nva[i].valuelen));
      }
      mrb_hash_set(conn->mrb, conn->response, 
          mrb_symbol_value(mrb_intern_cstr(conn->mrb, "request_headers")), req_headers);
    }
    break;
  case NGHTTP2_RST_STREAM:
    mrb_hash_set(conn->mrb, conn->response, 
        mrb_symbol_value(mrb_intern_cstr(conn->mrb, "frame_send_header_rst_stream")), mrb_true_value());
    break;
  case NGHTTP2_GOAWAY:
    mrb_hash_set(conn->mrb, conn->response, 
        mrb_symbol_value(mrb_intern_cstr(conn->mrb, "frame_send_header_goway")), mrb_true_value());
    break;
  }
  if (!mrb_nil_p(conn->cb_block_hash)) {
    mrb_value cb_block = mrb_hash_get(conn->mrb, conn->cb_block_hash, 
        mrb_str_new_cstr(conn->mrb, "on_frame_send_callback"));
    if (!mrb_nil_p(cb_block)) {
      mrb_yield_argv(conn->mrb, cb_block, 0, NULL);
    }
  }
  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
  struct mrb_http2_conn_t *conn;
  conn = (struct mrb_http2_conn_t*)user_data;

  switch(frame->hd.type) {
  case NGHTTP2_HEADERS:
    if(frame->headers.cat != NGHTTP2_HCAT_RESPONSE &&
       frame->headers.cat != NGHTTP2_HCAT_PUSH_RESPONSE) {
      break;
    }
    //TRACER;
    break;
  case NGHTTP2_RST_STREAM:
  //TRACER;
    mrb_hash_set(conn->mrb, conn->response, 
        mrb_symbol_value(mrb_intern_cstr(conn->mrb, "frame_recv_header_rst_stream")), mrb_true_value());
    break;
  case NGHTTP2_GOAWAY:
  //TRACER;
    mrb_hash_set(conn->mrb, conn->response, 
        mrb_symbol_value(mrb_intern_cstr(conn->mrb, "frame_recv_header_goway")), mrb_true_value());
    break;
  }
  //TRACER;
  //mrb_p(conn->mrb, conn->cb_block_hash);
  //conn->cb_block_hash = mrb_nil_value();
  //if (!mrb_nil_p(conn->cb_block_hash)) {
  //TRACER;
  //  mrb_value cb_block = mrb_hash_get(conn->mrb, conn->cb_block_hash, 
  //                          mrb_str_new_lit(conn->mrb, "on_frame_recv_callback"));
  //  if (!mrb_nil_p(cb_block)) {
  //    mrb_yield_argv(conn->mrb, cb_block, 0, NULL);
  //  }
  //}
  return 0;
}

//static int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
static int on_header_callback(nghttp2_session *session,
                       const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen,
                       void *user_data)

{
  struct mrb_http2_conn_t *conn;
  //mrb_value reply_headers;
  size_t i;
  struct mrb_http2_request_t *req;
  conn = (struct mrb_http2_conn_t*)user_data;
  switch(frame->hd.type) {
  case NGHTTP2_HEADERS:
    if(frame->headers.cat != NGHTTP2_HCAT_RESPONSE &&
       frame->headers.cat != NGHTTP2_HCAT_PUSH_RESPONSE) {
      break;
    }
    //TRACER;
    req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if(req) {
      //TRACER;
      const nghttp2_nv *nva = frame->headers.nva;
      //printf("nvlen:%d\n", frame->headers.nvlen);
      printf("RESPONSE_HEADERS: %s:%s\n", strcopy((const char*)name, namelen), strcopy((const char*)value, valuelen));
      //printf("%s:%s\n", (char *)nva[1].name, (char *)nva[1].value);
      mrb_http2_check_gzip(conn->mrb, req, frame->headers.nva, frame->headers.nvlen);
      //reply_headers = mrb_hash_new(conn->mrb);
      for(i = 0; i < frame->headers.nvlen; ++i) {
        printf("%s:%s\n", (char *)nva[i].name, (char *)nva[i].value);
        //TRACER;
        //mrb_hash_set(conn->mrb, reply_headers
        //    , mrb_str_new(conn->mrb, (char *)nva[i].name, nva[i].namelen)
        //    , mrb_str_new(conn->mrb, (char *)nva[i].value, nva[i].valuelen));
      }
      //mrb_hash_set(conn->mrb, conn->response, 
      //    mrb_symbol_value(mrb_intern_cstr(conn->mrb, "response_headers")), reply_headers);
      //mrb_hash_set(conn->mrb, conn->response, mrb_symbol_value(mrb_intern_cstr(conn->mrb, "response_headers")), mrb_str_new_lit(conn->mrb, "hoge"));
    }
    break;
  case NGHTTP2_GOAWAY:
    mrb_hash_set(conn->mrb, conn->response, 
        mrb_symbol_value(mrb_intern_cstr(conn->mrb, "on_header_goway")), mrb_true_value());
    break;
  }
  //if (!mrb_nil_p(conn->cb_block_hash)) {
  //  mrb_value cb_block = mrb_hash_get(conn->mrb, conn->cb_block_hash, mrb_str_new_cstr(conn->mrb, "on_header_callback"));
  //  if (!mrb_nil_p(cb_block)) {
  //    mrb_yield_argv(conn->mrb, cb_block, 0, NULL);
  //  }
  //}
  return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code, void *user_data)
{
  struct mrb_http2_conn_t *conn;
  struct mrb_http2_request_t *req;
  mrb_state *mrb;

  conn = (struct mrb_http2_conn_t*)user_data;
  mrb = conn->mrb;
  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if(req) {
    int rv;
    rv = nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE, NGHTTP2_NO_ERROR, NULL, 0);
    if(rv != 0) {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "nghttp2_submit_goaway: %S", mrb_fixnum_value(rv));
    }
  }
  if (!mrb_nil_p(conn->cb_block_hash)) {
    mrb_value cb_block = mrb_hash_get(conn->mrb, conn->cb_block_hash, mrb_str_new_cstr(conn->mrb, "on_stream_close_callback"));
    if (!mrb_nil_p(cb_block)) {
      mrb_yield_argv(conn->mrb, cb_block, 0, NULL);
    }
  }
  return 0;
}

#define MAX_OUTLEN 4096

static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
  struct mrb_http2_conn_t *conn;
  struct mrb_http2_request_t *req;
  char *body;
  conn = (struct mrb_http2_conn_t*)user_data;
  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if(req) {
    mrb_value body_len;
    mrb_value body_data;

    mrb_hash_set(conn->mrb, conn->response, mrb_symbol_value(mrb_intern_cstr(conn->mrb, "recieve_bytes")), mrb_float_value(conn->mrb, (float)len));
    body = NULL;
    if(req->inflater) {
      while(len > 0) {
        uint8_t out[MAX_OUTLEN];
        size_t outlen = MAX_OUTLEN;
        size_t tlen = len;
        int rv;
        char *merge_body;
        rv = nghttp2_gzip_inflate(req->inflater, out, &outlen, data, &tlen);
        if(rv == -1) {
          nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_INTERNAL_ERROR);
          break;
        }
        merge_body = strcopy((const char *)out, outlen);
        if (body == NULL) {
          body = merge_body;
        }
        else {
          strcat(body, merge_body);
        }
        data += tlen;
        len -= tlen;
      }
    } else {
      body = strcopy((char *)data, len);
    }
    body_data = mrb_hash_get(conn->mrb, conn->response, mrb_symbol_value(mrb_intern_cstr(conn->mrb, "body")));
    if (!mrb_nil_p(body_data)) {
      mrb_str_concat(conn->mrb, body_data, mrb_str_new_cstr(conn->mrb, (char *)body));
    }
    else {
      body_data = mrb_str_new_cstr(conn->mrb, (char *)body);
    }
    body_len = mrb_fixnum_value(strlen(body));
    mrb_hash_set(conn->mrb, conn->response, mrb_symbol_value(mrb_intern_cstr(conn->mrb, "body")), body_data);
    mrb_hash_set(conn->mrb, conn->response, mrb_symbol_value(mrb_intern_cstr(conn->mrb, "body_length")), body_len);
  }
  if (!mrb_nil_p(conn->cb_block_hash)) {
    mrb_value cb_block = mrb_hash_get(conn->mrb, conn->cb_block_hash, mrb_str_new_cstr(conn->mrb, "on_data_chunk_recv_callback"));
    if (!mrb_nil_p(cb_block)) {
      pthread_mutex_lock(&mutex);
      mrb_yield_argv(conn->mrb, cb_block, 0, NULL);
      pthread_mutex_unlock(&mutex);
    }
  }
  return 0;
}

static void mrb_http2_setup_nghttp2_callbacks(mrb_state *mrb, nghttp2_session_callbacks *callbacks)
{
  memset(callbacks, 0, sizeof(nghttp2_session_callbacks));
  callbacks->send_callback = send_callback;
  callbacks->recv_callback = recv_callback;
  callbacks->before_frame_send_callback = before_frame_send_callback;
  callbacks->on_frame_send_callback = on_frame_send_callback;
  callbacks->on_frame_recv_callback = on_frame_recv_callback;
  callbacks->on_stream_close_callback = on_stream_close_callback;
  callbacks->on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks->on_header_callback = on_header_callback;
}

static int select_next_proto_cb(SSL* ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
  int rv;
  rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
  if(rv <= 0) {
    fprintf(stderr, "FATAL: %s\n", "Server did not advertise HTTP/2.0 protocol");
    exit(EXIT_FAILURE);
  }
  return SSL_TLSEXT_ERR_OK;
}

static void mrb_http2_init_ssl_ctx(mrb_state *mrb, SSL_CTX *ssl_ctx)
{
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
}

static void mrb_http2_ssl_handshake(mrb_state *mrb, SSL *ssl, int fd)
{
  int rv;
  if(SSL_set_fd(ssl, fd) == 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_set_fd: %S", mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
  ERR_clear_error();
  rv = SSL_connect(ssl);
  if(rv <= 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_connect: %S", mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
}

static int mrb_http2_connect_to(mrb_state *mrb, const char *host, uint16_t port)
{ 
  struct addrinfo hints;
  int fd = -1;
  int rv;
  char service[NI_MAXSERV];
  struct addrinfo *res, *rp;
  snprintf(service, sizeof(service), "%u", port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  rv = getaddrinfo(host, service, &hints, &res);
  if(rv != 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "getaddrinfo: %S", mrb_str_new_cstr(mrb, gai_strerror(rv)));
  }
  for(rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if(fd == -1) {
      continue;
    }
    while((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
          errno == EINTR);
    if(rv == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

static void mrb_http2_make_non_block(mrb_state *mrb, int fd)
{ 
  int flags, rv;
  while((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
  if(flags == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "fcntl: %S", mrb_str_new_cstr(mrb, strerror(errno)));
  }
  while((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
  if(rv == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "fcntl: %S", mrb_str_new_cstr(mrb, strerror(errno)));
  }
}

static void mrb_http2_set_tcp_nodelay(mrb_state *mrb, int fd)
{ 
  int val = 1;
  int rv;
  rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
  if(rv == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "setsockopt: %S", mrb_str_new_cstr(mrb, strerror(errno)));
  }
}

static void mrb_http2_ctl_poll(mrb_state *mrb, struct pollfd *pollfd, struct mrb_http2_conn_t *conn)
{
  pollfd->events = 0;
  if(nghttp2_session_want_read(conn->session) ||
     conn->want_io == WANT_READ) {
    pollfd->events |= POLLIN;
  }
  if(nghttp2_session_want_write(conn->session) ||
     conn->want_io == WANT_WRITE) {
    pollfd->events |= POLLOUT;
  }
}

static void mrb_http2_submit_request(mrb_state *mrb, struct mrb_http2_conn_t *conn, struct mrb_http2_request_t *req)
{
  int pri = 0;
  int rv;
  const nghttp2_nv nva[] = {
    MAKE_NV(":method", "GET"),
    MAKE_NV_CS(":path", req->path),
    MAKE_NV(":scheme", "https"),
    MAKE_NV_CS(":authority", req->hostport),
    MAKE_NV("accept", "*/*"),
    MAKE_NV("accept-encoding", GZIP),
    MAKE_NV("user-agent", MRUBY_HTTP2_NAME"/"MRUBY_HTTP2_VERSION)
  };
  rv = nghttp2_submit_request(conn->session, pri, nva, sizeof(nva)/sizeof(nva[0]), NULL, req);
  if(rv != 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "http2_submit_request: %S", mrb_fixnum_value(rv));
  }
}

static void mrb_http2_exec_io(mrb_state *mrb, struct mrb_http2_conn_t *conn)
{
  int rv;
  rv = nghttp2_session_recv(conn->session);
  if(rv != 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "nghttp2_session_recv: %S", mrb_fixnum_value(rv));
  }
  rv = nghttp2_session_send(conn->session);
  if(rv != 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "nghttp2_session_send: %S", mrb_fixnum_value(rv));
  }
}

static void mrb_http2_request_init(mrb_state *mrb, struct mrb_http2_request_t *req, const struct mrb_http2_uri_t *uri)
{
  req->host = strcopy(uri->host, uri->hostlen);
  req->port = uri->port;
  req->path = strcopy(uri->path, uri->pathlen);
  req->hostport = strcopy(uri->hostport, uri->hostportlen);
  req->stream_id = -1;
  req->inflater = NULL;
}

static mrb_value mrb_http2_cb_block_hash_init(mrb_state *mrb)
{
  mrb_value hash = mrb_hash_new(mrb);
  mrb_hash_set(mrb, hash, mrb_str_new_cstr(mrb, "send_callback"), mrb_nil_value());
  mrb_hash_set(mrb, hash, mrb_str_new_cstr(mrb, "recv_callback"), mrb_nil_value());
  mrb_hash_set(mrb, hash, mrb_str_new_cstr(mrb, "before_frame_send_callback"), mrb_nil_value());
  mrb_hash_set(mrb, hash, mrb_str_new_cstr(mrb, "on_frame_send_callback"), mrb_nil_value());
  mrb_hash_set(mrb, hash, mrb_str_new_cstr(mrb, "on_frame_recv_callback"), mrb_nil_value());
  mrb_hash_set(mrb, hash, mrb_str_new_cstr(mrb, "on_stream_close_callback"), mrb_nil_value());
  mrb_hash_set(mrb, hash, mrb_str_new_cstr(mrb, "on_data_chunk_recv_callback"), mrb_nil_value());
  return hash;
}

static mrb_value mrb_http2_fetch_uri(mrb_state *mrb, const struct mrb_http2_uri_t *uri)
{
  nghttp2_session_callbacks callbacks;
  int fd;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  struct mrb_http2_request_t req;
  struct mrb_http2_conn_t conn;
  int rv;
  nfds_t npollfds = 1;
  struct pollfd pollfds[1];
  mrb_http2_request_init(mrb, &req, uri);

  mrb_http2_setup_nghttp2_callbacks(mrb, &callbacks);

  fd = mrb_http2_connect_to(mrb, req.host, req.port);
  if(fd == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Could not open file descriptor");
  }
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if(ssl_ctx == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_CTX_new: %S", mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
  mrb_http2_init_ssl_ctx(mrb, ssl_ctx);
  ssl = SSL_new(ssl_ctx);
  if(ssl == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_new: %S", mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
  mrb_http2_ssl_handshake(mrb, ssl, fd);

  conn.ssl = ssl;
  conn.want_io = IO_NONE;

  SSL_write(ssl, NGHTTP2_CLIENT_CONNECTION_HEADER, NGHTTP2_CLIENT_CONNECTION_HEADER_LEN);

  mrb_http2_make_non_block(mrb, fd);
  mrb_http2_set_tcp_nodelay(mrb, fd);
  conn.mrb = mrb;
  conn.response = mrb_hash_new(mrb);
  conn.cb_block_hash = mrb_nil_value();

  rv = nghttp2_session_client_new(&conn.session, &callbacks, &conn);
  if(rv != 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "nghttp2_session_client_new: %S", mrb_fixnum_value(rv));
  }

  mrb_http2_submit_request(mrb, &conn, &req);

  pollfds[0].fd = fd;
  mrb_http2_ctl_poll(mrb, pollfds, &conn);

  while(nghttp2_session_want_read(conn.session) || nghttp2_session_want_write(conn.session)) {
    int nfds = poll(pollfds, npollfds, -1);
    if(nfds == -1) {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "poll: %S", mrb_str_new_cstr(mrb, strerror(errno)));
    } 
    if(pollfds[0].revents & (POLLIN | POLLOUT)) {
      mrb_http2_exec_io(mrb, &conn);
    }
    if((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "connection error");
    }
    mrb_http2_ctl_poll(mrb, pollfds, &conn);
  }

  nghttp2_session_del(conn.session);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  shutdown(fd, SHUT_WR);
  close(fd);
  mrb_http2_request_free(mrb, &req);

  return conn.response;
}

static mrb_value mrb_http2_get_uri(mrb_state *mrb, mrb_http2_context_t *ctx)
{
  nghttp2_session_callbacks callbacks;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int rv;
  int fd;
  struct pollfd pollfds[1];
  nfds_t npollfds = 1;

  mrb_http2_setup_nghttp2_callbacks(mrb, &callbacks);

  fd = mrb_http2_connect_to(mrb, ctx->req->host, ctx->req->port);
  if(fd == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not open file descriptor: host \"%S\", port \"%S\"", mrb_str_new_cstr(mrb, ctx->req->host), mrb_fixnum_value(ctx->req->port));
  }
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if(ssl_ctx == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_CTX_new: %S", mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
  mrb_http2_init_ssl_ctx(mrb, ssl_ctx);
  ssl = SSL_new(ssl_ctx);
  if(ssl == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_new: %S", mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
  mrb_http2_ssl_handshake(mrb, ssl, fd);

  ctx->conn->ssl = ssl;
  ctx->conn->want_io = IO_NONE;

  SSL_write(ssl, NGHTTP2_CLIENT_CONNECTION_HEADER, NGHTTP2_CLIENT_CONNECTION_HEADER_LEN);

  mrb_http2_make_non_block(mrb, fd);
  mrb_http2_set_tcp_nodelay(mrb, fd);
  ctx->conn->mrb = mrb;
  rv = nghttp2_session_client_new(&ctx->conn->session, &callbacks, ctx->conn);
  if(rv != 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "nghttp2_session_client_new: %S", mrb_fixnum_value(rv));
  }

  mrb_http2_submit_request(mrb, ctx->conn, ctx->req);

  pollfds[0].fd = fd;
  mrb_http2_ctl_poll(mrb, pollfds, ctx->conn);

  while(nghttp2_session_want_read(ctx->conn->session) || nghttp2_session_want_write(ctx->conn->session)) {
    int nfds = poll(pollfds, npollfds, -1);
    if(nfds == -1) {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "poll: %S", mrb_str_new_cstr(mrb, strerror(errno)));
    } 
    if(pollfds[0].revents & (POLLIN | POLLOUT)) {
      mrb_http2_exec_io(mrb, ctx->conn);
    }
    if((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "connection error");
    }
    mrb_http2_ctl_poll(mrb, pollfds, ctx->conn);
  }

  nghttp2_session_del(ctx->conn->session);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  shutdown(fd, SHUT_WR);
  close(fd);
  mrb_http2_request_free(mrb, ctx->req);

  return ctx->conn->response;
}

static mrb_value mrb_http2_client_inst_get(mrb_state *mrb, mrb_value self)
{
  mrb_http2_context_t *ctx = DATA_PTR(self);
  return mrb_http2_get_uri(mrb, ctx);
}

static mrb_value mrb_http2_client_request(mrb_state *mrb, mrb_value self)
{
  mrb_http2_context_t *ctx = DATA_PTR(self);
  mrb_value block;

  mrb_get_args(mrb, "&", &block);
  mrb_yield_argv(mrb, block, 0, NULL);

  if(ctx->uri == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "not found uri data");
  }
  ctx->req = (struct mrb_http2_request_t *)mrb_malloc(mrb, sizeof(struct mrb_http2_request_t));
  mrb_http2_request_init(mrb, ctx->req, ctx->uri);

  return self;
}

static mrb_value mrb_http2_set_block_callback(mrb_state *mrb, mrb_value self, char *cb_type)
{
  mrb_http2_context_t *ctx = DATA_PTR(self);
  mrb_value cb_block;

  mrb_get_args(mrb, "&", &cb_block);
  mrb_hash_set(mrb, ctx->conn->cb_block_hash, mrb_str_new_cstr(mrb, cb_type), cb_block);

  return ctx->conn->cb_block_hash;
}

static mrb_value mrb_http2_set_send_callback(mrb_state *mrb, mrb_value self)
{
  return mrb_http2_set_block_callback(mrb, self, "send_callback");
}

static mrb_value mrb_http2_set_recv_callback(mrb_state *mrb, mrb_value self)
{
  return mrb_http2_set_block_callback(mrb, self, "recv_callback");
}

static mrb_value mrb_http2_set_before_frame_send_callback(mrb_state *mrb, mrb_value self)
{
  return mrb_http2_set_block_callback(mrb, self, "before_frame_send_callback");
}

static mrb_value mrb_http2_set_on_frame_send_callback(mrb_state *mrb, mrb_value self)
{
  return mrb_http2_set_block_callback(mrb, self, "on_frame_send_callback");
}

static mrb_value mrb_http2_set_on_frame_recv_callback(mrb_state *mrb, mrb_value self)
{
  return mrb_http2_set_block_callback(mrb, self, "on_frame_recv_callback");
}

static mrb_value mrb_http2_set_on_stream_close_callback(mrb_state *mrb, mrb_value self)
{
  return mrb_http2_set_block_callback(mrb, self, "on_stream_close_callback");
}

static mrb_value mrb_http2_set_on_data_chunk_recv_callback(mrb_state *mrb, mrb_value self)
{
  return mrb_http2_set_block_callback(mrb, self, "on_data_chunk_recv_callback");
}

static mrb_value mrb_http2_client_set_uri(mrb_state *mrb, mrb_value self)
{
  mrb_http2_context_t *ctx = DATA_PTR(self);
  int rv;
  char *uri;
  ctx->uri = (struct mrb_http2_uri_t *)mrb_malloc(mrb, sizeof(struct mrb_http2_uri_t));

  mrb_get_args(mrb, "z", &uri);
  rv = parse_uri(ctx->uri, uri);
  if(rv != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "parse_uri failed");
  }

  return self;
}

static mrb_value mrb_http2_client_init(mrb_state *mrb, mrb_value self)
{
  mrb_http2_context_t *ctx;
  struct sigaction act;

  pthread_mutex_init(&mutex, NULL);
  ctx = (mrb_http2_context_t *)DATA_PTR(self);
  if (ctx) {
      mrb_free(mrb, ctx);
  }
  DATA_TYPE(self) = &mrb_http2_context_type;
  DATA_PTR(self) = NULL;

  ctx = (mrb_http2_context_t *)mrb_malloc(mrb, sizeof(mrb_http2_context_t));
  ctx->uri = NULL;
  ctx->conn = (struct mrb_http2_conn_t *)mrb_malloc(mrb, sizeof(struct mrb_http2_conn_t));
  ctx->conn->mrb = mrb;
  ctx->conn->response = mrb_hash_new(mrb);
  ctx->conn->cb_block_hash = mrb_nil_value();
  DATA_PTR(self) = ctx;

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  SSL_load_error_strings();
  SSL_library_init();

  return self;
}

mrb_value mrb_http2_client_get(mrb_state *mrb, mrb_value self)
{
  char *uri;
  struct mrb_http2_uri_t uri_data;
  struct sigaction act;
  int rv;

  mrb_get_args(mrb, "z", &uri);
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  SSL_load_error_strings();
  SSL_library_init();

  rv = parse_uri(&uri_data, uri);
  if(rv != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "parse_uri failed");
  }
  return mrb_http2_fetch_uri(mrb, &uri_data);
}

//
//
// HTTP2::Server class
//
//
static unsigned char next_proto_list[256];
static size_t next_proto_list_len;

static int next_proto_cb(SSL *s, const unsigned char **data, unsigned int *len, 
    void *arg)
{
  *data = next_proto_list;
  *len = next_proto_list_len;
  return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX* mrb_create_ssl_ctx(mrb_state *mrb, const char *key_file, 
    const char *cert_file)
{
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  if(!ssl_ctx) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not create SSL/TLS context: %S", 
        mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
  SSL_CTX_set_options(ssl_ctx, 
      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION |
      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

  if(SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, 
        SSL_FILETYPE_PEM) != 1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not read private key file %S", 
        mrb_str_new_cstr(mrb, key_file));
  }
  if(SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not read certificate file %S", 
        mrb_str_new_cstr(mrb, cert_file));
  }

  next_proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
  memcpy(&next_proto_list[1], NGHTTP2_PROTO_VERSION_ID, 
      NGHTTP2_PROTO_VERSION_ID_LEN);
  next_proto_list_len = 1 + NGHTTP2_PROTO_VERSION_ID_LEN;

  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);
  return ssl_ctx;
}

static void init_app_context(app_context_t *app_ctx, SSL_CTX *ssl_ctx,
    struct event_base *evbase)
{
  memset(app_ctx, 0, sizeof(app_context_t));
  app_ctx->ssl_ctx = ssl_ctx;
  app_ctx->evbase = evbase;
}

static mrb_value mrb_http2_server_init(mrb_state *mrb, mrb_value self)
{
  mrb_http2_context_t *ctx;
  struct sigaction act;
  SSL_CTX *ssl_ctx;
  app_context_t app_ctx;
  struct event_base *evbase;
  mrb_value config;
  mrb_value port;
  char *service, *key_file, *cert_file;

  ctx = (mrb_http2_context_t *)mrb_malloc(mrb, sizeof(mrb_http2_context_t));
  ctx->uri = NULL;
  ctx->conn = (struct mrb_http2_conn_t *)mrb_malloc(mrb, sizeof(struct mrb_http2_conn_t));
  ctx->conn->mrb = mrb;
  ctx->conn->response = mrb_hash_new(mrb);
  ctx->conn->cb_block_hash = mrb_nil_value();

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);

  SSL_load_error_strings();
  SSL_library_init();

  mrb_get_args(mrb, "H", &config);
  port = mrb_hash_get(mrb, config, mrb_symbol_value(mrb_intern_lit(mrb, "port")));
  service = mrb_str_to_cstr(mrb, mrb_fixnum_to_str(mrb, port, 10));
  key_file = mrb_str_to_cstr(mrb, mrb_hash_get(mrb, config, mrb_symbol_value(mrb_intern_lit(mrb, "key"))));
  cert_file = mrb_str_to_cstr(mrb, mrb_hash_get(mrb, config, mrb_symbol_value(mrb_intern_lit(mrb, "crt"))));

  ssl_ctx = mrb_create_ssl_ctx(mrb, key_file, cert_file);
  evbase = event_base_new();
  init_app_context(&app_ctx, ssl_ctx, evbase);
  ctx->server = (mrb_http2_server_t *)mrb_malloc(mrb, sizeof(mrb_http2_server_t));
  ctx->server->service = service;
  ctx->server->app_ctx = app_ctx;

  DATA_TYPE(self) = &mrb_http2_context_type;
  DATA_PTR(self) = ctx;
  TRACER;

  return self;
}


void mrb_mruby_http2_gem_init(mrb_state *mrb)
{
  struct RClass *http2, *client, *server;

  http2 = mrb_define_module(mrb, "HTTP2");
  client = mrb_define_class_under(mrb, http2, "Client", mrb->object_class);
  server = mrb_define_class_under(mrb, http2, "Server", mrb->object_class);

  mrb_define_method(mrb, client, "initialize", mrb_http2_client_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, client, "request", mrb_http2_client_request, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, client, "inst_get", mrb_http2_client_inst_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, client, "uri=", mrb_http2_client_set_uri, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, client, "send_callback", mrb_http2_set_send_callback, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, client, "recv_callback", mrb_http2_set_recv_callback, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, client, "before_frame_send_callback", mrb_http2_set_before_frame_send_callback, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, client, "on_frame_send_callback", mrb_http2_set_on_frame_send_callback, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, client, "on_frame_recv_callback", mrb_http2_set_on_frame_recv_callback, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, client, "on_stream_close_callback", mrb_http2_set_on_stream_close_callback, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, client, "on_data_chunk_recv_callback", mrb_http2_set_on_data_chunk_recv_callback, MRB_ARGS_REQ(1));
  
  mrb_define_class_method(mrb, client, "http2_get", mrb_http2_client_get, MRB_ARGS_REQ(1));

  mrb_define_method(mrb, server, "initialize", mrb_http2_server_init, MRB_ARGS_REQ(1));
  //mrb_define_method(mrb, server, "run", mrb_http2_server_run, MRB_ARGS_NONE());

  DONE;
}

void mrb_mruby_http2_gem_final(mrb_state *mrb)
{
}

