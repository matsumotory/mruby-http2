/* 
// mrb_http2_gzip.c - to provide http2 methods
// 
// See Copyright Notice in mrb_http2.c
*/ 
#include "mrb_http2_gzip.h"
#include <assert.h>

int nghttp2_gzip_inflate_new(nghttp2_gzip **inflater_ptr)
{
  int rv;
  *inflater_ptr = malloc(sizeof(nghttp2_gzip));
  if(*inflater_ptr == NULL) {
    return -1;
  }
  (*inflater_ptr)->finished = 0;
  (*inflater_ptr)->zst.next_in = Z_NULL;
  (*inflater_ptr)->zst.avail_in = 0;
  (*inflater_ptr)->zst.zalloc = Z_NULL;
  (*inflater_ptr)->zst.zfree = Z_NULL;
  (*inflater_ptr)->zst.opaque = Z_NULL;
  rv = inflateInit2(&(*inflater_ptr)->zst, 47);
  if(rv != Z_OK) {
    free(*inflater_ptr);
    return -1;
  }
  return 0;
}

void nghttp2_gzip_inflate_del(nghttp2_gzip *inflater)
{
  if(inflater != NULL) {
    inflateEnd(&inflater->zst);
    free(inflater);
  }
}

int nghttp2_gzip_inflate(nghttp2_gzip *inflater, uint8_t *out, 
    size_t *outlen_ptr, const uint8_t *in, size_t *inlen_ptr)
{
  int rv;
  if(inflater->finished) {
    return -1;
  }
  inflater->zst.avail_in = *inlen_ptr;
  inflater->zst.next_in = (unsigned char*)in;
  inflater->zst.avail_out = *outlen_ptr;
  inflater->zst.next_out = out;

  rv = inflate(&inflater->zst, Z_NO_FLUSH);

  *inlen_ptr -= inflater->zst.avail_in;
  *outlen_ptr -= inflater->zst.avail_out;
  switch(rv) {
  case Z_STREAM_END:
    inflater->finished = 1;
  case Z_OK:
  case Z_BUF_ERROR:
    return 0;
  case Z_DATA_ERROR:
  case Z_STREAM_ERROR:
  case Z_NEED_DICT:
  case Z_MEM_ERROR:
    return -1;
  default:
    assert(0);
    /* We need this for some compilers */
    return 0;
  }
}

int nghttp2_gzip_inflate_finished(nghttp2_gzip *inflater)
{
  return inflater->finished;
}
