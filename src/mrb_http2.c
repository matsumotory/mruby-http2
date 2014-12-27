/*
** mrb_http2 - http2 class for mruby
**
** Copyright (c) MATSUMOTO, Ryosuke 2013-
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

#include "mrb_http2.h"

void mrb_http2_client_class_init(mrb_state *mrb, struct RClass *http2);
void mrb_http2_server_class_init(mrb_state *mrb, struct RClass *http2);
void mrb_http2_request_class_init(mrb_state *mrb, struct RClass *http2);

// get nghttp2_nv by name
int mrb_http2_get_nv_id(nghttp2_nv *nva, size_t nvlen, const char *key)
{
  int i;
  size_t len = strlen(key);

  for (i = 0; i < nvlen; i++) {
    if(nva[i].namelen == len && memcmp(key, nva[i].name, nva[i].namelen) == 0) {
      return i;
    }
  }
  return MRB_HTTP2_HEADER_NOT_FOUND;
}

// create nghttp2_nv
void mrb_http2_create_nv(mrb_state *mrb, nghttp2_nv *nv, const uint8_t *name,
    size_t namelen, const uint8_t *value, size_t valuelen)
{
  nv->name = (uint8_t *)name;
  nv->namelen = namelen;
  nv->value = (uint8_t *)value;
  nv->valuelen = valuelen;
  nv->flags = NGHTTP2_NV_FLAG_NONE;
}

// add nghttp2_nv into existing nghttp2_nv array
size_t mrb_http2_add_nv(nghttp2_nv *nva, size_t nvlen, nghttp2_nv *nv)
{
  if (nvlen > MRB_HTTP2_HEADER_MAX) {
    return -1;
  }
  nva[nvlen] = *nv;
  //fprintf(stderr, "%s: nvlen=%ld ARRLEN=%ld\n", __func__, nvlen, ARRLEN(nva));
  nvlen++;

  return nvlen;
}

char *mrb_http2_strcat(mrb_state *mrb, const char *s1, const char *s2)
{
  size_t len1 = strlen(s1);
  size_t len2 = strlen(s2);

  char *s3 = (char *)mrb_malloc(mrb, len1 + len2 + 1);
  memcpy(s3, s1, len1);
  memcpy(s3 + len1, s2, len2 + 1);

  return s3;
}

char *mrb_http2_strcat2(mrb_state *mrb, mrb_http2_str *s1, mrb_http2_str *s2)
{
  char *s3 = (char *)mrb_malloc(mrb, s1->len + s2->len + 1);

  memcpy(s3, s1->str, s1->len);
  memcpy(s3 + s1->len, s2->str, s2->len + 1);

  return s3;
}

mrb_http2_str *mrb_http2_str_new(mrb_state *mrb, char *s, size_t len)
{
  mrb_http2_str *dst;
  dst = mrb_malloc(mrb, sizeof(mrb_http2_str));
  dst->str = s;
  dst->len = len;
  return dst;
}

char *mrb_http2_strcopy(mrb_state *mrb, const char *s, size_t len)
{
  char *dst;
  dst = mrb_malloc(mrb, len+1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

// will remove
char *strcopy(const char *s, size_t len)
{
  char *dst;
  dst = malloc(len+1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

mrb_value mrb_http2_class_obj(mrb_state *mrb, mrb_value self,
    char *obj_id, char *class_name)
{
  mrb_value obj;
  struct RClass *target, *http2;

  obj = mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, obj_id));
  if (mrb_nil_p(obj)) {
    http2 = mrb_module_get(mrb, "HTTP2");
    target = (struct RClass *)mrb_class_ptr(mrb_const_get(mrb,
          mrb_obj_value(http2), mrb_intern_cstr(mrb, class_name)));
    obj = mrb_obj_new(mrb, target, 0, NULL);
    mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, obj_id), obj);
  }
  return obj;
}

void mrb_mruby_http2_gem_init(mrb_state *mrb)
{
  struct RClass *http2;

  http2 = mrb_define_module(mrb, "HTTP2");

  mrb_http2_client_class_init(mrb, http2);
  mrb_http2_server_class_init(mrb, http2);
  mrb_http2_request_class_init(mrb, http2);

  DONE;
}

void mrb_mruby_http2_gem_final(mrb_state *mrb)
{
}

