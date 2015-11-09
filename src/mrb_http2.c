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
#include <pwd.h>

static const char *MONTH[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

static const char *DAY_OF_WEEK[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

void mrb_http2_client_class_init(mrb_state *mrb, struct RClass *http2);
void mrb_http2_server_class_init(mrb_state *mrb, struct RClass *http2);
void mrb_http2_request_class_init(mrb_state *mrb, struct RClass *http2);

void mrb_free_unless_null(mrb_state *mrb, void *ptr)
{
  if (ptr != NULL) {
    mrb_free(mrb, ptr);
  }
}

void debug_header(const char *tag, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen)
{
  char *key = alloca(namelen + 1);
  char *val = alloca(valuelen + 1);
  memcpy(key, name, namelen);
  memcpy(val, value, valuelen);
  key[namelen] = '\0';
  val[valuelen] = '\0';
  fprintf(stderr, "%s: header={name=%s, value=%s}\n", tag, key, val);
}

uid_t mrb_http2_get_uid(mrb_state *mrb, const char *user)
{
  struct passwd *pw;

  if (user == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Not found 'run_user' value");
  }

  pw = getpwnam(user);

  if (pw == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "getpwnam failed");
  }
  return pw->pw_uid;
}

static char *dig_memcpy(char *buf, int n, size_t len)
{
  char *p;

  p = buf + len - 1;
  do {
    // dig to str
    *p-- = (n % 10) + '0';
    n /= 10;
  } while (p >= buf);

  return buf + len;
}

// Sat, 27 Dec 2014 08:30:29 GMT
void set_http_date_str(time_t *time, char *date)
{
  struct tm t;
  char *p = date;

  if (gmtime_r(time, &t) == NULL) {
    return;
  }

  memcpy(p, DAY_OF_WEEK[t.tm_wday], 3);
  p += 3;
  *p++ = ',';
  *p++ = ' ';
  p = dig_memcpy(p, t.tm_mday, 2);
  *p++ = ' ';
  memcpy(p, MONTH[t.tm_mon], 3);
  p += 3;
  *p++ = ' ';
  p = dig_memcpy(p, t.tm_year + 1900, 4);
  *p++ = ' ';
  p = dig_memcpy(p, t.tm_hour, 2);
  *p++ = ':';
  p = dig_memcpy(p, t.tm_min, 2);
  *p++ = ':';
  p = dig_memcpy(p, t.tm_sec, 2);
  memcpy(p, " GMT", 4);
  p += 4;
  *p = '\0';
}

// get nghttp2_nv by name
int mrb_http2_get_nv_id(nghttp2_nv *nva, size_t nvlen, const char *key)
{
  int i;
  size_t len = strlen(key);

  for (i = 0; i < nvlen; i++) {
    if (nva[i].namelen == len && memcmp(key, nva[i].name, nva[i].namelen) == 0) {
      return i;
    }
  }
  return MRB_HTTP2_HEADER_NOT_FOUND;
}

// free nghttp2_nv
void mrb_http2_free_nva(mrb_state *mrb, nghttp2_nv *nva, size_t nvlen)
{
  int i;
  for (i = 0; i < nvlen; i++) {
    mrb_free(mrb, nva[i].name);
    mrb_free(mrb, nva[i].value);
    nva[i].namelen = 0;
    nva[i].valuelen = 0;
  }
}

// create nghttp2_nv
void mrb_http2_create_nv(mrb_state *mrb, nghttp2_nv *nv, const uint8_t *name, size_t namelen, const uint8_t *value,
                         size_t valuelen)
{
  nv->name = mrb_malloc(mrb, namelen);
  memcpy(nv->name, name, namelen);
  nv->namelen = namelen;

  nv->value = mrb_malloc(mrb, valuelen);
  memcpy(nv->value, value, valuelen);
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
  // fprintf(stderr, "%s: nvlen=%ld ARRLEN=%ld\n", __func__, nvlen,
  // ARRLEN(nva));
  nvlen++;

  return nvlen;
}

int mrb_http2_strrep(char *buf, char *before, char *after)
{
  char *ptr;
  size_t beforelen, afterlen;

  beforelen = strlen(before);
  afterlen = strlen(after);

  if (beforelen == 0 || (ptr = strstr(buf, before)) == NULL) {
    return 0;
  }
  memmove(ptr + afterlen, ptr + beforelen, strlen(buf) - (ptr + beforelen - buf) + 1);
  memcpy(ptr, after, afterlen);
  return 1;
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

char *mrb_http2_strcopy(mrb_state *mrb, const char *s, size_t len)
{
  char *dst;
  dst = mrb_malloc(mrb, len + 1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

// will remove
char *strcopy(const char *s, size_t len)
{
  char *dst;
  dst = malloc(len + 1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

mrb_value mrb_http2_class_obj(mrb_state *mrb, mrb_value self, char *obj_id, char *class_name)
{
  mrb_value obj;
  struct RClass *target, *http2;

  obj = mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, obj_id));
  if (mrb_nil_p(obj)) {
    http2 = mrb_module_get(mrb, "HTTP2");
    target = (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(http2), mrb_intern_cstr(mrb, class_name)));
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
