/*
// mrb_http2_error.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_ERROR_H
#define MRB_HTTP2_ERROR_H

#include "mrb_http2_request.h"


const char *mrb_http2_1xx_error_table[] = {
  // 100 -
  "<html><head><title>100</title></head><body><h1>100 Continue</h1></body></html>",
  NULL
};

const char *mrb_http2_3xx_error_table[] = {
  // 300 -
  "<html><head><title>300</title></head><body><h1>300 Multiple Choices</h1></body></html>",
  "<html><head><title>301</title></head><body><h1>301 Moved Permanently</h1></body></html>",
  "<html><head><title>302</title></head><body><h1>302 Found</h1></body></html>",
  NULL
};

const char *mrb_http2_4xx_error_table[] = {
  // 400 -
  "<html><head><title>400</title></head><body><h1>400 Bad Request</h1></body></html>",
  "<html><head><title>401</title></head><body><h1>401 Unauthorized</h1></body></html>",
  "<html><head><title>402</title></head><body><h1>402 Payment Required</h1></body></html>",
  "<html><head><title>403</title></head><body><h1>403 Forbidden</h1></body></html>",
  "<html><head><title>404</title></head><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>",
  NULL
};

const char *mrb_http2_5xx_error_table[] = {
  // 500 -
  "<html><head><title>500</title></head><body><h1>500 Internal Server Error</h1></body></html>",
  "<html><head><title>501</title></head><body><h1>501 Not Implemented</h1></body></html>",
  "<html><head><title>502</title></head><body><h1>502 Bad Gateway</h1></body></html>",
  "<html><head><title>503</title></head><body><h1>503 Service Unavailable</h1></body></html>",
  NULL
};

const int mrb_http2_1xx_error_table_len = (sizeof(mrb_http2_1xx_error_table) / sizeof(mrb_http2_1xx_error_table[0])) - 1;
const int mrb_http2_3xx_error_table_len = (sizeof(mrb_http2_3xx_error_table) / sizeof(mrb_http2_3xx_error_table[0])) - 1;
const int mrb_http2_4xx_error_table_len = (sizeof(mrb_http2_4xx_error_table) / sizeof(mrb_http2_4xx_error_table[0])) - 1;
const int mrb_http2_5xx_error_table_len = (sizeof(mrb_http2_5xx_error_table) / sizeof(mrb_http2_5xx_error_table[0])) - 1;

const char *mrb_http2_error_message(int status)
{

  if (status >= 500) {
    if ((status - 500 + 1) > mrb_http2_5xx_error_table_len) goto not_implement;
    return mrb_http2_5xx_error_table[status - 500];
  } else if (status >= 400) {
    if ((status - 400 + 1) > mrb_http2_4xx_error_table_len) goto not_implement;
    return mrb_http2_4xx_error_table[status - 400];
  } else if (status  >= 300) {
    if ((status - 300 + 1) > mrb_http2_3xx_error_table_len) goto not_implement;
    return mrb_http2_3xx_error_table[status - 300];
  } else if (status >= 200) {
    goto not_implement;
  } else if (status >= 100) {
    if ((status - 100 + 1) > mrb_http2_1xx_error_table_len) goto not_implement;
    return mrb_http2_1xx_error_table[status - 100];
  } else {
    return mrb_http2_5xx_error_table[0];
  }

not_implement:
  return mrb_http2_4xx_error_table[4];
}

#endif
