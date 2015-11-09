/*
// mrb_http2_ssl.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_SSL_H
#define MRB_HTTP2_SSL_H

const char *const DEFAULT_CIPHER_LIST = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-"
                                        "AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:"
                                        "DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-"
                                        "AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-"
                                        "AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-"
                                        "AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:"
                                        "DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:"
                                        "!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";

#endif
