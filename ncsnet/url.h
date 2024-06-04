/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef NCSURLHDR
#define NCSURLHDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <ctype.h>

#include "utils.h"
#include "sys/types.h"
#include "../ncsnet-config.h"

/*
 * RFC 3986
 * RFC 4248
 * RFC 4266
 * RFC 6270
 * RFC 6067 | 50%
 * RFC 1738 | 50%
 */

/* file:///path<..,> */
#define URL_INTER_TYPE_SCHEMEPATHSLASH 0
/* scheme://<etc. ...,> */
#define URL_INTER_TYPE_DEFAULT         1
/* scheme:<etc. ...,> */
#define URL_INTER_TYPE_SCHEMEPATH      2

#define URL_SCHEME_DEL ':'
#define URL_SCHEME_DICT "abcdefghijklmnopqrstuvwxyz123456789+-."
#define URL_SCHEME_DICT_INTER						\
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789+-."
#define USERINFO_DEL    '@'
#define PORT_DEL        ':'
#define PATH_DEL        '/'
#define QUERY_DEL       '?'
#define QUERYVAL_DEL    '='
#define QUERYOPT_DEL    '&'
#define FRAGMENT_DEL    '#'
#define AUTHORITY_DEL   "//"

#define URL_SCHEME               1
#define URL_PATH                 2
#define URL_AUTHORITY_HOST       3
#define URL_AUTHORITY_PORT       4
#define URL_AUTHORITY_USERINFO   5
#define URL_QUERY                6
#define URL_FRAGMENT             7

struct url_query { char *query; char *value; struct url_query *nxt; };
struct url_path { char *path; struct url_path *nxt; };
struct url_authority { char *host; char *userinfo; char *port; };

typedef struct url_addr
{
  char*                 scheme;
  struct url_authority *authority;
  struct url_path      *path;
  struct url_query     *query;
  char                 *fragment;
  int                   type;
} url_t;

__BEGIN_DECLS

void    url_field(url_t *url, const char *txt, int field);
#define url_query(url, query)        url_field((url), (query), URL_QUERY)
#define url_path(url, path)          url_field((url), (path), URL_PATH)
#define url_host(url, host)          url_field((url), (host), URL_AUTHORITY_HOST)
#define url_port(url, port)          url_field((url), (port), URL_AUTHORITY_PORT)
#define url_userinfo(url, userinfo)  url_field((url), (userinfo), URL_AUTHORITY_USERINFO)
#define url_fragment(url, fragment)  url_field((url), (fragment), URL_FRAGMENT)
#define url_scheme(url, scheme)      url_field((url), (scheme), URL_SCHEME)
void    url_free(url_t *url);

url_t  *url_from_str(const char *url);
void    url_to_str(url_t *url, char *buf, size_t buflen);
size_t  url_len(url_t *url);
void    url_print(url_t *url);
url_t  *url_build(const char *scheme, const char *paths,
		 const char *host, const char *userinfo,
		 const char *port, const char *querys);

url_t * ___url_init(void);
void    ___url_add_path(url_t *url, char *path);
void    ___url_add_query(url_t *url, char *query);
void    ___url_free_path(struct url_path *path);
void    ___url_free_query(struct url_query *query);

__END_DECLS

#endif
