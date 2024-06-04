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

#ifndef NCSHTTPHDR
#define NCSHTTPHDR

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "base64.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define MAX_PACKET_SIZE 65535

struct uri
{
  char *scheme;
  char *host;
  u16   port;
  char *path;
};

struct _http_header
{
  char *field;
  char *value;
  struct _http_header *nxt;
};

struct http_request
{
  char method[24];
  struct uri uri;
  struct _http_header *hdr;
  u64 contentlen;
  u64 transflen;
};

struct http_response
{
  int code;
  char *phrase;
  struct _http_header *hdr;
  u64 contentlen;
};

static const char base64_dict[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

__BEGIN_DECLS

void http_init_uri(struct uri *u, const char *scheme, const char *host, u16 port,
              const char *path);
void http_print_uri(struct uri *u);
void http_free_uri(struct uri *u);
void http_update_uri(struct uri *u, const char *scheme, const char *host, u16 port,
                const char *path);
void http_init_hdr(struct _http_header *h, const char *field,
                   const char *value);
void http_print_hdr(struct _http_header *h);
void http_free_hdr(struct _http_header *h);
void http_add_hdr(struct http_request *r, const char *field, const char *value);
void http_init_req(struct http_request *r, const char *method,
                       const char *scheme, const char *host, u8 port,
                       const char *path, u64 contentlen, u64 trasflen);
void http_print_req(struct http_request *r);
void http_free_req(struct http_request *r);
void http_print_res(struct http_response *r);
void http_free_res(struct http_response *r);
char *http_util_findval(struct _http_header *h, const char *field);
void http_modify_hdr(struct http_request *r, const char *field,
                     const char *newvalue);
void http_add_basiauth(struct http_request *h, const char *user,
                       const char *pass);
u8 *http_build_pkt(struct http_request *request, const char *data,
                   ssize_t datalen, ssize_t *pktlen);
u8 *http_remove_html(u8 *packet);
struct http_response http_read_pkt(u8 *response);
void http_qprc_title(const char *h, char *titlebuf,
                     size_t buflen);
char *http_parse_parent_location(const char *buf);
char *http_parse_url_from_js(const char *buf);
char *http_parse_http_equiv(const char *buf);
void http_qprc_redirect(struct _http_header *h, u8 *pkt, char *res,
                        ssize_t reslen);
int http_send_pkt(int fd, struct http_request *r);
int http_recv_pkt(int fd, struct http_response *r, u8 *packet,
                  ssize_t packetlen);
int httpreq_qprc_pkt(const char *dst, u16 dstport, const char *path,
                     long long timeoutns, struct http_response *r, u8 *buf,
                     ssize_t buflen);
int http_qprc_pkt(const char *dst, u16 dstport, long long timeoutns,
                  struct http_request *r, struct http_response *res, u8 *buf,
                  ssize_t buflen);
bool http_basicauth(int fd, const char *dst, const char *path, const char *user,
                     const char *pass);
int http_qprc_robots_txt(const char *dst, const int dstport, const long long timeoutns);
int http_qprc_sitemap_xml(const char *dst, const int dstport, const long long timeoutns);

__END_DECLS

#endif
