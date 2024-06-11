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

#include <ncsnet/url.h>

static void url_print_path(struct url_path *path, int indent)
{
  int i;
  if (!path)
    return;
  for (i = 0; i < indent; ++i)
    printf(" ");
  printf("\\_path = %s\n", path->path);
  if (path->nxt)
    url_print_path(path->nxt, indent + 4);
}

static void url_print_query(struct url_query *query, int indent)
{
  int i;
  if (!query)
    return;
  for (i = 0; i < indent; ++i)
    printf(" ");
  printf("\\_query = %s%s%s\n", query->query,
	 (IS_NULL_OR_EMPTY(query->value)) ?  "" : ", val = ",
	 (IS_NULL_OR_EMPTY(query->value)) ?  "" : query->value);
  if (query->nxt)
    url_print_query(query->nxt, indent + 4);
}

void url_print(url_t *url)
{
  char __url[(url_len(url))];
  int indent = 0, i;
  
  url_to_str(url, __url, sizeof(__url));
  printf("(%ld len) checksum = %s\n", sizeof(__url), __url);
  if (url->scheme)
    printf(" \\_scheme = %s\n", url->scheme);
  if (url->authority) {
    indent += 4;
    if (url->authority->userinfo) {
      for (i = 0; i < indent; ++i)
	printf(" ");
      printf("\\_userinfo = %s\n", url->authority->userinfo);
    }
    if (url->authority->host) {
      for (i = 0; i < indent; ++i)
	printf(" ");
      printf("\\_host = %s\n", url->authority->host);
    }
    if (url->authority->port) {
      for (i = 0; i < indent; ++i)
	printf(" ");
      printf("\\_port = %s\n", url->authority->port);
    }
  }
  if (url->path)
    url_print_path(url->path, indent);
  if (url->query)
    url_print_query(url->query, indent);
  if (url->fragment) {
    for (i = 0; i < indent; ++i)
      printf(" ");
    printf("\\_fragment = %s\n", url->fragment);
  }
}
