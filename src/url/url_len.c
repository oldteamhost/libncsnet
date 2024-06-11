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

static size_t get_query_length(struct url_query *query)
{
  size_t res;
  int is_first;
  res = 0;
  is_first = 1;
  if (!query)
    return res;
  res += 1; /* ? */
  while (query) {
    if (query->query) {
      if (!is_first)
	res += 1; /* & */
      else
	is_first = 0;
      if (query->value)
	res++; /* = */
      res += safe_strlen(query->value) + safe_strlen(query->query);
      query = query->nxt;
    }
  }
  return res;
}

static size_t get_path_length(struct url_path *path, int type)
{
  int skipfirst;
  size_t res;
  skipfirst =
    ((type == URL_INTER_TYPE_SCHEMEPATH || type == URL_INTER_TYPE_SCHEMEPATHSLASH));
  res = 0;
  if (!path)
    return res;
  if (path && !path->nxt && path->path[0] == '/' && path->path[1] == '\0')
    return ++res;
  while (path) {
    res += safe_strlen(path->path);
    if (!skipfirst)
      res += 1; /* / */
    skipfirst = 0;
    if (!path->nxt && path->path[strlen(path->path)-1] == '/')
      res--;
    path = path->nxt;
  }
  return res;
}

size_t url_len(url_t *url)
{
  size_t res;
  res = 0;
  if (!url)
    return res;
  res += safe_strlen(url->scheme);
  res++; /* : */
  if (url->authority) {
    if (url->type == URL_INTER_TYPE_SCHEMEPATHSLASH)
      res += 3; /* /// */
    else if (url->type == URL_INTER_TYPE_DEFAULT)
      res += 2; /* // */
    if (url->authority->host)
      res += safe_strlen(url->authority->host);
    if (url->authority->userinfo) {
      res += safe_strlen(url->authority->userinfo);
      res++; /* @ */
    }
    if (url->authority->port) {
      res += safe_strlen(url->authority->port);
      res += 1; /* : */
    }
  }
  res += get_path_length(url->path, url->type);
  res += get_query_length(url->query);
  if (url->fragment) {
    res += safe_strlen(url->fragment);
    res += 1; /* # */
  }
  return res;
}
