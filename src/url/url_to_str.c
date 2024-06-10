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

static void url_write_path(struct url_path *path, char *buf, int type)
{
  int skipfirst;

  skipfirst = (type == URL_INTER_TYPE_SCHEMEPATH);
  if (!path)
    return;
  while (path) {
    if (!skipfirst)
      strcat(buf, "/");
    strcat(buf, path->path);
    path = path->nxt;
    skipfirst = 0;
  }
}

static void url_write_query(struct url_query *query, char *buf)
{
  int is_first;
  if (!query)
    return;
  is_first = 1;
  strcat(buf, "?");
  while (query) {
    if (query->query) {
      if (!is_first) {
        if (query->value)
          strcat(buf, "&");
	else
          strcat(buf, "?");
      }
      else
        is_first = 0;
      strcat(buf, query->query);
      if (query->value) {
        strcat(buf, "=");
        strcat(buf, query->value);
      }
    }
    query = query->nxt;
  }
}

void url_to_str(url_t *url, char *buf, size_t buflen)
{
  if (buflen < url_len(url))
    return;

  if (url->scheme)
    strcpy(buf, url->scheme);
  
  if (url->type == URL_INTER_TYPE_SCHEMEPATHSLASH)
    strcat(buf, ":///");
  else if (url->type == URL_INTER_TYPE_DEFAULT)
    strcat(buf, "://");
  else if (url->type == URL_INTER_TYPE_SCHEMEPATH)
    strcat(buf, ":");
  
  if (url->authority) {
    if (url->authority->userinfo) {
      strcat(buf, url->authority->userinfo);
      strcat(buf, "@");
    }
    if (url->authority->host)
      strcat(buf, url->authority->host);
    if (url->authority->port) {
      strcat(buf, ":");
      strcat(buf, url->authority->port);
    }
  }
  if (url->path)
    url_write_path(url->path, buf, url->type);
  if (url->query)
    url_write_query(url->query, buf);
  if (url->fragment) {
    strcat(buf, "#");
    strcat(buf, url->fragment);
  }

}
