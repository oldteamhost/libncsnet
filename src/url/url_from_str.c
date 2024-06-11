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

struct preproc_url {
  char *scheme, *authority, *path, *query, *fragment;
  int type;
};

static bool validate_dict(const char *str, const char *dict);
static struct preproc_url *preprocurl(const char *url);
static void parse_authority(struct url_authority *url_auth, const char *authority);

url_t *url_from_str(const char *url)
{
  struct preproc_url *pu;
  bool tmp = false;
  url_t *res;

  res = ___url_init();
  if (!res)
    goto fail;
  pu = preprocurl(url);
  if (!pu)
    goto fail;

  if (pu->scheme) {
    res->scheme = strdup(pu->scheme);
    free(pu->scheme);
  }
  if (pu->fragment) {
    res->fragment = strdup(pu->fragment);
    free(pu->fragment);
  }
  if (pu->path) {
    if (pu->path[strlen(pu->path)-1] == '/') {
      tmp = true;
      pu->path[strlen(pu->path)-1] = '\0';
    }
    ___url_add_path(res, pu->path);
    free(pu->path);
    if (tmp)
      ___url_add_path(res, "/");

  }
  if (pu->query) {
    ___url_add_query(res, pu->query);
    free(pu->query);
  }
  if (pu->authority) {
    parse_authority(res->authority, pu->authority);
    free(pu->authority);
  }
  res->type = pu->type;

  return res;
  
 fail:
  url_free(res);
  return NULL;
}

static bool
validate_dict(const char *str, const char *dict)
{
  while (*str) {
    if (!strchr(dict, *str))
      return false;
    str++;
  }
  return true;
}

static struct preproc_url *
preprocurl(const char *url)
{
  struct preproc_url *parsed_url;
  const char *pos, *start;

  parsed_url = malloc(sizeof(struct preproc_url));
  if (!parsed_url)
    return NULL;

  parsed_url->scheme = parsed_url->authority = parsed_url->path
    = parsed_url->query = parsed_url->fragment = NULL;
  parsed_url->type = URL_INTER_TYPE_DEFAULT;

  pos = url;
  start = pos;
  
  for (;*pos && *pos != ':' && *pos != '/' && *pos != '?' && *pos != '#'; pos++);
  if (*pos == ':') {
    parsed_url->scheme = mkstr(start, pos);
    if (!parsed_url->scheme ||
	!validate_dict(parsed_url->scheme, URL_SCHEME_DICT_INTER))
      goto fail;
    pos++;
  }
  else
    goto fail;

  if (*pos == '/' && *(pos + 1) == '/') {
    if (*(pos + 2) != '/') {
      pos += 2;
      start = pos;
      for (;*pos && *pos != '/' && *pos != '?' && *pos != '#'; pos++);
      parsed_url->authority = mkstr(start, pos);
      if (!parsed_url->authority)
	goto fail;
    }
    else {
      pos += 3;
      parsed_url->type = URL_INTER_TYPE_SCHEMEPATHSLASH;
    }
  }
  else
    parsed_url->type = URL_INTER_TYPE_SCHEMEPATH;
  if (*pos) {
    start = pos;
    for (;*pos && *pos != '?' && *pos != '#'; pos++);
    parsed_url->path = mkstr(start, pos);
    if (!parsed_url->path)
      goto fail;
  }
  if (*pos == '?') {
    pos++;
    start = pos;
    for (;*pos && *pos != '#'; pos++);
    parsed_url->query = mkstr(start, pos);
    if (!parsed_url->query)
      goto fail;
  }
  if (*pos == '#') {
    pos++;
    start = pos;
    for (;*pos; pos++);
    parsed_url->fragment = mkstr(start, pos);
    if (!parsed_url->fragment)
      goto fail;
  }
  
  return parsed_url;
  
 fail:
  if (parsed_url->scheme)
    free(parsed_url->scheme);
  if (parsed_url->authority)
    free(parsed_url->authority);
  if (parsed_url->path)
    free(parsed_url->path);
  if (parsed_url->query)
    free(parsed_url->query);
  if (parsed_url)
    free(parsed_url);
  
  return NULL;
}

static void
parse_authority(struct url_authority *url_auth, const char *authority)
{
  const char *p, *port;
  char *at;

  url_auth->host = NULL;
  url_auth->port = NULL;
  url_auth->userinfo = NULL;
  
  p = authority;
  at = strchr(authority, '@');
  if (at) {
    url_auth->userinfo = mkstr(authority, at);
    p = at + 1;
  }
  port = strchr(p, ':');
  if (port) {
    url_auth->host = mkstr(p, port);
    url_auth->port = strdup(port + 1);
  }
  else
    url_auth->host = strdup(p);
}


url_t *___url_init(void)
{
  url_t *res;
  
  res = (url_t*)malloc(sizeof(url_t));
  if (!res)
    goto fail;
  memset(res, 0, sizeof(url_t));
  res->authority = (struct url_authority*)
    malloc(sizeof(struct url_authority));
  if (!res->authority)
    goto fail;
  memset(res->authority, 0, sizeof(struct url_authority));

  return res;
  
 fail:
  url_free(res);
  return NULL;
}

static void url_add_path_general(url_t *url, char *path)
{
  struct url_path *new, *current;
  new = (struct url_path*)malloc(sizeof(struct url_path));
  if (!new)
    return;
  memset(new, 0, sizeof(struct url_path));
  
  if (path)
    new->path = strdup(path);
  else
    new->path = NULL;
  new->nxt = NULL;
  
  if (!url->path)
    url->path = new;
  else {
    current = url->path;
    while (current->nxt)
      current = current->nxt;
    current->nxt = new;
  }
}

void ___url_add_path(url_t *url, char *path)
{
  char *token;

  if (path[0] == '/' && path[1] == '\0') {
    url_add_path_general(url, "/");
    return;
  }
  
  if (*path == '\0')
    return;
  token = strtok(path, "/");
  while (token) {
    url_add_path_general(url, token);
    token = strtok(NULL, "/");
  }
}


static void url_add_query_general(url_t *url, char *query, char *value)
{
  struct url_query *new, *current;
  new = (struct url_query *)malloc(sizeof(struct url_query));
  if (!new)
    return;
  memset(new, 0, sizeof(struct url_query));

  if (query)
    new->query = strdup(query);
  else
    new->query = NULL;
  if (value)
    new->value = strdup(value);
  else
    new->value = NULL;
  new->nxt = NULL;

  if (!url->query)
    url->query = new;
  else {
    current = url->query;
    while (current->nxt)
      current = current->nxt;
    current->nxt = new;
  }
}

void ___url_add_query(url_t *url, char *query)
{
  char *tmpquery, *tmpval;
  const char *ptr, *pos;
  
  ptr = query;
  for (;*ptr != '\0';) {
    tmpval = tmpquery = NULL;
    for (;*ptr == QUERYOPT_DEL || *ptr == QUERY_DEL; ptr++);
    if (*ptr != '\0') {
      pos = strpbrk(ptr, "?&=");
      if (!pos)
	tmpquery = strdup(ptr);
      else
	tmpquery = mkstr(ptr, pos);
      for (;*ptr != QUERYOPT_DEL && *ptr != QUERY_DEL && *ptr != QUERYVAL_DEL &&
	     *ptr != '\0'; ptr++);
      if (*ptr++ == '=') {
	pos = strpbrk(ptr, "?&=");
	if (!pos)
	  tmpval = strdup(ptr);
	else
	  tmpval = mkstr(ptr, pos);
	for (;*ptr != QUERYOPT_DEL && *ptr != QUERY_DEL && *ptr != '\0'; ptr++);
      }
      if (tmpquery) {
	url_add_query_general(url, tmpquery, tmpval);
	free(tmpquery);
      }
      if (tmpval)
	free(tmpval);
    }
    for (;*ptr == QUERYOPT_DEL || *ptr == '?'; ptr++);
  }
}
