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

#include "ncsnet/url.h"

#define SET_FIELD_PTR(ptr, new_value) \
  do {				      \
    if ((ptr) != NULL) {	      \
      free(ptr);		      \
    }				      \
    ptr = strdup(new_value);	      \
    } while (0)

void url_field(url_t *url, const char *txt, int field)
{
  if (!url)
    return;
  switch(field) {
  case URL_SCHEME:
    SET_FIELD_PTR(url->scheme, txt);
    break;
  case URL_FRAGMENT:
    SET_FIELD_PTR(url->fragment, txt);
    break;
  case URL_AUTHORITY_HOST:
    SET_FIELD_PTR(url->authority->host, txt);
    break;
  case URL_AUTHORITY_PORT:
    SET_FIELD_PTR(url->authority->port, txt);
    break;
  case URL_AUTHORITY_USERINFO:
    SET_FIELD_PTR(url->authority->userinfo, txt);
    break;
  case URL_PATH:
    if (url->path) {
      ___url_free_path(url->path);
      url->path = NULL;
    }
    ___url_add_path(url, strdup(txt));
    break;
  case URL_QUERY:
    if (url->query) {
      ___url_free_query(url->query);
      url->query = NULL;
    }
    ___url_add_query(url, strdup(txt));
    break;    
  };
}
