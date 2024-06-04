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

void ___url_free_path(struct url_path *path)
{
  if (!path)
    return;
  if (path->path)
    free(path->path);
  if (path->nxt)
    ___url_free_path(path->nxt);
  free(path);
}

void ___url_free_query(struct url_query *query)
{
  if (!query)
    return;
  if (query->query)
    free(query->query);
  if (query->nxt)
    ___url_free_query(query->nxt);
  free(query);
}

static void url_free_authority(struct url_authority *auth)
{
  if (!auth)
    return;
  if (auth->userinfo)
    free(auth->userinfo);
  if (auth->port)
    free(auth->port);
  free(auth);
}

void url_free(url_t *url)
{
  if (!url)
    return;
  if (url->scheme)
    free(url->scheme);
  if (url->fragment)
    free(url->fragment);

  url_free_authority(url->authority);
  ___url_free_path(url->path);
  ___url_free_query(url->query);
  
  free(url);
}
