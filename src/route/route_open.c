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

#include <ncsnet/route.h>

route_t *route_open(void)
{
  struct sockaddr_nl snl;
  route_t *r;

  r=calloc(1, sizeof(*r));
  if (!r)
    return NULL;

  r->fd=r->fd6=r->nlfd=-1;
  if ((r->fd=socket(AF_INET, SOCK_DGRAM, 0))<0)
    goto fail;
  if ((r->fd6=socket(AF_INET6, SOCK_DGRAM, 0))<0)
    goto fail;
  if ((r->nlfd=socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE))<0)
    goto fail;

  memset(&snl, 0, sizeof(snl));
  snl.nl_family = AF_NETLINK;
  if (bind(r->nlfd, (struct sockaddr *)&snl, sizeof(snl))<0)
    goto fail;

  return (r);
fail:
  route_close(r);
  return NULL;
}
