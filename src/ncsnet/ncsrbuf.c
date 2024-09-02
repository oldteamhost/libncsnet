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

#include <ncsnet/ncsnet.h>

void __ncsrbuf_create(ncsnet_t *n, int index)
{
  ncsnet_rbuf *new, *cur;
  if (!(new=(ncsnet_rbuf*)calloc(1, sizeof(ncsnet_rbuf))))
    return;

  new->rbuf=calloc(1, n->sock.rbuflen);
  if (!new->rbuf) {
    free(new);
    return;
  }
  new->received=0;
  new->index=index;
  new->nxt=NULL;

  if (!n->sock.recvfd.rbuf)
    n->sock.recvfd.rbuf=new;
  else {
    cur=n->sock.recvfd.rbuf;
    while (cur->nxt)
      cur=cur->nxt;
    cur->nxt=new;
  }
}

ncsnet_rbuf *__ncsrbuf_get(ncsnet_t *n, int index)
{
  ncsnet_rbuf *cur;
  if (!n->sock.recvfd.rbuf)
    return NULL;
  cur=n->sock.recvfd.rbuf;
  while (cur) {
    if (cur->index==index)
      return cur;
    cur=cur->nxt;
  }
  return NULL;
}

u8 *__ncsrbuf_getrbuf(ncsnet_t *n, int index)
{
  ncsnet_rbuf *cur;
  if (!n)
    return NULL;
  cur=__ncsrbuf_get(n, index);
  if (!cur||!cur->rbuf)
    return NULL;
  return cur->rbuf;
}

void __ncsrbuf_free(ncsnet_t *n, int index)
{
  ncsnet_rbuf *cur=__ncsrbuf_get(n, index);
  ncsnet_rbuf *prev=NULL;

  if (!cur)
    return;

  prev=n->sock.recvfd.rbuf;
  if (prev==cur)
    n->sock.recvfd.rbuf=cur->nxt;
  else {
    while (prev&&prev->nxt!=cur)
      prev=prev->nxt;
    if (prev)
      prev->nxt=cur->nxt;
  }

  if (cur->rbuf)
    free(cur->rbuf);
  free(cur);
}

void __ncsrbuf_all_free(ncsnet_rbuf *rbuf)
{
  if (!rbuf)
    return;
  if (rbuf->rbuf)
    free(rbuf->rbuf);
  if (rbuf->nxt)
    __ncsrbuf_all_free(rbuf->nxt);
  free(rbuf);
}

u8 *ncsrbuf(ncsnet_t *n, int id_rb, size_t getlen)
{
  ncsnet_rbuf *rbuf;
  u8 *res;

  rbuf=__ncsrbuf_get(n, id_rb);
  if (!rbuf)
    return NULL;
  if (!n||!getlen||rbuf->received<=0)
    return NULL;

  if (getlen>rbuf->received)
    getlen=rbuf->received;
  res=(u8*)calloc(1, getlen);
  if (!res)
    return NULL;

  memcpy(res, rbuf->rbuf, getlen);
  return res;
}

ncstime_t ncsrbuf_rtt(ncsnet_t *n, int id_rb)
{
  ncsnet_rbuf *rbuf;
  rbuf=__ncsrbuf_get(n, id_rb);
  if (!rbuf)
    return 0;
  return (rbuf->tstamp_e.tv_sec-rbuf->tstamp_s.tv_sec)*1000000000LL+
    (rbuf->tstamp_e.tv_usec-rbuf->tstamp_s.tv_usec)*1000LL;
}

size_t ncsrbuf_len(ncsnet_t *n, int id_rb)
{
  ncsnet_rbuf *rbuf;
  rbuf=__ncsrbuf_get(n, id_rb);
  if (!rbuf)
    return 0;
  return rbuf->received;
}

bool ncsrbuf_write(ncsnet_t *n, int id_rb, void *dst, size_t dstlen, size_t getlen)
{
  ncsnet_rbuf *rbuf;
  rbuf=__ncsrbuf_get(n, id_rb);
  if (!rbuf)
    return 0;
  if (!n||!getlen||!dst||
    !dstlen||rbuf->received<=0)
    return 0;

  if (getlen>dstlen)
    return 0;
  if (getlen>rbuf->received)
    getlen=rbuf->received;

  memcpy(dst, rbuf->rbuf, getlen);
  return 1;
}

void ncsrbuf_free(ncsnet_t *n, int id_rb)
{
  if (!n)
    return;
  __ncsrbuf_free(n, id_rb);
}
