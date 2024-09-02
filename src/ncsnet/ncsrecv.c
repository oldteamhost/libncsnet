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
#include "../../ncsnet/trace.h"

ssize_t ncsrecv(ncsnet_t *n, lrcall_t callback, int id_rb)
{
  ncsnet_rbuf *rbuf;

  if (!n)
    n=ncsopen();
  if (!callback&&n->sock.bind>0)
    lr_callback(n->sock.recvfd.lr, __bind_callback);
  else
    lr_callback(n->sock.recvfd.lr, callback);

  __ncsrbuf_create(n, id_rb);
  rbuf=__ncsrbuf_get(n, id_rb);

  rbuf->received=lr_live(n->sock.recvfd.lr, &rbuf->rbuf, n->sock.rbuflen);
  if (n->sock.rinfolvl>0&&rbuf->received>0)
    printf("%s\n", frminfo(rbuf->rbuf, rbuf->received, n->sock.rinfolvl, 0));

  rbuf->tstamp_e=n->sock.recvfd.lr->tstamp_e;
  rbuf->tstamp_s=n->sock.recvfd.lr->tstamp_s;

  return rbuf->received;
}
