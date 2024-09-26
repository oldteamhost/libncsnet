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

static void
*bindtmp;

bool __bind_callback(u8 *frame, size_t fmrlen, void *arg)
{
  ncsnet_t *n=(ncsnet_t*)bindtmp;
  mach_t *dlt=(mach_t*)(frame);
  size_t skip;

  if (n->sock.sendfd.dlttype==DLT_EN10MB)
    skip=sizeof(mach_t);
  else
    skip=36;

  switch (n->sock.bind) {
    case __BINDTYPE_IP4: {
      if (ntohs(dlt->type)!=ETH_TYPE_IPV4)
        return 0;
      ip4h_t *ip=(ip4h_t*)((frame)+skip);
      if (n->sock.bindproto>0)
        if (ip->proto!=n->sock.bindproto)
          return 0;
      if (!ip4t_compare(ip->src, n->sock.ncsnet_bind.ip4))
        return 0;
      return 1;
    }
    case __BINDTYPE_IP6: {
      if (ntohs(dlt->type)!=ETH_TYPE_IPV6)
        return 0;
      ip6h_t *ip6=(ip6h_t*)((frame)+skip);
      if (n->sock.bindproto>0)
        if (ip6->nxt!=n->sock.bindproto)
          return 0;
      if (!ip6t_compare(ip6->src, n->sock.ncsnet_bind.ip6))
        return 0;
      return 1;
    }
    case __BINDTYPE_MAC: {
      if (!mact_compare(dlt->src, n->sock.ncsnet_bind.mac))
        return 0;
      return 1;
    }
  }
  return 0;
}

bool __ncsbind_general(ncsnet_t *n, int bind, ip4_t *ip4, ip6_t *ip6, mac_t *mac)
{
  if (!n)
    return 0;
  n->sock.bind=bind;
  switch (bind) {
    case __BINDTYPE_IP4:
      n->sock.ncsnet_bind.ip4=*ip4;
      break;
    case __BINDTYPE_IP6:
      n->sock.ncsnet_bind.ip6=*ip6;
      break;
    case __BINDTYPE_MAC:
      n->sock.ncsnet_bind.mac=*mac;
      break;
  }
  bindtmp=(ncsnet_t*)n;
  return 1;
}
