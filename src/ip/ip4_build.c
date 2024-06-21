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

#include <ncsnet/ip.h>

u8 *ip4_build(u32 src, u32 dst, u8 proto, int ttl, u16 id, u8 tos, bool df,
              const u8 *opt, int optlen, u8 *frame, size_t frmlen,
              size_t *pktlen)
{
  ip4h_t *ip;
  u8 *pkt;

  assert(optlen % 4 == 0);
  *pktlen = sizeof(ip4h_t) + optlen + frmlen;
  pkt = (u8*)malloc(*pktlen);
  if (!pkt)
    return NULL;

  ip = (struct ip4_hdr*)pkt;
  ip->version = 4;
  ip->ihl     = 5 + (optlen / 4);
  ip->tos     = tos;
  ip->totlen  = htons(*pktlen);
  ip->id      = htons(id);
  ip->off     = htons((df ? IP4_DF : 0));
  ip->ttl     = ttl;
  ip->proto   = proto;
  ip->src     = src;
  ip->dst     = dst;
  if (opt && optlen)
    memcpy((u8*)ip + sizeof(ip4h_t), opt, optlen);
  ip4_check((u8*)ip, sizeof(ip4h_t) + optlen, false);
  
  if (frame && frmlen)
    memcpy((u8*)ip + sizeof(ip4h_t) + optlen,
	   frame, frmlen);

  return pkt;
}
