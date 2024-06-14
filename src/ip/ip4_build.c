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

u8 *ip4_build(u32 src, u32 dst, u8 proto, int ttl, u16 id, u8 tos,
	      bool df, const u8 *opt, int optlen, const char *data,
	      u16 datalen, u32 *pktlen)
{
  struct ip4_hdr *ip;
  u8 *pkt;

  assert(optlen % 4 == 0);
  *pktlen = sizeof(struct ip4_hdr) + optlen + datalen;
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
    memcpy((u8*)ip + sizeof(struct ip4_hdr),
	   opt, optlen);
  ip->check   = 0;
  ip->check   = ip_check_add((u16*)ip,
            sizeof(struct ip4_hdr) + optlen, 0);

  if (data && datalen)
    memcpy((u8*)ip + sizeof(struct ip4_hdr) + optlen,
	   data, datalen);

  return pkt;
}
