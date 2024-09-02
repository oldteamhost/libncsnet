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

#include <ncsnet/icmp.h>

u8 *icmp4_build_pkt(const ip4_t src, const ip4_t dst, int ttl, u16 ipid, u8 tos,
                    u16 off, u8 *ipopt, int ipoptlen, u8 type, u8 code, u8 *msg,
                    size_t msglen, size_t *pktlen, bool badsum)
{
  size_t icmplen;
  icmp4h_t *icmp;
  u8 *pkt;

  icmp=(icmp4h_t*)icmp_build(type, code, msg, msglen, &icmplen);
  if (!icmp)
    return NULL;
  icmp4_check((u8*)icmp, icmplen, badsum);

  pkt=ip4_build(src, dst, IPPROTO_ICMP, ttl, ipid, tos, off, ipopt,
    ipoptlen, (u8*)icmp, icmplen, pktlen);

  free(icmp);
  return pkt;
}
