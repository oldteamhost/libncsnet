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

#include <ncsnet/udp.h>

u8 *udp4_build_pkt(const u32 src, const u32 dst, int ttl, u16 ipid, u8 tos,
                   bool df, u8 *ipopt, int ipoptlen, u16 srcport, u16 dstport,
                   const char *data, u16 datalen, u32 *pktlen, bool badsum)
{
  struct udp_hdr *udp;
  u32 udplen;
  u8 *pkt;

  udp = (struct udp_hdr*)udp_build(srcport, dstport, data, datalen, &udplen);
  udp->check = ip4_pseudocheck(src, dst, IPPROTO_UDP, udplen, udp);
  if (badsum)
    udp->check = 0xffff;

  pkt = ip4_build(src, dst, IPPROTO_UDP, ttl, ipid, tos, df, ipopt,
      ipoptlen, (char*)udp, udplen, pktlen);

  free(udp);
  return pkt;
}
