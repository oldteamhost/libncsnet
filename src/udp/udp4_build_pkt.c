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
                   const char *data, size_t *pktlen, bool badsum)
{
  size_t udplen;
  udph_t *udp;
  u8 *pkt;

  udp = (udph_t*)udp_build(srcport, dstport, data, &udplen);
  if (!udp)
    return NULL;
  udp4_check((u8*)udp, udplen, src, dst, badsum);
  pkt = ip4_build(src, dst, IPPROTO_UDP, ttl, ipid, tos, df, ipopt,
      ipoptlen, (u8*)udp, udplen, pktlen);

  free(udp);
  return pkt;
}
