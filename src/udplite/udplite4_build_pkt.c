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

#include <ncsnet/udplite.h>

u8 *udplite4_build_pkt(const ip4_t src, const ip4_t dst, int ttl, u16 ipid, u8 tos,
                       u16 off, u8 *ipopt, int ipoptlen, u16 srcport, u16 dstport,
                       u16 checkcrg, u8 *frame, size_t frmlen, size_t *pktlen,
                       bool badsum)
{
  udpliteh_t *udplite;
  size_t udplitelen;
  u8 *pkt;

  udplite=(udpliteh_t*)udplite_build(srcport, dstport, frame, frmlen, &udplitelen);
  if (!udplite)
    return NULL;
  udplite4_check((u8*)udplite, udplitelen, src, dst, checkcrg, badsum);
  pkt=ip4_build(src, dst, IPPROTO_UDPLITE, ttl, ipid, tos, off, ipopt, ipoptlen,
    (u8*)udplite, udplitelen, pktlen);

  free(udplite);
  return pkt;
}

