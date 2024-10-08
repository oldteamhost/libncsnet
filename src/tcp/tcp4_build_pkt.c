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

#include <ncsnet/tcp.h>

u8 *tcp4_build_pkt(const ip4_t src, const ip4_t dst, u8 ttl, u16 id, u8 tos, u16 off,
                   u8 *ipopt, size_t ipoptlen, u16 srcport, u16 dstport,
                   u32 seq, u32 ack, u8 reserved, u8 flags, u16 win, u16 urp,
                   u8 *opt, size_t optlen, u8 *frame, size_t frmlen,
                   size_t *pktlen, bool badsum)
{
  size_t tcplen;
  tcph_t *tcp;
  u8 *pkt;

  tcp=(tcph_t*)tcp_build(srcport, dstport, seq, ack, reserved, flags, win, urp,
    opt, optlen, frame, frmlen, &tcplen);
  if (!tcp)
    return NULL;
  tcp4_check((u8*)tcp, tcplen, src, dst, badsum);
  pkt=ip4_build(src, dst, IPPROTO_TCP, ttl, id, tos, off, ipopt, ipoptlen,
    (u8*)tcp, tcplen, pktlen);

  free(tcp);
  return pkt;
}
