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

u8 *tcp_build(u16 srcport, u16 dstport, u32 seq, u32 ack, u8 reserved, u8 flags,
              u16 win, u16 urp, const u8 *opt, size_t optlen, u8 *frame, size_t frmlen,
              size_t *pktlen)
{
  tcph_t *tcp;
  u8 *pkt;

  *pktlen=sizeof(*tcp)+optlen+frmlen;
  pkt=(u8*)malloc(*pktlen);
  if (!pkt)
    return NULL;
  tcp=(tcph_t*)pkt;

  memset(tcp, 0, sizeof(*tcp));
  tcp->th_sport=htons(srcport);
  tcp->th_dport=htons(dstport);
  tcp->th_off=5+(optlen/4);
  tcp->th_flags=flags;

  if (seq)
    tcp->th_seq=htonl(seq);
  if (ack)
    tcp->th_ack=htonl(ack);
  if (reserved)
    tcp->th_x2=reserved & 0x0F;
  if (win)
    tcp->th_win=htons(win);
  else
    tcp->th_win=htons(1024);
  if (urp)
    tcp->th_urp=htons(urp);

  if (opt&&optlen)
    memcpy(pkt+sizeof(*tcp), opt, optlen);
  if (frame&&frmlen)
    memcpy(pkt+sizeof(*tcp)+optlen, frame, frmlen);

  tcp->th_sum = 0;
  return pkt;
}
