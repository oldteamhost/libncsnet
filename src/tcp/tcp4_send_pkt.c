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

ssize_t tcp4_send_pkt(struct ethtmp *eth, int fd, const ip4_t src, const ip4_t dst,
                      int ttl, u16 off, u8 *ipops, size_t ipoptlen, u16 srcport,
                      u16 dstport, u32 seq, u32 ack, u8 reserved, u8 flags, u16 win,
                      u16 urp, u8 *opt, size_t optlen, u8 *frame, size_t frmlen, int mtu,
                      bool badsum)
{
  struct sockaddr_storage _dst;
  struct sockaddr_in *dst_in;
  size_t pktlen;
  ssize_t res;
  u8 *pkt;

  pkt=tcp4_build_pkt(src, dst, ttl, random_u16(), IP_TOS_DEFAULT,
    off, ipops, ipoptlen, srcport, dstport, seq, ack, reserved, flags,
    win, urp, opt, optlen, frame, frmlen, &pktlen, badsum);
  if (!pkt)
    return -1;

  memset(&_dst, 0, sizeof(_dst));
  dst_in=(struct sockaddr_in*)&_dst;
  dst_in->sin_family=AF_INET;
  dst_in->sin_addr.s_addr=ip4t_u32(&dst);

  res=ip_send(eth, fd, &_dst, mtu, pkt, pktlen);

  free(pkt);
  return res;
}
