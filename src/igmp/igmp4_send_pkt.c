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

#include <ncsnet/igmp.h>

int igmp4_send_pkt(struct ethtmp *eth, int fd, const u32 src, const u32 dst,
                   int ttl, bool df, u8 *ipops, int ipoptlen, u16 ipid, u8 tos,
                   u8 type, u8 code, const char *data, size_t datalen, int mtu,
                   bool badsum)
{
  struct sockaddr_storage _dst;
  struct sockaddr_in *dst_in;
  size_t packetlen;
  u8 *pkt;
  int res;

  pkt = igmp4_build_pkt(src, dst, ttl, ipid, tos, df, ipops,
      ipoptlen, type, code, data, datalen, &packetlen, badsum);
  if (!pkt)
    return -1;

  memset(&_dst, 0, sizeof(_dst));
  dst_in = (struct sockaddr_in*)&_dst;
  dst_in->sin_family = AF_INET;
  dst_in->sin_addr.s_addr = dst;
  
  res = ip_send(eth, fd, &_dst, mtu, pkt, packetlen);

  free(pkt);
  return res;
}
