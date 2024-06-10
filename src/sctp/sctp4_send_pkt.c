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

#include <ncsnet/sctp.h>

int sctp4_send_pkt(struct ethtmp *eth, int fd, const u32 src, const u32 dst,
                   int ttl, bool df, u8 *ipops, int ipoptlen, u16 srcport,
                   u16 dstport, char *chunks, int chunkslen, u32 vtag,
                   const char *data, u16 datalen, int mtu, bool adler32sum,
                   bool badsum)
{
  struct sockaddr_storage _dst;
  struct sockaddr_in *dst_in;
  int res = -1;
  u32 pktlen;
  u8 *pkt;

  pkt = sctp4_build_pkt(src, dst, ttl, random_u16(),
      0, df, ipops, ipoptlen, srcport, dstport, vtag, chunks,
      chunkslen, data, datalen, &pktlen,
      adler32sum, badsum);
  if (!pkt)
    return -1;

  memset(&_dst, 0, sizeof(_dst));
  dst_in = (struct sockaddr_in*)&_dst;
  dst_in->sin_family = AF_INET;
  dst_in->sin_addr.s_addr = dst;
  res = ip_send(eth, fd, &_dst, mtu, pkt, pktlen);

  free(pkt);
  return res;
}
