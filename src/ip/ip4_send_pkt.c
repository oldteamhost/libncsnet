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
#include <ncsnet/utils.h>

int ip4_send_pkt(int fd, u32 src, u32 dst, u16 ttl, u8 proto, bool df,
                 const u8 *opt, int optlen, const char *data, u16 datalen,
                 int mtu)
{
  struct sockaddr_in dst_in;
  u32 pktlen;
  int res = -1;
  u8 *pkt;

  pkt = ip4_build(src, dst, proto, ttl, random_u16(), 5, df,
      opt, optlen, data, datalen, &pktlen);
  if (!pkt)
    return -1;

  memset(&dst_in, 0, sizeof(struct sockaddr_in));
  dst_in.sin_addr.s_addr = dst;
  dst_in.sin_port = 0;
  dst_in.sin_family = AF_INET;

  res = ip4_send(NULL, fd, &dst_in, mtu, pkt, pktlen);

  free(pkt);
  return res;
}

