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

int ip4_send_raw(int fd, const struct sockaddr_in *dst, const u8 *pkt,
                 u32 pktlen)
{
  struct sockaddr_in sock;
  struct tcp_hdr *tcp;
  struct udp_hdr *udp;
  struct ip4_hdr *ip;
  int res;

  ip = (struct ip4_hdr*)pkt;
  assert(fd >= 0);
  sock = *dst;

  if (pktlen >= 20) {
    if (ip->proto == IPPROTO_TCP && pktlen >= (u32)ip->ihl * 4 + 20) {
      tcp = (struct tcp_hdr*)((u8*)ip + ip->ihl * 4);
      sock.sin_port = tcp->th_dport;
    }
    else if (ip->proto == IPPROTO_UDP && pktlen >= (u32) ip->ihl  * 4 + 8) {
      udp = (struct udp_hdr*)((u8*)ip + ip->ihl * 4);
      sock.sin_port = udp->dstport;
    }
  }

#if (defined(IS_BSD) || (__FreeBSD_version < 1100030))
  ip->totlen = ntohs(ip->totlen);
  ip->off = ntohs(ip->off);
#endif

  res = sendto(fd, pkt, pktlen, 0, (struct sockaddr*)&sock,
		 (int)sizeof(struct sockaddr_in));

#if (defined(IS_BSD) || (IS_BSD && (__FreeBSD_version < 1100030)))
  ip->totlen = htons(ip->totlen);
  ip->off = htons(ip->off);
#endif

  return res;
}
