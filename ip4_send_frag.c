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

#include "ncsnet/ip.h"

int ip4_send_frag(int fd, const struct sockaddr_in *dst, const u8 *pkt,
                  u32 pktlen, u32 mtu)
{
  int fdatalen = 0, res = 0, fragment = 0, headerlen;
  struct ip4_hdr *ip;
  u32 datalen;
  u8 *fpkt;

  ip = (struct ip4_hdr*)pkt;
  headerlen = ip->ihl* 4;
  datalen = pktlen - headerlen;

  assert(headerlen <= (int)pktlen);
  assert(headerlen >= 20 && headerlen <= 60); /* sanity check (RFC791) */
  assert(mtu > 0 && mtu % 8 == 0);

  if (datalen <= mtu)
    return ip4_send_raw(fd, dst, pkt, pktlen);

  fpkt = (u8*)malloc(headerlen + mtu);
  memcpy(fpkt, pkt, headerlen + mtu);
  ip = (struct ip4_hdr*)fpkt;

  for (fragment = 1; fragment * mtu < datalen + mtu; fragment++) {
    fdatalen = (fragment * mtu <= datalen ? mtu : datalen % mtu);
    ip->totlen = htons(headerlen + fdatalen);
    ip->off = htons((fragment - 1) * mtu / 8);
    if ((fragment - 1) * mtu + fdatalen < datalen)
      ip->off |= htons(IP4_MF);
    ip->check = 0;
    ip->check = in_check((u16*) ip, headerlen);
    if (fragment > 1)
      memcpy(fpkt + headerlen, pkt + headerlen + (fragment - 1) * mtu, fdatalen);
    res = ip4_send_raw(fd, dst, fpkt, ntohs(ip->totlen));
    if (res == -1)
      break;
  }

  free(fpkt);
  return res;
}
