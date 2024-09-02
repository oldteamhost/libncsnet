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

u8 *ip6_build(const ip6_t src, const ip6_t dst, u8 tc, u32 flowlabel, u8 nexthdr, int hoplimit,
              u8 *frame, size_t frmlen, size_t *pktlen)
{
  u8 *pkt;

  pkt=frmbuild(pktlen, NULL, "u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u16(%hu),u8(%hhu),u8(%hhu)",
    ((0x06<<4)|((tc&0xF0)>>4)),(((tc&0x0F)<<4)|((flowlabel&0xF0000)>>16)),
    ((flowlabel&0x0FF00)>>8),(flowlabel&0x000FF),htons(frmlen),nexthdr,hoplimit);

  if (pkt)
    pkt=frmbuild_add(pktlen, pkt, NULL, "u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu), \
      u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu)",
      ip6t_getid(&src, 0),  ip6t_getid(&src, 1),  ip6t_getid(&src, 2),  ip6t_getid(&src, 3),
      ip6t_getid(&src, 4),  ip6t_getid(&src, 5),  ip6t_getid(&src, 6),  ip6t_getid(&src, 7),
      ip6t_getid(&src, 8),  ip6t_getid(&src, 9),  ip6t_getid(&src, 10), ip6t_getid(&src, 11),
      ip6t_getid(&src, 12), ip6t_getid(&src, 13), ip6t_getid(&src, 14), ip6t_getid(&src, 15));
  if (pkt)
    pkt=frmbuild_add(pktlen, pkt, NULL, "u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu), \
      u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu)",
      ip6t_getid(&dst, 0),  ip6t_getid(&dst, 1),  ip6t_getid(&dst, 2),  ip6t_getid(&dst, 3),
      ip6t_getid(&dst, 4),  ip6t_getid(&dst, 5),  ip6t_getid(&dst, 6),  ip6t_getid(&dst, 7),
      ip6t_getid(&dst, 8),  ip6t_getid(&dst, 9),  ip6t_getid(&dst, 10), ip6t_getid(&dst, 11),
      ip6t_getid(&dst, 12), ip6t_getid(&dst, 13), ip6t_getid(&dst, 14), ip6t_getid(&dst, 15));

  if (pkt&&frame&&frmlen)
    pkt=frmbuild_addfrm(frame, frmlen, pkt, pktlen, NULL);

  return pkt;
}
