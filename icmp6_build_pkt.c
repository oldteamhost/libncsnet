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

#include "ncsnet/icmp.h"
#include "ncsnet/ip.h"

u8 *icmp6_build_pkt(const struct in6_addr *src, const struct in6_addr *dst,
                    u8 tc, u32 flowlabel, u8 hoplimit, u16 seq, u16 id, u8 type,
                    u8 code, const char *data, u16 datalen, u32 *pktlen,
                    bool badsum)
{
  struct icmp6_hdr *icmpv6;
  union icmp6_msg *msg;
  u32 icmplen;
  char *pkt;
  u8 *ipv6;

  pkt = (char*)malloc(sizeof(*icmpv6) + sizeof(*msg) + datalen);
  if (!pkt)
    return NULL;
  icmpv6 = (struct icmp6_hdr*)pkt;
  msg = (union icmp6_msg*)(pkt + sizeof(*icmpv6));

  memset(icmpv6, 0, sizeof(*icmpv6));
  icmplen = sizeof(*icmpv6);
  icmpv6->type = type;
  icmpv6->code = code;

#define ICMP6_ECHO 128
  if (type == ICMP6_ECHO) {
    msg->echo.icmpv6_seq = htons(seq);
    msg->echo.icmpv6_id = htons(id);
    icmplen += sizeof(msg->echo);
  }

  memcpy(pkt + icmplen, data, datalen);
  icmplen += datalen;

  icmpv6->check = 0;
  icmpv6->check = ip6_pseudocheck(src, dst, IPPROTO_ICMPV6,
      icmplen, icmpv6);
  if (badsum)
    icmpv6->check--;

  ipv6 = ip6_build(src, dst, tc, flowlabel, IPPROTO_ICMPV6,
      hoplimit, pkt, icmplen, pktlen);

  free(pkt);
  return ipv6;
}
