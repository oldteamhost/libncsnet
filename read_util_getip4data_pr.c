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

#include "ncsnet/readpkt.h"

const void *read_util_getip4data_pr(const void *pkt, u32 *len, struct abstract_iphdr *hdr, bool upperlayer_only)
{
  const struct ip4_hdr *ip;
  ip = (struct ip4_hdr *)pkt;
  
  if (*len >= 20 && ip->version == 4) {
    struct sockaddr_in *sin;
    hdr->version = 4;
    sin = (struct sockaddr_in *) &hdr->src;
    memset(&hdr->src, 0, sizeof(hdr->src));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip->src;

    sin = (struct sockaddr_in *) &hdr->dst;
    memset(&hdr->dst, 0, sizeof(hdr->dst));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip->dst;

    hdr->proto = ip->proto;
    hdr->ttl = ip->ttl;
    hdr->ipid = ntohs(ip->id);
    return read_util_ip4getdata_up(ip, len);
  }
  else if (*len >= 40 && ip->version == 6) {
    const struct ip6_hdr *ip6 = (struct ip6_hdr*) ip;
    struct sockaddr_in6 *sin6;
    hdr->version = 6;
    sin6 = (struct sockaddr_in6 *) &hdr->src;
    memset(&hdr->src, 0, sizeof(hdr->src));
    sin6->sin6_family = AF_INET6;
    memcpy(&sin6->sin6_addr, &ip6->ip6_src, IP6_ADDR_LEN);

    sin6 = (struct sockaddr_in6 *) &hdr->dst;
    memset(&hdr->dst, 0, sizeof(hdr->dst));
    sin6->sin6_family = AF_INET6;
    memcpy(&sin6->sin6_addr, &ip6->ip6_dst, IP6_ADDR_LEN);

    hdr->ttl = ip6->IP6_HLIM;
    hdr->ipid = ntohl(ip6->IP6_FLOW & IP6_FLOWLABEL_MASK);
    return read_util_getip6data_pr(ip6, len, &hdr->proto, upperlayer_only);
  }
  return NULL;
}
