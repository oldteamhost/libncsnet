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
#include "ncsnet/readpkt.h"

void ip4_recheck(u8 *pkt, u32 pktlen)
{
  struct abstract_iphdr ip;
  struct ip4_hdr *ipreal;
  struct tcp_hdr *tcp;
  struct udp_hdr *udp;
  struct sctp_hdr *sctp;
  struct igmp_hdr *igmp;
  struct icmp4_hdr *icmp;        
  const u8 *res = NULL;
  
  res = (u8*)read_util_ip4getdata_any(pkt, &pktlen, &ip);
  if (ip.version == 4) {
    ipreal = (struct ip4_hdr*)pkt;
    if (ip.proto == IPPROTO_TCP) {
      tcp = (struct tcp_hdr*)res;
      tcp->th_sum = 0;
      tcp->th_sum = ip4_pseudocheck(ipreal->src, ipreal->dst, IPPROTO_TCP, pktlen, tcp);
    }
    else if (ip.proto == IPPROTO_UDP) {
      udp = (struct udp_hdr*)res;
      sctp->check = 0;
      udp->check = ip4_pseudocheck(ipreal->src, ipreal->dst, IPPROTO_UDP, pktlen, tcp);
    }
    else if (ip.proto == IPPROTO_SCTP) {
      sctp = (struct sctp_hdr*)res;
      sctp->check = 0;
      sctp->check = htonl(crc32((u8*)res, pktlen, NULL));
    }
    else if (ip.proto == IPPROTO_IGMP) {
      igmp = (struct igmp_hdr*)res;
      igmp->check = 0;
      igmp->check = in_check((u16*)res, pktlen);
    }
    else if (ip.proto == IPPROTO_ICMP) {
      icmp = (struct icmp4_hdr*)res;
      icmp->check = 0;
      icmp->check = in_check((u16*)res, pktlen);
    }            
    ipreal->check = 0;
    ipreal->check = ip_check_add((u16*)ipreal, sizeof(struct ip4_hdr) + (4 * (ipreal->ihl - 5)), 0);
  }
}
