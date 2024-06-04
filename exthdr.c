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

#include "ncsnet/eth.h"
#include "ncsnet/icmp.h"
#include "ncsnet/igmp.h"
#include "ncsnet/readpkt.h"

struct ip4_hdr* ext_iphdr(u8 *buf)
{
  struct ip4_hdr *iphdr;
  iphdr = (struct ip4_hdr*)(buf + sizeof(struct eth_hdr));
  return iphdr;
}

struct tcp_hdr* ext_tcphdr(u8 *buf)
{
  struct tcp_hdr *tcphdr;
  tcphdr = (struct tcp_hdr*)(buf + sizeof(struct eth_hdr) + sizeof(struct ip4_hdr));
  return tcphdr;
}

struct udp_hdr* ext_udphdr(u8 *buf)
{
  struct udp_hdr *udphdr;
  udphdr = (struct udp_hdr *)(buf + sizeof(struct eth_hdr) + sizeof(struct ip4_hdr));
  return udphdr;
}

struct icmp4_hdr* ext_icmphdr(u8 *buf)
{
  struct icmp4_hdr *icmphdr;
  icmphdr = (struct icmp4_hdr *)(buf + sizeof(struct eth_hdr) + sizeof(struct ip4_hdr));
  return icmphdr;
}

struct igmp_hdr* ext_igmphdr(u8 *buf)
{
  struct igmp_hdr *igmphdr;
  igmphdr = (struct igmp_hdr *)(buf + sizeof(struct eth_hdr) + sizeof(struct ip4_hdr));
  return igmphdr;
}
