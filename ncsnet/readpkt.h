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

#ifndef NCSREADPKTHDR
#define NCSREADPKTHDR

#include <stdarg.h>

#include "igmp.h"
#include "ip.h"
#include "eth.h"
#include "sctp.h"
#include "arp.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "utils.h"
#include "inet.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define RECV_BUFFER_SIZE 60000

#define TRACE_PKT_SENT 1
#define TRACE_PKT_RCVD 0

#define LOW_DETAIL     1
#define MEDIUM_DETAIL  2
#define HIGH_DETAIL    3

__BEGIN_DECLS

struct abstract_iphdr {
  u8 version, proto, ttl;
  struct sockaddr_storage src, dst;
  u32 ipid;
};

struct link_header {
  int datalinktype;
  int headerlen;
#define MAX_LINK_HEADERSZ 24
  u8 header[MAX_LINK_HEADERSZ];
};

void        read_util_tracepkt(int pdir, const u8 *pkt, u32 len, double rtt, int detail);
const char *read_ippktinfo(const u8 *pkt, u32 len, int detail);
bool  read_util_validate_tcp(const u8 *tcpc, unsigned len);
bool  read_util_validate_pkt(const u8 *ipc, unsigned *len);
int   read_util_datalinkoffset(int datalink);
const void *read_util_getip4data_pr(const void *pkt, u32 *len, struct abstract_iphdr *hdr, bool upperlayer_onl);
const void *read_util_getip6data_pr(const struct ip6_hdr *ip6, u32 *len, u8 *nxt, bool upperlayer_only);
const void *read_util_ip4getdata_up(const struct ip4_hdr *ip, u32 *len);
const void *read_util_icmp4getdata(const struct icmp4_hdr *icmp, u32 *len);
const void *read_util_icmp6getdata(const struct icmp6_hdr *icmp, u32 *len);
char       *read_util_nexthdrtoa(u8 nxthdr, int acronym);
void        read_util_tcpoptinfo(u8 *optp, int len, char *result, int bufsize);
char       *read_util_fmtipopt(const u8 *ipopt, int ipoptlen);
#define     read_util_ip4getdata(pkt, len, hdr) read_util_getip4data_pr((pkt), (len), (hdr), true)
#define     read_util_ip4getdata_any(pkt, len, hdr) read_util_getip4data_pr((pkt), (len), (hdr), false)
#define     read_util_ip6getdata(ip6, len, nxt) read_util_getip6data_pr((ip6), (len), (nxt), true)
#define     read_util_ip6getdata_any(ip6, len, nxt) read_util_getip6data_pr((ip6), (len), (nxt), false)

/* OLD */
struct ip4_hdr*   ext_iphdr(u8 *buf);
struct tcp_hdr*  ext_tcphdr(u8 *buf);
struct udp_hdr*  ext_udphdr(u8 *buf);
struct icmp4_hdr* ext_icmphdr(u8 *buf);
struct igmp_hdr* ext_igmphdr(u8 *buf);

void print_ipdr(const struct ip4_hdr *iphdr);
void print_tcphdr(const struct tcp_hdr *tcphdr);
void print_udphdr(const struct udp_hdr *udphdr);
void print_icmphdr(const struct icmp4_hdr *icmphdr);
void print_payload(const u8 *payload, int len);
void print_payload_ascii(const u8 *payload, int len);

__END_DECLS


#endif


