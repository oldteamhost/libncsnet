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

#ifndef NCSTRACEHDR
#define NCSTRACEHDR

#include "udp.h"
#include "tcp.h"
#include "ip.h"
#include "icmp.h"
#include "raw.h"
#include "sctp.h"
#include "utils.h"
#include "arp.h"
#include "mt19937.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define TRACE_MAX_DATA_LEN 4096
#define TRACE_PROTO_MAX_LEN 8192
#define TRACE_MAX_TOTAL_LEN 65535
#define RECV_BUFFER_SIZE 60000
#define TRACE_PKT_SENT 1
#define TRACE_PKT_RCVD 0
#define LOW_DETAIL     1
#define MEDIUM_DETAIL  2
#define HIGH_DETAIL    3

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

__BEGIN_DECLS

#define FLAG_SKIPETH  0x00000001  /* 0000 0001 */
#define FLAG_UDP      0x00000002  /* 0000 0010 */
#define FLAG_ICMP4    0x00000004  /* 0000 0100 */
#define FLAG_SCTP     0x00000008  /* 0000 1000 */
#define FLAG_IP       0x00000010  /* 0001 0000 */
#define FLAG_ETH      0x00000020  /* 0010 0000 */
#define FLAG_FRAME    0x00000040  /* 0100 0000 */
#define FLAG_TCP      0x00000080  /* 1000 0000 */
#define FLAG_ARP      0x00000100  /* 0000 0001 0000 0000 */

const char *frminfo(const u8 *frame, size_t frmlen, int detail, u32 flags);

const char *frm_info(const u8 *frame, size_t frmlen, bool *valid);
const char *ip_info(const u8 *ip, size_t iplen, int detail, struct abstract_iphdr *info);
const char *udp_info(const u8 *udp, size_t udplen, int detail);
const char *eth_info(const u8 *eth, size_t ethlen, int detail);
const char *sctp_info(const u8 *sctp, size_t sctplen, int detail);
const char *tcp_info(const u8 *tcp, size_t tcplen, int detail);
const char *icmp4_info(const u8 *icmp4, size_t icmp4len, int detail);
const char *arp_info(const u8 *arp, size_t arplen, int detail);

const char *arp_operation_info(const u8 *op, size_t oplen, u16 optype, u16 ptype, u8 plen, u8 hlen);
const char *icmp4_message_info(const u8 *msg, size_t msglen, u8 type, u8 code);
const char *sctp_chunktypestr(u8 type);
const char *sctp_chunk_info(const u8 *chunk);

const void *read_util_getip4data_pr(const void *pkt, u32 *len, struct abstract_iphdr *hdr, bool upperlayer_onl);
void        read_util_tracepkt(int pdir, const u8 *pkt, u32 len, double rtt, int detail);
const char *read_ippktinfo(const u8 *pkt, u32 len, int detail);
char       *read_hexdump(const u8 *txt, size_t txtlen);
bool        read_util_validate_tcp(const u8 *tcpc, unsigned len);
bool        read_util_validate_pkt(const u8 *ipc, unsigned *len);
int         read_util_datalinkoffset(int datalink);
const void *read_util_getip6data_pr(const struct ip6_hdr *ip6, u32 *len, u8 *nxt, bool upperlayer_only);
const void *read_util_ip4getdata_up(const struct ip4_hdr *ip, u32 *len);
const void *read_util_icmp4getdata(const icmp4h_t *icmp, u32 *len);
const void *read_util_icmp6getdata(const icmp6h_t *icmp, u32 *len);
char       *read_util_nexthdrtoa(u8 nxthdr, int acronym);
void        read_util_tcpoptinfo(u8 *optp, int len, char *result, int bufsize);
char       *read_util_fmtipopt(const u8 *ipopt, int ipoptlen);
#define     read_util_ip4getdata(pkt, len, hdr) read_util_getip4data_pr((pkt), (len), (hdr), true)
#define     read_util_ip4getdata_any(pkt, len, hdr) read_util_getip4data_pr((pkt), (len), (hdr), false)
#define     read_util_ip6getdata(ip6, len, nxt) read_util_getip6data_pr((ip6), (len), (nxt), true)
#define     read_util_ip6getdata_any(ip6, len, nxt) read_util_getip6data_pr((ip6), (len), (nxt), false)

#define hexchar_len(currentlen) (currentlen*2+1)
#define asciichar_len(currentlen) (currentlen+1)
void    asciihex(const u8 *txt, size_t txtlen, char *asciibuf, char *hexbuf);

__END_DECLS

#endif
