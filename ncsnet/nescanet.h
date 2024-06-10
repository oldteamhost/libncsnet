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

#ifndef NESCANETHDR
#define NESCANETHDR

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "utils.h"
#include "ip.h"
#include "tcp.h"
#include "icmp.h"
#include "udp.h"
#include "sctp.h"
#include "igmp.h"
#include "readpkt.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define NCSRAWBUILD_ERRBUF_MAXLEN       512
#define NCSRAWBUILD_FMT_MAXLEN          65535
#define NCSRAWBUILD_PROTOS_MAXLEN       512
#define NCSRAWBUILD_TOKEN_PROTO_OPEN    '['
#define NCSRAWBUILD_TOKEN_PROTO_CLOSE   ']'
#define NCSRAWBUILD_TOKEN_IP4_IDENT     "ip4"
#define NCSRAWBUILD_TOKEN_IP6_IDENT     "ip6"
#define NCSRAWBUILD_TOKEN_IP4_IDENT_1   "ip"
#define NCSRAWBUILD_TOKEN_TCP_IDENT     "tcp"
#define NCSRAWBUILD_TOKEN_ICMP4_IDENT   "icmp4"
#define NCSRAWBUILD_TOKEN_ICMP4_IDENT_1 "icmp"
#define NCSRAWBUILD_TOKEN_ICMP6_IDENT   "icmp6"
#define NCSRAWBUILD_TOKEN_UDP_IDENT     "udp"
#define NCSRAWBUILD_TOKEN_SCTP_IDENT    "sctp"
#define NCSRAWBUILD_TOKEN_IGMP_IDENT    "igmp"
#define NCSRAWBUILD_TOKEN_SPEC_DEL      ","
#define NCSRAWBUILD_TOKEN_OPT_DEL       '='
#define NCSRAWBUILD_TOKEN_LOCALIP   "local"
#define NCSRAWBUILD_TOKEN_LOCALIP_1 "localhost"
#define NCSRAWBUILD_PROTO_IP4       0
#define NCSRAWBUILD_IP4HDR_SRC      "src"
#define NCSRAWBUILD_IP4HDR_DST      "dst"
#define NCSRAWBUILD_IP4HDR_PROTO    "proto"
#define NCSRAWBUILD_IP4HDR_TTL      "ttl"
#define NCSRAWBUILD_IP4HDR_ID       "ipid"
#define NCSRAWBUILD_IP4HDR_TOS      "tos"
#define NCSRAWBUILD_IP4HDR_DF       "df"
#define NCSRAWBUILD_IP4HDR_OPT      "ipopt"
#define NCSRAWBUILD_PROTO_TCP       1
#define NCSRAWBUILD_TCPHDR_SRCPORT  "srcport"
#define NCSRAWBUILD_TCPHDR_DSTPORT  "dstport"
#define NCSRAWBUILD_TCPHDR_SEQ      "seq"
#define NCSRAWBUILD_TCPHDR_ACK      "acknum"
#define NCSRAWBUILD_TCPHDR_RESERVED "reserved"
#define NCSRAWBUILD_TCPHDR_WINDOW   "win"
#define NCSRAWBUILD_TCPHDR_URP      "urp"
#define NCSRAWBUILD_TCPHDR_OPT      "tcpopt"
#define NCSRAWBUILD_TCPHDR_DATA     "payload"
#define NCSRAWBUILD_TCPHDR_FLAGS    "flags"
#define NCSRAWBUILD_PROTO_UDP       2
#define NCSRAWBUILD_UDPHDR_SRCPORT  "srcport"
#define NCSRAWBUILD_UDPHDR_DSTPORT  "dstport"
#define NCSRAWBUILD_UDPHDR_DATA     "payload"
#define NCSRAWBUILD_PROTO_ICMP4     3
#define NCSRAWBUILD_ICMP4HDR_TYPE   "type"
#define NCSRAWBUILD_ICMP4HDR_CODE   "code"
#define NCSRAWBUILD_ICMP4HDR_ID     "icmpid"
#define NCSRAWBUILD_ICMP4HDR_SEQ    "seq"
#define NCSRAWBUILD_ICMP4HDR_DATA   "payload"
#define NCSRAWBUILD_PROTO_IGMP      4
#define NCSRAWBUILD_IGMPHDR_TYPE    "type"
#define NCSRAWBUILD_IGMPHDR_CODE    "code"
#define NCSRAWBUILD_IGMPHDR_DATA    "payload"
#define NCSRAWBUILD_HDR_BADSUM      "badsum"
#define NCSRAW_OPT_SEND_TRACE     0
#define NCSRAW_OPT_FRAGMENT       1
#define NCSRAW_OPT_SEND_DELAY     2
#define NCSRAW_OPT_SEND_CUSTOM_FD 3
#define NCSRAW_OPT_SEND_RANDOM_FD 4

struct nescanetraw_opts
{
  long long delay;
  bool randomfd;
  int trace;
};

struct nescanetraw
{
  struct sockaddr_storage dst_in;
  struct nescanetraw_opts no;
  int mtu;  
  u8 *pkt;
  u32 pktlen;
  int fd;
};

typedef struct nescanetraw ncsraw_t;

ncsraw_t *ncsraw_init(void);
void      ncsraw_build(ncsraw_t *n, char *errbuf, const char *fmt, ...);
#define   ncsraw_option(n, option, val)			      \
  _Generic((val),					      \
	   const char*: __opt_str,			      \
	   char*: __opt_str,				      \
	   default: __opt_num				      \
	   )(n, option, val)
ssize_t   ncsraw_send(ncsraw_t *n);
void      ncsraw_free(ncsraw_t *n);

void __opt_str(ncsraw_t *n, int option, const char *val);
void __opt_num(ncsraw_t *n, int option, size_t val);

#endif
