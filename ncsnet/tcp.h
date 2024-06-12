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

#ifndef NCSTCPHDR
#define NCSTCPHDR

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

#include "eth.h"
#include "utils.h"
#include "mt19937.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define TCP_HDR_LEN         20
#define TCP_OPT_LEN         2
#define TCP_OPT_LEN_MAX     40
#define TCP_HDR_LEN_MAX     (TCP_HDR_LEN + TCP_OPT_LEN_MAX)
#define TCP_PAYLOAD_LEN_MAX 65495

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_CWR 0x80
#define TCP_FLAG_ECE 0x40

enum TCP_FLAGS {
  URG = TCP_FLAG_URG,
  ACK = TCP_FLAG_ACK,
  PSH = TCP_FLAG_PSH,
  RST = TCP_FLAG_RST,
  SYN = TCP_FLAG_SYN,
  CWR = TCP_FLAG_CWR,
  ECE = TCP_FLAG_ECE,        
  FIN = TCP_FLAG_FIN
};

#define TCP_OPT_EOL         0   /* End of Option List (RFC793)                 */
#define TCP_OPT_NOP         1   /* No-Operation (RFC793)                       */
#define TCP_OPT_MSS         2   /* Maximum Segment Size (RFC793)               */
#define TCP_OPT_WSCALE      3   /* WSOPT - Window Scale (RFC1323)              */
#define TCP_OPT_SACKOK      4   /* SACK Permitted (RFC2018)                    */
#define TCP_OPT_SACK        5   /* SACK (RFC2018)                              */
#define TCP_OPT_ECHOREQ     6   /* Echo (obsolete) (RFC1072)(RFC6247)          */
#define TCP_OPT_ECHOREP     7   /* Echo Reply (obsolete) (RFC1072)(RFC6247)    */
#define TCP_OPT_TSTAMP      8   /* TSOPT - Time Stamp Option (RFC1323)         */
#define TCP_OPT_POCP        9   /* Partial Order Connection Permitted (obsol.) */
#define TCP_OPT_POSP        10  /* Partial Order Service Profile (obsolete)    */
#define TCP_OPT_CC          11  /* CC (obsolete) (RFC1644)(RFC6247)            */
#define TCP_OPT_CCNEW       12  /* CC.NEW (obsolete) (RFC1644)(RFC6247)        */
#define TCP_OPT_CCECHO      13  /* CC.ECHO (obsolete) (RFC1644)(RFC6247)       */
#define TCP_OPT_ALTCSUMREQ  14  /* TCP Alternate Checksum Request (obsolete)   */
#define TCP_OPT_ALTCSUMDATA 15  /* TCP Alternate Checksum Data (obsolete)      */
#define TCP_OPT_MD5         19  /* MD5 Signature Option (obsolete) (RFC2385)   */
#define TCP_OPT_SCPS        20  /* SCPS Capabilities                           */
#define TCP_OPT_SNACK       21  /* Selective Negative Acknowledgements         */
#define TCP_OPT_QSRES       27  /* Quick-Start Response (RFC4782)              */
#define TCP_OPT_UTO         28  /* User Timeout Option (RFC5482)               */
#define TCP_OPT_AO          29  /* TCP Authentication Option (RFC5925)         */

struct tcp_hdr
{
  u16 th_sport;  /* Source port. */
  u16 th_dport;  /* Destination port. */
  u32 th_seq;    /* Sequence number. */
  u32 th_ack;    /* Acknowledgement number. */
#if (defined(LITTLE_ENDIAN_SYSTEM))
  u8  th_x2:4;   /* (unused). */
  u8  th_off:4;  /* Data offset. */
#else
  u8  th_off:4;  /* Data offset. */
  u8  th_x2:4;   /* (unused). */
#endif
  u8  th_flags;  /* TCP flags. */
  u16 th_win;    /* Window. */
  u16 th_sum;    /* Checksum. */
  u16 th_urp;    /* Urgent pointer. */
};

struct tcp_flags
{

  u8 syn; /* Synchronize sequence numbers. */
  u8 ack; /* Acknowledgment field significant. */
  u8 rst; /* Reset the connection. */
  u8 fin; /* No more data from sender. */
  u8 psh; /* Push Function. */
  u8 urg; /* Urgent Pointer field significant. */
  u8 cwr; /* Congestion Window reduced. */
  u8 ece; /* Explicit Congestion notification echo. */
};

struct tcp_opthdr
{
  u8    opt_type;        /* option type */
  u8    opt_len;         /* option length >= TCP_OPT_LEN */
  union tcp_opt_data {
    u16 mss;          /* TCP_OPT_MSS */
    u8  wscale;        /* TCP_OPT_WSCALE */
    u16 sack[19];     /* TCP_OPT_SACK */
    u32 echo;         /* TCP_OPT_ECHO{REPLY} */
    u32 timestamp[2]; /* TCP_OPT_TIMESTAMP */
    u32 cc;           /* TCP_OPT_CC{NEW,ECHO} */
    u8  cksum;         /* TCP_OPT_ALTSUM */
    u8  md5[16];       /* TCP_OPT_MD5 */
    u8  data8[TCP_OPT_LEN_MAX - TCP_OPT_LEN];
  } opt_data;
};

__BEGIN_DECLS

u8 *tcp_build(u16 srcport, u16 dstport, u32 seq, u32 ack, u8 reserved, u8 flags,
              u16 win, u16 urp, const u8 *opt, int optlen, const char *data,
              u16 datalen, u32 *pktlen);

u8 *tcp4_build_pkt(u32 src, u32 dst, u8 ttl, u16 id, u8 tos, bool df,
                   const u8 *ipopt, int ipoptlen, u16 srcport, u16 dstport,
                   u32 seq, u32 ack, u8 reserved, u8 flags, u16 win, u16 urp,
                   const u8 *opt, int optlen, const char *data, u16 datalen,
                   u32 *pktlen, bool badsum);

u8 *tcp6_build_pkt(const struct in6_addr *src, const struct in6_addr *dst,
                   u8 tc, u32 flowlabel, u8 hoplimit, u16 srcport, u16 dstport,
                   u32 seq, u32 ack, u8 reserved, u8 flags, u16 win, u16 urp,
                   const u8 *opt, int optlen, const char *data, u16 datalen,
                   u32 *pktlen, bool badsum);

int tcp4_send_pkt(struct ethtmp *eth, int fd, const u32 src, const u32 dst,
                  int ttl, bool df, u8 *ipops, int ipoptlen, u16 srcport,
                  u16 dstport, u32 seq, u32 ack, u8 reserved, u8 flags, u16 win,
                  u16 urp, u8 *opt, int optlen, const char *data, u16 datalen,
                  int mtu, bool badsum);

int tcp4_qsend_pkt(int fd, const char *src, const char *dst, int ttl,
                   u16 dstport, u8 flags, const char *data, u16 datalen);

#define TCP_SYN_PACKET            6
#define TCP_XMAS_PACKET           7
#define TCP_FIN_PACKET            8
#define TCP_NULL_PACKET           9
#define TCP_ACK_PACKET            10
#define TCP_WINDOW_PACKET         11
#define TCP_MAIMON_PACKET         12
#define TCP_PSH_PACKET            13

struct tcp_flags tcp_util_exflags(u8 type);
struct tcp_flags tcp_util_str_setflags(const char *flags);
struct tcp_flags tcp_util_getflags(u8 flags);
u8 tcp_util_setflags(struct tcp_flags *tf);

__END_DECLS

#endif
