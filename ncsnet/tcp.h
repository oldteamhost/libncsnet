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
#include "ip.h"
#include "utils.h"
#include "raw.h"
#include "mt19937.h"
#include "random.h"
#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define TCP_HDR_LEN         20
#define TCP_OPT_LEN         2
#define TCP_OPT_LEN_MAX     40
#define TCP_HDR_LEN_MAX     (TCP_HDR_LEN + TCP_OPT_LEN_MAX)
#define TCP_PAYLOAD_LEN_MAX 65495

#define TCP_FLAG_FIN        0x01
#define TCP_FLAG_SYN        0x02
#define TCP_FLAG_RST        0x04
#define TCP_FLAG_PSH        0x08
#define TCP_FLAG_ACK        0x10
#define TCP_FLAG_URG        0x20
#define TCP_FLAG_CWR        0x80
#define TCP_FLAG_ECE        0x40

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

enum TCP_FLAGS {URG = TCP_FLAG_URG, ACK = TCP_FLAG_ACK, PSH = TCP_FLAG_PSH, RST = TCP_FLAG_RST,
  SYN = TCP_FLAG_SYN, CWR = TCP_FLAG_CWR, ECE = TCP_FLAG_ECE, FIN = TCP_FLAG_FIN};

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

typedef struct tcp_hdr tcph_t;

struct tcp_flags {
  u8 syn; /* Synchronize sequence numbers. */
  u8 ack; /* Acknowledgment field significant. */
  u8 rst; /* Reset the connection. */
  u8 fin; /* No more data from sender. */
  u8 psh; /* Push Function. */
  u8 urg; /* Urgent Pointer field significant. */
  u8 cwr; /* Congestion Window reduced. */
  u8 ece; /* Explicit Congestion notification echo. */
};

typedef struct tcp_opt_hdr {
  u8 kind, len;
} tcp_opt;

typedef struct tcp_opt_hdr_mss {
  tcp_opt opt;
  u16 mss;
} tcp_opt_mss;

typedef struct tcp_opt_hdr_nop {
  u8 kind;
} tcp_opt_nop;

typedef struct tcp_opt_hdr_sackpr {
  tcp_opt opt;
} tcp_opt_sackpr;

typedef struct tcp_opt_hdr_wscale {
  tcp_opt opt;
  u8 shift;
} tcp_opt_wscale;

typedef struct tcp_opt_hdr_tstamp {
  tcp_opt opt;
  u32 val, erc;
} tcp_opt_tstamp;

typedef struct tcp_opt_hdr_altcheck_req {
  tcp_opt opt;
  u8 check;
} tcp_opt_altcheck_req;

__BEGIN_DECLS

u8 *tcp_build(u16 srcport, u16 dstport, u32 seq, u32 ack, u8 reserved, u8 flags,
              u16 win, u16 urp, u8 *opt, size_t optlen, u8 *frame, size_t frmlen,
              size_t *pktlen);

void tcp4_check(u8 *frame, size_t frmlen, const ip4_t src,
    const ip4_t dst, bool badsum);
void tcp6_check(u8 *frame, size_t frmlen, const ip6_t src,
    const ip6_t dst, bool badsum);

#define tcp_opt_mss_build(mss, optlen) \
  frmbuild(optlen, NULL, "u8(2), u8(4), u16(%hu)", htons((mss)))
#define tcp_opt_nop_build(optlen) \
  frmbuild(optlen, NULL, "u8(1)")
#define tcp_opt_sackpr_build(optlen) \
  frmbuild(optlen, NULL, "u8(1), u8(2)")
#define tcp_opt_wscale_build(shift, optlen) \
  frmbuild(optlen, NULL, "u8(3), u8(3), u8(%hhu)", shift)
#define tcp_opt_tstamp_build(val, erc, optlen) \
  frmbuild(optlen, NULL, "u8(8), u8(10), u32(%u), u32(%u)", htonl(val), htonl(erc))
#define tcp_opt_altcheck_req_build(check, optlen) \
  frmbuild(optlen, NULL, "u8(14), u8(3), u8(%hhu)", check)

u8 *tcp4_build_pkt(const ip4_t src, const ip4_t dst, u8 ttl, u16 id, u8 tos, u16 off,
                   u8 *ipopt, size_t ipoptlen, u16 srcport, u16 dstport,
                   u32 seq, u32 ack, u8 reserved, u8 flags, u16 win, u16 urp,
                   u8 *opt, size_t optlen, u8 *frame, size_t frmlen,
                   size_t *pktlen, bool badsum);

u8 *tcp6_build_pkt(const ip6_t src, const ip6_t dst, u8 tc, u32 flowlabel, u8 hoplimit,
                   u16 srcport, u16 dstport, u32 seq, u32 ack, u8 reserved, u8 flags,
                   u16 win, u16 urp, u8 *opt, size_t optlen, u8 *frame, size_t frmlen,
                   size_t *pktlen, bool badsum);

ssize_t tcp4_send_pkt(struct ethtmp *eth, int fd, const ip4_t src, const ip4_t dst,
                      int ttl, u16 off, u8 *ipops, size_t ipoptlen, u16 srcport,
                      u16 dstport, u32 seq, u32 ack, u8 reserved, u8 flags, u16 win,
                      u16 urp, u8 *opt, size_t optlen, u8 *frame, size_t frmlen, int mtu,
                      bool badsum);

ssize_t tcp4_qsend_pkt(int fd, const char *src, const char *dst, int ttl,
                       u16 dstport, u8 flags, u8 *frame, size_t frmlen);

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
u8               tcp_util_setflags(struct tcp_flags *tf);

__END_DECLS

#endif
