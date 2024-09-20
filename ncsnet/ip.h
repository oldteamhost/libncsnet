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

#ifndef NCSIPHDR
#define NCSIPHDR

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "mt19937.h"
#include "ip4addr.h"
#include "ip6addr.h"
#include "eth.h"
#include "random.h"
#include "raw.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define IP_TTL_DEFAULT        64      /* default ttl, RFC 1122, RFC 1340 */
#define IP_TTL_MAX            255     /* maximum ttl */
#define IP_TOS_DEFAULT        0x00    /* default */
#define IP_TOS_LOWDELAY       0x10    /* low delay */
#define IP_TOS_THROUGHPUT     0x08    /* high throughput */
#define IP_TOS_RELIABILITY    0x04    /* high reliability */
#define IP_TOS_LOWCOST        0x02    /* low monetary cost - XXX */
#define IP_TOS_ECT            0x02    /* ECN-capable transport */
#define IP_TOS_CE             0x01    /* congestion experienced */

#define IP4_LEN_MAX           65535
#define IP4_IHL_MAX           60
#define IP4_VERSION           4
#define IP4_OPT_LEN           2       /* base IP option length */
#define IP4_OPT_LEN_MAX       40

#define IP4_RF                0x8000  /* reserved fragment flag */
#define IP4_DF                0x4000  /* dont fragment flag */
#define IP4_MF                0x2000  /* more fragments flag */
#define IP4_DM                0x1fff  /* mask for fragmenting bits */
#define IP4_OFFMASK           0x1fff  /* mask for fragment offset */

#define IP4_LEN_MIN           IP4_HDR_LEN
#define IP4_HDR_LEN_MAX       (IP4_HDR_LEN + IP4_OPT_LEN_MAX)
#define IP4_OPT_CONTROL       0x00 /* control */
#define IP4_OPT_DEBMEAS       0x40 /* debugging & measurement */
#define IP4_OPT_COPY          0x80 /* copy into all fragments */
#define IP4_OPT_RESERVED1     0x20
#define IP4_OPT_RESERVED2     0x60
#define IP4_OPT_EOL           0 /* end of option list */
#define IP4_OPT_NOP           1 /* no operation */
#define IP4_OPT_SEC           (2|IP4_OPT_COPY) /* DoD basic security */
#define IP4_OPT_LSRR          (3|IP4_OPT_COPY) /* loose source route */
#define IP4_OPT_TS            (4|IP4_OPT_DEBMEAS) /* timestamp */
#define IP4_OPT_ESEC          (5|IP4_OPT_COPY) /* DoD extended security */
#define IP4_OPT_CIPSO         (6|IP4_OPT_COPY) /* commercial security */
#define IP4_OPT_RR            7 /* record route */
#define IP4_OPT_SATID         (8|IP4_OPT_COPY) /* stream ID (obsolete) */
#define IP4_OPT_SSRR          (9|IP4_OPT_COPY) /* strict source route */
#define IP4_OPT_ZSU           10 /* experimental measurement */
#define IP4_OPT_MTUP          11 /* MTU probe */
#define IP4_OPT_MTUR          12 /* MTU reply */
#define IP4_OPT_FINN          (13|IP4_OPT_COPY|IP4_OPT_DEBMEAS) /* exp flow control */
#define IP4_OPT_VISA          (14|IP4_OPT_COPY) /* exp access control */
#define IP4_OPT_ENCODE        15 /* ??? */
#define IP4_OPT_IMITD         (16|IP4_OPT_COPY) /* IMI traffic descriptor */
#define IP4_OPT_EIP           (17|IP4_OPT_COPY) /* extended IP, RFC 1385 */
#define IP4_OPT_TR            (18|IP4_OPT_DEBMEAS) /* traceroute */
#define IP4_OPT_ADDEXT        (19|IP4_OPT_COPY) /* IPv7 ext addr, RFC 1475 */
#define IP4_OPT_RTRALT        (20|IP4_OPT_COPY) /* router alert, RFC 2113 */
#define IP4_OPT_SDB           (21|IP4_OPT_COPY) /* directed bcast, RFC 1770 */
#define IP4_OPT_NSAPA         (22|IP4_OPT_COPY) /* NSAP addresses */
#define IP4_OPT_DPS           (23|IP4_OPT_COPY) /* dynamic packet state */
#define IP4_OPT_UMP           (24|IP4_OPT_COPY) /* upstream multicast */
#define IP4_OPT_MAX           25
#define IP4_OPT_SEC_UNCLASS   0x0000 /* unclassified */
#define IP4_OPT_SEC_CONFID    0xf135 /* confidential */
#define IP4_OPT_SEC_EFTO      0x789a /* EFTO */
#define IP4_OPT_SEC_MMMM      0xbc4d /* MMMM */
#define IP4_OPT_SEC_PROG      0x5e26 /* PROG */
#define IP4_OPT_SEC_RESTR     0xaf13 /* restricted */
#define IP4_OPT_SEC_SECRET    0xd788 /* secret */
#define IP4_OPT_SEC_TOPSECRET 0x6bc5 /* top secret */

#define IP4_OPT_COPIED(o)     ((o) & 0x80)
#define IP4_OPT_CLASS(o)      ((o) & 0x60)
#define IP4_OPT_NUMBER(o)     ((o) & 0x1f)
#define IP4_OPT_TYPEONLY(o)   ((o) == IP4_OPT_EOL || (o) == IP4_OPT_NOP)

#define IP4_OPT_TS_TSONLY     0 /* timestamps only */
#define IP4_OPT_TS_TSADDR     1 /* IP address / timestamp pairs */
#define IP4_OPT_TS_PRESPEC    3 /* IP address / zero timestamp pairs */

#define IP6_HDR_LEN           40      /* ip6 header length */
#define IP6_LEN_MAX           65535   /* non-jumbo payload */
#define IP6_MTU_MIN           1280    /* minimum MTU (1024 + 256) */
#define IP6_VERSION_MASK      0xf0    /* ip6_vfc version */
#define IP6_LEN_MIN           IP6_HDR_LEN
#define IP6_VERSION           0x60
#define IP6_VERSION_MASK      0xf0 /* ip6_vfc version */
#define IP6_HLIM_DEFAULT      64
#define IP6_HLIM_MAX          255
#if (defined(LITTLE_ENDIAN_SYSTEM))
  #define IP6_FLOWINFO_MASK   0xffffff0f /* ip6_flow info (28 bits) */
  #define IP6_FLOWLABEL_MASK  0xffff0f00 /* ip6_flow label (20 bits) */
#else
  #define IP6_FLOWINFO_MASK   0x0fffffff /* ip6_flow info (28 bits) */
  #define IP6_FLOWLABEL_MASK  0x000fffff /* ip6_flow label (20 bits) */
#endif
#if (defined(LITTLE_ENDIAN_SYSTEM))
  #define IP6_OFF_MASK        0xf8ff /* mask out offset from offlg */
  #define IP6_RESERVED_MASK   0x0600 /* reserved bits in offlg */
  #define IP6_MORE_FRAG       0x0100 /* more-fragments flag */
#else
  #define IP6_OFF_MASK        0xfff8 /* mask out offset from offlg */
  #define IP6_RESERVED_MASK   0x0006 /* reserved bits in offlg */
  #define IP6_MORE_FRAG       0x0001 /* more-fragments flag */
#endif
#define IP6_OPT_PAD1          0x00 /* 00 0 00000 */
#define IP6_OPT_PADN          0x01 /* 00 0 00001 */
#define IP6_OPT_JUMBO         0xC2 /* 11 0 00010 = 194 */
#define IP6_OPT_JUMBO_LEN     6
#define IP6_OPT_RTALERT       0x05 /* 00 0 00101 */
#define IP6_OPT_RTALERT_LEN   4
#define IP6_OPT_RTALERT_MLD   0 /* Datagram contains an MLD message */
#define IP6_OPT_RTALERT_RSVP  1 /* Datagram contains an RSVP message */
#define IP6_OPT_RTALERT_ACTNET 2 /* contains an Active Networks msg */
#define IP6_OPT_LEN_MIN       2
#define IP6_OPT_TYPE_SKIP     0x00 /* continue processing on failure */
#define IP6_OPT_TYPE_DISCARD  0x40 /* discard packet on failure */
#define IP6_OPT_TYPE_FORCEICMP  0x80 /* discard and send ICMP on failure */
#define IP6_OPT_TYPE_ICMP     0xC0 /* ...only if non-multicast dst */
#define IP6_OPT_MUTABLE       0x20 /* option data may change en route */
#define IP6_OPT_TYPE(o)       ((o) & 0xC0) /* high 2 bits of opt_type */

struct ip6_ext_data_routing { u8 type, segleft; };
struct ip6_ext_data_fragment { u16 offlg; u32 ident; };
struct ip6_ext_data_routing0 {
  u8 type, segleft, reserved;
  u8 slmap[3];
  ip6_t addr[1];
};
struct ip_opt_data_sec { u16 s, c, h; u8 tcc[3]; };
struct ip_opt_data_rr { u8 ptr; u32 iplist[]; };
struct ip_opt_data_tr { u16 id, ohc, rhc; u32 origip; };
struct ip_opt_data_ts { u8 ptr;
#if (defined(LITTLE_ENDIAN_SYSTEM))
  u8 flg:4, oflw:4;
#else
  u8 oflw:4, flg:4;
#endif
  u32 ipts[];
};

struct ip_opt
{
  u8 type, len;
  union ip_opt_data {
    struct ip_opt_data_sec sec; /* IP_OPT_SEC */
    struct ip_opt_data_rr rr;   /* IP4_OPT_{L,S}RR */
    struct ip_opt_data_ts ts;   /* IP4_OPT_TS */
    u16 satid; /* IP4_OPT_SATID */
    u16 mtu; /* IP4_OPT_MTU{P,R} */
    struct ip_opt_data_tr tr; /* IP4_OPT_TR */
    u32 addext[2]; /* IP4_OPT_ADDEXT */
    u16 rtralt; /* IP4_OPT_RTRALT */
    u32 sdb[9]; /* IP4_OPT_SDB */
    u8 data8[IP4_OPT_LEN_MAX - IP4_OPT_LEN];
  } opt_data;
};

struct ip6_ext_hdr {
  u8 nxt; /* next header */
  u8 len; /* following length in units of 8 octets */
  union {
    struct ip6_ext_data_routing	 routing;
    struct ip6_ext_data_fragment fragment;
  } ext_data;
};

struct ip4_hdr
{
#if (defined(LITTLE_ENDIAN_SYSTEM))
  u8    ihl:4;     /* header length */
  u8    version:4; /* ip proto version */
#else
  u8    version:4; /* ip proto version */
  u8    ihl:4;     /* header length */
#endif
  u8    tos;       /* type of service */
  u16   totlen;    /* total length */
  u16   id;        /* identificator */
  u16   off;       /* fragment offset */
  u8    ttl;       /* time to live */
  u8    proto;
  u16   check;     /* 16 bit checksum */
  ip4_t src, dst;  /* src and dst ip address */
};

typedef struct ip4_hdr ip4h_t;

struct ip6_hdr
{
  /*
   * total                       (32)
   * version        4 bits       (28)
   * traffic class  8 bits       (20)
   * flow label     20 bits      (0)
   */
  u8    flags[4];

  u16   totlen;   /* payload len*/
  u8    nxt;      /* next header (proto) */
  u8    hoplimit; /* hop limit (ttl) */
  ip6_t src, dst; /* src and dst ip6 address */
};

typedef struct ip6_hdr ip6h_t;

#define ip_check_carry(x) \
  (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
#define IP4_SEND_ETH_OR_SD(fd, eth, dst, pkt, pktlen) \
  ((eth) ? ip4_send_eth((eth), (pkt), (pktlen)) \
   : ip4_send_raw((fd), (dst), (pkt), (pktlen)))
#define IP6_SEND_ETH_OR_SD(fd, eth, dst, pkt, pktlen) \
  ((eth) ? ip6_send_eth((eth), (pkt), (pktlen)) \
   : sendto((fd), (pkt), (pktlen), 0, (dst), sizeof(*dst)))

__BEGIN_DECLS

u8 *ip4_build(const ip4_t src, const ip4_t dst, u8 proto, int ttl, u16 id, u8 tos, u16 off,
              u8 *opts, int optslen, u8 *frame, size_t frmlen,
              size_t *pktlen);

u8 *ip6_build(const ip6_t src, const ip6_t dst, u8 tc, u32 flowlabel, u8 nexthdr, int hoplimit,
              u8 *frame, size_t frmlen, size_t *pktlen);

void  ip4_check(u8 *frame, size_t frmlen, bool badsum);
int   ip_check_add(const void *buf, size_t len, int check);
u16   in_check(u16 *ptr, int nbytes);
void  ip4_recheck(u8 *pkt, u32 pktlen);

u16 ip4_pseudocheck(const ip4_t src, const ip4_t dst, u8 proto, u16 len, const void *hstart);
u16 ip6_pseudocheck(const ip6_t src, const ip6_t dst, u8 nxt, u32 len, const void *hstart);

int ip4_send_frag(int fd, const struct sockaddr_in *dst, const u8 *frame,
                  size_t frmlen, u32 mtu);

int ip4_send(struct ethtmp *eth, int fd, const struct sockaddr_in *dst,
             int mtu, const u8 *frame, size_t frmlen);

int ip6_send(struct ethtmp *eth, int fd, const struct sockaddr_in6 *dst,
             const u8 *frame, size_t frmlen);

int ip_send(struct ethtmp *eth, int fd, const struct sockaddr_storage *dst,
            int mtu, const u8 *frame, size_t frmlen);

int ip4_send_pkt(int fd, ip4_t src, ip4_t dst, u16 ttl, u8 proto, u16 off, u8 *opt,
                 int optlen, const char *data, size_t datalen, int mtu);

char *ip4_util_strsrc(void);
int   ip4_util_strdst(const char* dns, char* ipbuf, size_t buflen);
char *ip6_util_strsrc(void);
int   ip6_util_strdst(const char *dns, char *ipbuf, size_t buflen);

int   ip4_send_raw(int fd, const struct sockaddr_in *dst, const u8 *frame, size_t frmlen);
int   ip4_send_eth(struct ethtmp *eth, const u8 *frame, size_t frmlen);
int   ip6_send_eth(struct ethtmp *eth, const u8 *frame, size_t frmlen);

/* ipaddr.c */
char *ip_ntoa(const ip4_t *ip4);
char *ip6_ntoa(const ip6_t *ip6);

__END_DECLS

#endif
