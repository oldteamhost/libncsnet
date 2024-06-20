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

#ifndef NCSICMPHDR
#define NCSICMPHDR

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "udp.h"
#include "tcp.h"
#include "ip.h"
#include "raw.h"
#include "utils.h"
#include "mt19937.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define ICMP4_HDR_LEN 4
#define ICMP4_LEN_MIN 8
#define ICMP4_CODE_NONE 0 /* for types without codes */
#define ICMP4_ECHOREPLY 0 /* echo reply */
#define ICMP4_UNREACH   3 /* dest unreachable, codes: */
#define ICMP4_UNREACH_NET 0 /* bad net */
#define ICMP4_UNREACH_HOST 1 /* bad host */
#define ICMP4_UNREACH_PROTO 2 /* bad protocol */
#define ICMP4_UNREACH_PORT 3 /* bad port */
#define ICMP4_UNREACH_NEEDFRAG 4 /* IP_DF caused drop */
#define ICMP4_UNREACH_SRCFAIL 5 /* src route failed */
#define ICMP4_UNREACH_NET_UNKNOWN 6 /* unknown net */
#define ICMP4_UNREACH_HOST_UNKNOWN 7 /* unknown host */
#define ICMP4_UNREACH_ISOLATED 8 /* src host isolated */
#define ICMP4_UNREACH_NET_PROHIB 9 /* for crypto devs */
#define ICMP4_UNREACH_HOST_PROHIB 10 /* ditto */
#define ICMP4_UNREACH_TOSNET 11 /* bad tos for net */
#define ICMP4_UNREACH_TOSHOST 12 /* bad tos for host */
#define ICMP4_UNREACH_FILTER_PROHIB 13 /* prohibited access */
#define ICMP4_UNREACH_HOST_PRECEDENCE 14 /* precedence error */
#define ICMP4_UNREACH_PRECEDENCE_CUTOFF 15 /* precedence cutoff */
#define ICMP4_SRCQUENCH 4 /* packet lost, slow down */
#define ICMP4_REDIRECT 5 /* shorter route, codes: */
#define ICMP4_REDIRECT_NET 0 /* for network */
#define ICMP4_REDIRECT_HOST 1 /* for host */
#define ICMP4_REDIRECT_TOSNET 2 /* for tos and net */
#define ICMP4_REDIRECT_TOSHOST 3 /* for tos and host */
#define ICMP4_ALTHOSTADDR 6 /* alternate host address */
#define ICMP4_ECHO 8 /* echo service */
#define ICMP4_RTRADVERT 9 /* router advertise, codes: */
#define ICMP4_RTRADVERT_NORMAL 0 /* normal */
#define ICMP4_RTRADVERT_NOROUTE_COMMON 16 /* selective routing */
#define ICMP4_RTRSOLICIT 10 /* router solicitation */
#define ICMP4_TIMEXCEED 11 /* time exceeded, code: */
#define ICMP4_TIMEXCEED_INTRANS 0 /* ttl==0 in transit */
#define ICMP4_TIMEXCEED_REASS 1 /* ttl==0 in reass */
#define ICMP4_PARAMPROB 12 /* ip header bad */
#define ICMP4_PARAMPROB_ERRATPTR 0 /* req. opt. absent */
#define ICMP4_PARAMPROB_OPTABSENT 1 /* req. opt. absent */
#define ICMP4_PARAMPROB_LENGTH 2 /* bad length */
#define ICMP4_TSTAMP 13 /* timestamp request */
#define ICMP4_TSTAMPREPLY 14 /* timestamp reply */
#define ICMP4_INFO 15 /* information request */
#define ICMP4_INFOREPLY 16 /* information reply */
#define ICMP4_MASK 17 /* address mask request */
#define ICMP4_MASKREPLY 18 /* address mask reply */
#define ICMP4_TRACEROUTE 30 /* traceroute */
#define ICMP4_DATACONVERR 31 /* data conversion error */
#define ICMP4_MOBILE_REDIRECT 32 /* mobile host redirect */
#define ICMP4_IPV6_WHEREAREYOU 33 /* IPv6 where-are-you */
#define ICMP4_IPV6_IAMHERE 34 /* IPv6 i-am-here */
#define ICMP4_MOBILE_REG 35 /* mobile registration req */
#define ICMP4_MOBILE_REGREPLY 36 /* mobile registration reply */
#define ICMP4_DNS 37 /* domain name request */
#define ICMP4_DNSREPLY 38 /* domain name reply */
#define ICMP4_SKIP 39 /* SKIP */
#define ICMP4_PHOTURIS 40 /* Photuris */
#define ICMP4_PHOTURIS_UNKNOWN_INDEX 0 /* unknown sec index */
#define ICMP4_PHOTURIS_AUTH_FAILED 1 /* auth failed */
#define ICMP4_PHOTURIS_DECOMPRESS_FAILED 2 /* decompress failed */
#define ICMP4_PHOTURIS_DECRYPT_FAILED 3 /* decrypt failed */
#define ICMP4_PHOTURIS_NEED_AUTHN 4 /* no authentication */
#define ICMP4_PHOTURIS_NEED_AUTHZ 5 /* no authorization */
#define ICMP4_TYPE_MAX 40
#define ICMP4_PAYLOAD_MAXLEN 1500
#define ICMP4_MAX_ROUTER_ADVERT_ENTRIES (((ICMP4_PAYLOAD_MAXLEN-4)/8)-1)
#define ICMP6_COMMON_HEADER_LEN 4

#define ICMP6_HDR_LEN 4
#define ICMP6_REDIRECT_LEN (ICMP6_COMMON_HEADER_LEN + 36)
#define ICMP6_MAX_MESSAGE (ICMP6_REDIRECT_LEN - ICMP6_COMMON_HEADER_LEN)
#define ICMP6_CODE_NONE 0    /* for types without codes */
#define ICMP6_UNREACH  1 /* dest unreachable */
#define ICMP6_UNREACH_NOROUTE 0 /* no route to dest */
#define ICMP6_UNREACH_PROHIB 1  /* admin prohibited */
#define ICMP6_UNREACH_SCOPE 2   /* beyond scope of source address */
#define ICMP6_UNREACH_ADDR 3    /* address unreach */
#define ICMP6_UNREACH_PORT 4 /* port unreach */
#define ICMP6_UNREACH_FILTER_PROHIB 5 /* src failed ingress/egress policy */
#define ICMP6_UNREACH_REJECT_ROUTE 6  /* reject route */
#define ICMP6_TIMEXCEED 3 /* time exceeded, code: */
#define ICMP6_TIMEXCEED_INTRANS 0 /* hop limit exceeded in transit */
#define ICMP6_TIMEXCEED_REASS 1 /* fragmetn reassembly time exceeded */
#define ICMP6_PARAMPROBLEM 4 /* parameter problem, code: */
#define ICMP6_PARAMPROBLEM_FIELD 0 /* erroneous header field encountered */
#define ICMP6_PARAMPROBLEM_NEXTHEADER 1 /* unre. Next Header type encountered */
#define ICMP6_PARAMPROBLEM_OPTION 2 /* unrecognized IPv6 option encountered */
#define ICMP6_ECHO 128 /* echo request */
#define ICMP6_ECHOREPLY 129 /* echo reply */
#define	ICMP6_NEIGHBOR_SOLICITATION 135
#define	ICMP6_NEIGHBOR_ADVERTISEMENT 136
#define	ICMP6_INFOTYPE(type) (((type) & 0x80) != 0)

struct icmp4_hdr
{
  u8  type;
  u8  code;
  u16 check;
};

struct icmp6_hdr
{
  u8  type;
  u8  code;
  u16 check;
};

typedef struct icmp4_message_echo {
  u16 id, seq; /* and data */
} icmp4_msg_echo;

typedef struct icmp4_message_mask {
  u16 id, seq; u32 mask;
} icmp4_msg_mask;

typedef struct icmp4_message_needfrag {
  u16 zero, mtu; /* and ip */
} icmp4_msg_needfrag;

typedef struct icmp4_message_tstamp {
  u16 id, seq; u32 orig, rx, tx;
} icmp4_msg_tstamp;

typedef struct icmp4_message_redir {
  u32 gateway; /* and ip */
} icmp4_msg_redir;

typedef struct icmp4_message_info {
  u16 id, seq;
} icmp4_msg_info;

typedef struct icmp4_message_quench {
  u32 unsed; /* and ip */
} icmp4_msg_quench;

typedef struct icmp4_message_timexeed {
  u32 unsed; /* and ip */
} icmp4_msg_timexeed;

typedef struct icmp4_message_dstunreach {
  u32 unsed; /* and ip */
} icmp4_msg_dstunreach;

typedef struct icmp4_message_paramprob {
  u32 ptr_unsed;
} icmp4_msg_paramprob;

typedef struct icmp6_message_echo {
  u16 id, seq; /* and data */
} icmp6_msg_echo;

typedef struct icmp6_msg_nd {
  u32 flags; ip6_t target; u8 opttype, optlen; mac_t mac;
} icmp6_msg_nd;

__BEGIN_DECLS

u8 *icmp4_build(u8 type, u8 code, u8 *msg, u16 msglen, u32 *pktlen, bool badsum);
u8 *icmp6_build(u8 type, u8 code, u8 *msg, u16 msglen, u32 *pktlen);

u8 *icmp4_msg_echo_build(u16 id, u16 seq, const char *data, size_t *msglen);
u8 *icmp4_msg_mask_build(u16 id, u16 seq, u32 mask, size_t *msglen);
u8 *icmp4_msg_needfrag_build(u16 mtu, u8 *frame, size_t frmlen, size_t *msglen);
u8 *icmp4_msg_tstamp_build(u16 id, u16 seq, u32 orig, u32 rx, u32 tx, size_t *msglen);
u8 *icmp4_msg_redir_build(u32 gateway, u8 *frame, size_t frmlen, size_t *msglen);

#define icmp4_msg_info_build(id, seq, msglen)		\
  icmp4_msg_echo_build((id), (seq), NULL, (msglen))
#define icmp4_msg_quench_build(unsed, frame, frmlen, msglen)	\
  icmp4_msg_redir_build((unsed), (frame), (frmlen), (msglen))
#define icmp4_msg_timexeed_build(unsed, frame, frmlen, msglen)	\
  icmp4_msg_redir_build((unsed), (frame), (frmlen), (msglen))
#define icmp4_msg_dstunreach_build(unsed, frame, frmlen, msglen)	\
  icmp4_msg_redir_build((unsed), (frame), (frmlen), (msglen))
#define icmp4_msg_paramprob_build(ptr_unsed, frame, frmlen, msglen)	\
  icmp4_msg_redir_build((ptr_unsed), (frame), (frmlen), (msglen))
#define icmp6_msg_echo_build(id, seq, data, msglen)	\
  icmp4_msg_echo_build((id), (seq), (data), (msglen))

u8 *icmp4_build_pkt(const u32 src, const u32 dst, int ttl, u16 ipid, u8 tos,
                    bool df, u8 *ipopt, int ipoptlen, u8 type, u8 code, u8 *msg,
		    u16 msglen, u32 *pktlen, bool badsum);

u8 *icmp6_build_pkt(const struct in6_addr *src, const struct in6_addr *dst,
                    u8 tc, u32 flowlabel, u8 hoplimit, u8 type, u8 code,
		    u8 *msg, u16 msglen, u32 *pktlen, bool badsum);

int icmp4_send_pkt(struct ethtmp *eth, int fd, const u32 src, const u32 dst,
                   int ttl, u16 ipid, u8 tos, bool df, u8 *ipopt, int ipoptlen,
		   u8 type, u8 code, u8 *msg, u16 msglen, int mtu, bool badsum);

int icmp6_send_pkt(struct ethtmp *eth, int fd, const struct in6_addr *src,
		   const struct in6_addr *dst, u8 tc, u32 flowlabel,
		   u8 hoplimit, u8 type, u8 code, u8 *msg, u16 msglen,
		   bool badsum);

__END_DECLS


/* tmp */
struct icmp4_hdr_ {
  u8 type, code;
  u16 check, seq, id;
  u8 data[ICMP4_PAYLOAD_MAXLEN];
};
struct icmp4_msg_rtr_data {
  u32 zero, pref;
};
struct icmp4_msg_rtradvert {
  u8  numaddrs;
  u8  wpa;
  u16 lifetime;
  struct icmp4_msg_rtr_data adv[ICMP4_MAX_ROUTER_ADVERT_ENTRIES];
};
struct icmp4_msg_traceroute {
  u16 id, zero, ohc, rhc;
  u32 speed, mtu;
};
struct icmp4_msg_sec_fails {
  u16 reserved;
  u16 pointer;
  /* orighdrs */
};
struct icmp4_msg_dnsreply {
  u16 id, seq;
  u32 tl;
  u8 names[ICMP4_PAYLOAD_MAXLEN-8];
};

#endif
