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

#ifndef NCSIGMPHDR
#define NCSIGMPHDR

#include "ip.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define IGMP_V0_CREATE_GROUP_REQUEST 0x01
#define IGMP_V0_CREATE_GROUP_REPLY 0x02
#define IGMP_V0_JOIN_GROUP_REQUEST 0x03
#define IGMP_V0_JOIN_GROUP_REPLY 0x04
#define IGMP_V0_LEAVE_GROUP_REQUEST 0x05
#define IGMP_V0_LEAVE_GROUP_REPLY 0x06
#define IGMP_V0_CONFIRM_GROUP_REQUEST 0x07
#define IGMP_V0_CONFIRM_GROUP_REPLY 0x08
#define IGMP_V1_HOST_MEMBERSHIP_QUERY 0x11
#define IGMP_V1_HOST_MEMBERSHIP_REPORT 0x12
#define IGMP_DVMRP 0x13
#define IGMP_V1_PIM_ROUTING_MESSAGE 0x14
#define IGMP_V2_MEMBERSHIP_REPORT 0x16
#define IGMP_V2_LEAVE_GROUP 0x17
#define IGMP_TRACEROUTE_RESPONSE 0x1e
#define IGMP_TRACEROUTE_QUERY_REQ 0x1f
#define IGMP_V3_MEMBERSHIP_REPORT 0x22

#define IGMP_TYPE_0x23 0x23
#define IGMP_TYPE_0x24 0x24
#define IGMP_TYPE_0x25 0x25
#define IGMP_TYPE_0x26 0x26

#define IGMP_IGAP_JOIN                  0x40
#define IGMP_IGAP_QUERY                 0x41
#define IGMP_IGAP_LEAVE                 0x42
#define IGMP_RGMP_LEAVE                 0xFC
#define IGMP_RGMP_JOIN                  0xFD
#define IGMP_RGMP_BYE                   0xFE
#define IGMP_RGMP_HELLO                 0xFF

#define IGMP_DO_NOTHING                 0 /* don't send a record */
#define IGMP_MODE_IS_INCLUDE            1 /* MODE_IN */
#define IGMP_MODE_IS_EXCLUDE            2 /* MODE_EX */
#define IGMP_CHANGE_TO_INCLUDE_MODE     3 /* TO_IN */
#define IGMP_CHANGE_TO_EXCLUDE_MODE     4 /* TO_EX */
#define IGMP_ALLOW_NEW_SOURCES          5 /* ALLOW_NEW */
#define IGMP_BLOCK_OLD_SOURCES          6 /* BLOCK_OLD */
#define IGMP_V3_QUERY_MINLEN            12

#define IGMP_V3_GENERAL_QUERY           1
#define IGMP_V3_GROUP_QUERY             2
#define IGMP_V3_GROUP_SOURCE_QUERY      3

#define	IGMP_DELAYING_MEMBER            1
#define	IGMP_IDLE_MEMBER                2
#define	IGMP_LAZY_MEMBER                3
#define	IGMP_SLEEPING_MEMBER            4
#define	IGMP_AWAKENING_MEMBER           5

#define IGMP_EXP(x)             (((x) >> 4) & 0x07)
#define IGMP_MANT(x)            ((x) & 0x0f)
#define IGMP_QRESV(x)           (((x) >> 4) & 0x0f)
#define IGMP_SFLAG(x)           (((x) >> 3) & 0x01)
#define IGMP_QRV(x)             ((x) & 0x07)

struct igmp_hdr
{
  u8  type;
  u8  code;
  u16 check;
  u32 var;
  u8  data[1500];
};

typedef struct igmp_hdr igmph_t;

__BEGIN_DECLS

u8 *igmp4_build_pkt(const u32 src, const u32 dst, u16 ttl, u16 ipid, u8 tos,
                   u16 off, u8 *ipopt, int ipoptlen, u8 type, u8 code,
                   const char *data, size_t datalen, size_t *pktlen, bool badsum);

int igmp4_send_pkt(struct ethtmp *eth, int fd, const u32 src, const u32 dst,
                   int ttl, u16 off, u8 *ipops, int ipoptlen, u16 ipid, u8 tos,
                   u8 type, u8 code, const char *data, size_t datalen, int mtu,
                   bool badsum);
__END_DECLS

/* Old */
#define IGMP_HOST_MEMBERSHIP_QUERY      0x11 /* membership query         */
#define IGMP_v1_HOST_MEMBERSHIP_REPORT  0x12 /* Ver. 1 membership report */
#define IGMP_DVMRP                      0x13 /* DVMRP routing message    */
#define IGMP_PIM                        0x14 /* PIMv1 message (historic) */
#define IGMP_v2_HOST_MEMBERSHIP_REPORT  0x16 /* Ver. 2 membership report */
#define IGMP_HOST_LEAVE_MESSAGE         0x17 /* Leave-group message     */
#define IGMP_MTRACE_REPLY               0x1e /* mtrace(8) reply */
#define IGMP_MTRACE_QUERY               0x1f /* mtrace(8) probe */
#define IGMP_v3_HOST_MEMBERSHIP_REPORT  0x22 /* Ver. 3 membership report */

#endif
