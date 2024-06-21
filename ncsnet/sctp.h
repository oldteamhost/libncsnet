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

#ifndef NCSSCTPHDR
#define NCSSCTPHDR

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
#include "crc.h"
#include "adler32.h"
#include "mt19937.h"

#include "../ncsnet-config.h"
#include "sys/types.h"
#include "sys/nethdrs.h"

#define SCTP_HDR_LEN            12
#define SCTP_DATA               0x00
#define SCTP_INIT               0x01
#define SCTP_INIT_ACK           0x02
#define SCTP_SACK               0x03
#define SCTP_HEARTBEAT          0x04
#define SCTP_HEARTBEAT_ACK      0x05
#define SCTP_ABORT              0x06
#define SCTP_SHUTDOWN           0x07
#define SCTP_SHUTDOWN_ACK       0x08
#define SCTP_ERROR              0x09
#define SCTP_COOKIE_ECHO        0x0a
#define SCTP_COOKIE_ACK         0x0b
#define SCTP_ECNE               0x0c
#define SCTP_CWR                0x0d
#define SCTP_SHUTDOWN_COMPLETE  0x0e
#define SCTP_AUTH               0x0f /* RFC 4895 */
#define SCTP_ASCONF_ACK         0x80 /* RFC 5061 */
#define SCTP_PKTDROP            0x81 /* draft-stewart-sctp-pktdrprep-08 */
#define SCTP_PAD                0x84 /* RFC 4820 */
#define SCTP_FORWARD_TSN        0xc0 /* RFC 3758 */
#define SCTP_ASCONF             0xc1 /* RFC 5061 */

#define SCTP_TYPEFLAG_REPORT 1
#define SCTP_TYPEFLAG_SKIP   2

#define SCTP_CAUSE_INVALID_STREAM_IDENTIFIER                0x1
#define SCTP_CAUSE_MISSING_MANDATORY_PARAMETER              0x2
#define SCTP_CAUSE_STALE_COOKIE_ERROR                       0x3
#define SCTP_CAUSE_OUT_OF_RESOURCE                          0x4
#define SCTP_CAUSE_UNRESOLVABLE_ADDRESS                     0x5
#define SCTP_CAUSE_UNRECOGNIZED_CHUNK_TYPE                  0x6
#define SCTP_CAUSE_INVALID_MANDATORY_PARAMETER              0x7
#define SCTP_CAUSE_UNRECOGNIZED_PARAMETERS                  0x8
#define SCTP_CAUSE_NO_USER_DATA                             0x9
#define SCTP_CAUSE_COOKIE_RECEIVED_WHILE_SHUTTING_DOWN      0xA
#define SCTP_CAUSE_RESTART_OF_AN_ASSOCIATION_WITH_NEW_ADDRS 0xB
#define SCTP_CAUSE_USER_INITIATED_ABORT                     0xC
#define SCTP_CAUSE_PROTOCOL_VIOLATION                       0xD

struct sctp_hdr
{
  u16 srcport; /* source port */
  u16 dstport; /* dest port*/
  u32 vtag;    /* verification tag */
  u32 check;   /* checksum */
};

typedef struct sctp_hdr sctph_t;

typedef struct sctp_chunk_hdr {
  u8  type, flags;
  u16 len;
} sctp_chunk;

typedef struct sctp_error_cause_op_hdr {
  u16 code, len;
} sctp_error_cause_op;

typedef struct sctp_chunk_hdr_abort {
  sctp_chunk chunkhdr;
  sctp_error_cause_op ec;
} sctp_chunk_abort;

typedef struct sctp_chunk_hdr_shutdown {
  sctp_chunk chunkhdr;
  u32 tsnack;
} sctp_chunk_shutdown;

typedef struct sctp_chunk_hdr_heartbeat_info {
  u16 type, infolen;
} sctp_chunk_heartbeat_info;

typedef struct sctp_chunk_hdr_heartbeat {
  sctp_chunk chunkhdr;
  sctp_chunk_heartbeat_info hi;
} sctp_chunk_heartbeat;

typedef struct sctp_chunk_hdr_error {
  sctp_chunk chunkhdr;
  sctp_error_cause_op ec;
} sctp_chunk_error;

typedef struct sctp_chunk_hdr_init {
  sctp_chunk chunkhdr;
  u32 itag;
  u32 arwnd;
  u16 nos;
  u16 nis;
  u32 itsn;
} sctp_chunk_init;

typedef struct sctp_chunk_hdr_data {
  sctp_chunk chunkhdr;
  u32 tsn;
  u16 s, n;
  u32 protoload; /* and data */
} sctp_chunk_data;

__BEGIN_DECLS

u8 *sctp_build(u16 srcport, u16 dstport, u32 vtag, u8 *chunks,
               size_t chunkslen, size_t *pktlen);

void sctp_check(u8 *frame, size_t frmlen, bool adler32sum, bool badsum);

u8 *sctp_chunk_build(u8 type, u8 flags, u8 *value, size_t valuelen, size_t *chunklen);
u8 *sctp_init_build(u8 type, u8 flags, u32 itag, u32 arwnd, u16 nos, u16 nis, u32 itsn, size_t *chunklen);
u8 *sctp_data_build(u8 reserved, u32 tsn, u16 s, u16 n, u32 protoload, u8 *data, size_t datalen, size_t *chunklen);
u8 *sctp_cookie_build(u8 type, u8 flags, u8 *cookie, size_t cookielen, size_t *chunklen);
u8 *sctp_abort_build(u16 code, u8 flags, u8 *info, size_t infolen, size_t *chunklen);
u8 *sctp_heartbeat_build(u8 type, u8 flags, u8 *info, size_t infolen, size_t *chunklen);
u8 *sctp_error_build(u8 flags, u8 code, u8 *info, size_t infolen, size_t *chunklen);
u8 *sctp_shutdown_build(u8 flags, u32 tsnack, size_t *chunklen);

#define sctp_shutdown_ack_build(flags, chunklen)		\
  sctp_chunk_build(SCTP_SHUTDOWN_ACK, flags, NULL, 0, chunklen)
#define sctp_shutdown_complete_build(flags, chunklen)			\
  sctp_chunk_build(SCTP_SHUTDOWN_COMPLETE, flags, NULL, 0, chunklen)

u8 *sctp4_build_pkt(u32 src, u32 dst, int ttl, u16 ipid, u8 tos, bool df,
                    u8 *ipopt, int ipoptlen, u16 srcport, u16 dstport, u32 vtag,
                    u8 *chunks, size_t chunkslen, size_t *pktlen, bool adler32sum,
		    bool badsum);

u8 *sctp6_build_pkt(const struct in6_addr *src, const struct in6_addr *dst,
                    u8 tc, u32 flowlabel, u8 hoplimit, u16 srcport, u16 dstport,
                    u32 vtag, u8 *chunks, size_t chunkslen, size_t *pktlen,
		    bool adler32sum, bool badsum);

int sctp4_send_pkt(struct ethtmp *eth, int fd, const u32 src, const u32 dst,
                   int ttl, u16 ipid, u8 tos, bool df, u8 *ipops, int ipoptlen,
		   u16 srcport, u16 dstport, u8 *chunks, size_t chunkslen, u32 vtag,
                   int mtu, bool adler32sum, bool badsum);

int sctp6_send_pkt(struct ethtmp *eth, int fd, const struct in6_addr *src,
		   const struct in6_addr *dst, u8 tc, u32 flowlabel, u8 hoplimit,
		   u16 srcport, u16 dstport, u32 vtag, u8 *chunks, size_t chunkslen,
		   bool adler32sum, bool badsum);

__END_DECLS

#endif

