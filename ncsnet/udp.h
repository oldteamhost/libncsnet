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

#ifndef NCSUDPHDR
#define NCSUDPHDR

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "eth.h"

#include "../ncsnet-config.h"
#include "sys/types.h"
#include "sys/nethdrs.h"

#define UDP_HDR_LEN 8

struct udp_hdr
{
  u16 srcport; /* source port */
  u16 dstport; /* destination port */
  u16 len;     /* udp length (including header) */
  u16 check;   /* udp checksum */
};

__BEGIN_DECLS

u8 *udp_build(u16 srcport, u16 dstport, const char *data, u16 datalen,
              u32 *pktlen);
u8 *udp4_build_pkt(const u32 src, const u32 dst, int ttl, u16 ipid, u8 tos,
                   bool df, u8 *ipopt, int ipoptlen, u16 srcport, u16 dstport,
                   const char *data, u16 datalen, u32 *pktlen, bool badsum);
u8 *udp6_build_pkt(const struct in6_addr *src, const struct in6_addr *dst,
                   u8 tc, u32 flowlabel, u8 hoplimit, u16 srcport, u16 dstport,
                   const char *data, u16 datalen, u32 *pktlen, bool badsum);
int udp4_send_pkt(struct ethtmp *eth, int fd, const u32 src, const u32 dst,
                  int ttl, u16 ipid, u8 *ipopt, int ipoptlen, u16 srcport,
                  u16 dstport, bool df, const char *data, u16 datalen, int mtu,
                  bool badsum);

__END_DECLS

#endif
