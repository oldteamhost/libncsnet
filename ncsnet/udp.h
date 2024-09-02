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
#include "ip.h"
#include "raw.h"

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

typedef struct udp_hdr udph_t;

__BEGIN_DECLS

u8 *udp_build(u16 srcport, u16 dstport, u8 *frame, size_t frmlen, size_t *pktlen);

void udp4_check(u8 *frame, size_t frmlen, const ip4_t src,
    const ip4_t dst, bool badsum);
void udp6_check(u8 *frame, size_t frmlen, const ip6_t src,
  const ip6_t dst, bool badsum);

u8 *udp4_build_pkt(const ip4_t src, const ip4_t dst, int ttl, u16 ipid, u8 tos,
                   u16 off, u8 *ipopt, int ipoptlen, u16 srcport, u16 dstport,
                   u8 *frame, size_t frmlen, size_t *pktlen, bool badsum);

u8 *udp6_build_pkt(const ip6_t src, const ip6_t dst, u8 tc, u32 flowlabel,
                   u8 hoplimit, u16 srcport, u16 dstport, u8 *frame,
                   size_t frmlen, size_t *pktlen, bool badsum);

ssize_t udp4_send_pkt(struct ethtmp *eth, int fd, const ip4_t src, const ip4_t dst,
                      int ttl, u16 ipid, u8 *ipopt, int ipoptlen, u16 srcport,
                      u16 dstport, u16 off, u8 *frame, size_t frmlen, int mtu, bool badsum);

ssize_t udp6_send_pkt(struct ethtmp *eth, int fd, const ip6_t src, const ip6_t dst,
                      u8 tc, u32 flowlabel, u8 hoplimit, u16 srcport, u16 dstport,
                      u8 *frame, size_t frmlen, bool badsum);

__END_DECLS

#endif
