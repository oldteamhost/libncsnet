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

#ifndef NCSUDPLITE
#define NCSUDPLITE

#include <stdbool.h>

#include "raw.h"

#include "../ncsnet-config.h"
#include "sys/types.h"
#include "sys/nethdrs.h"

struct udplite_hdr
{
  u16 srcport;  /* source port */
  u16 dstport;  /* destination port */
  u16 checkcrg; /* checksum coverage */
  u16 check;    /* checksum */
};

typedef struct udplite_hdr udpliteh_t;

__BEGIN_DECLS

u8 *udplite_build(u16 srcport, u16 dstport, u8 *frame, size_t frmlen, size_t *pktlen);

/* i'm not sure about the checksum calculation with coverage ??? */
void udplite4_check(u8 *frame, size_t frmlen, const ip4_t src, const ip4_t dst,
    u16 checkcrg, bool badsum);
void udplite6_check(u8 *frame, size_t frmlen, const ip6_t src, const ip6_t dst,
    u16 checkcrg, bool badsum);

u8 *udplite4_build_pkt(const ip4_t src, const ip4_t dst, int ttl, u16 ipid, u8 tos,
                       u16 off, u8 *ipopt, int ipoptlen, u16 srcport, u16 dstport,
                       u16 checkcrg, u8 *frame, size_t frmlen, size_t *pktlen,
                       bool badsum);

u8 *udplite6_build_pkt(const ip6_t src, const ip6_t dst, u8 tc, u32 flowlabel,
                       u8 hoplimit, u16 srcport, u16 dstport, u16 checkcrg,
                       u8 *frame, size_t frmlen, size_t *pktlen, bool badsum);

__END_DECLS

#endif
