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

#include <ncsnet/icmp.h>
#include "ncsnet/ip.h"

#ifndef MIN
  #define MIN(a,b) ((a) <= (b) ? (a) : (b))
#endif

u8 *icmp4_build_pkt(const u32 src, const u32 dst, int ttl, u16 ipid, u8 tos,
                    bool df, u8 *ipopt, int ipoptlen, u16 seq, u16 id, u8 type,
                    u8 code, const char *data, u16 datalen, u32 *pktlen,
                    bool badsum)
{
  struct icmp4_hdr_ icmphdr;
  int dlen = 0, icmplen = 0;
  u8 *datastart;
  char *ping;

  datastart = icmphdr.data;
  dlen = sizeof(icmphdr.data);
  ping = (char*)&icmphdr;

  icmphdr.type = type;
  icmphdr.code = code;

  if (type == 8)
    icmplen = 8;
  else if (type == 13 && code == 0) {
    icmplen = 20;
    memset(datastart, 0, 12);
    datastart += 12;
    dlen -= 12;
  }
  else if (type == 17 && code == 0) {
    icmplen = 12;
    memset(datastart, 0, 4);
    datastart += 4;
    dlen -= 4;
  }

  if (datalen > 0) {
    icmplen += MIN(dlen, datalen);
    if (!data)
      memset(datastart, 0, MIN(dlen, datalen));
    else
      memcpy(datastart, data, MIN(dlen, datalen));
  }

  icmphdr.id = htons(id);
  icmphdr.seq = htons(seq);
  icmphdr.check = 0;
  icmphdr.check = in_check((u16*)ping, icmplen);

  if (badsum)
    --icmphdr.check;

  return ip4_build(src, dst, IPPROTO_ICMP, ttl,
      ipid, tos, df, ipopt, ipoptlen, ping, icmplen, pktlen);
}
