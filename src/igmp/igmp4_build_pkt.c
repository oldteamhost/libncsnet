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

#include <ncsnet/igmp.h>

#ifndef MIN
  #define MIN(a,b) ((a) <= (b) ? (a) : (b))
#endif

u8 *igmp4_build_pkt(const u32 src, const u32 dst, u16 ttl, u16 ipid, u8 tos,
                   bool df, u8 *ipopt, int ipoptlen, u8 type, u8 code,
                   const char *data, u16 datalen, u32 *pktlen, bool badsum)
{
  int dlen = 0, igmplen = 0;
  struct igmp_hdr igmp;
  u32 *datastart;
  char *pkt;

  datastart = (u32*)igmp.data;
  dlen = sizeof(igmp.data);
  pkt = (char*)&igmp;

  igmp.type = type;
  igmp.code = code;

  switch (type) {
    case IGMP_HOST_MEMBERSHIP_QUERY:
    case IGMP_v1_HOST_MEMBERSHIP_REPORT:
    case IGMP_v2_HOST_MEMBERSHIP_REPORT:
    case IGMP_HOST_LEAVE_MESSAGE:
    case IGMP_v3_HOST_MEMBERSHIP_REPORT:
      igmplen = 8;
      break;
  }

  if (datalen > 0) {
    igmplen += MIN(dlen, datalen);
    if (!data)
      memset(datastart, 0, MIN(dlen, datalen));
    else
      memcpy(datastart, data, MIN(dlen, datalen));
  }

  igmp.check = 0;
  igmp.check = in_check((u16*)pkt, igmplen);

  if (badsum)
    --igmp.check;

  return ip4_build(src, dst, IPPROTO_IGMP, ttl,
      ipid, tos, df, ipopt, ipoptlen, pkt, igmplen, pktlen);
}
