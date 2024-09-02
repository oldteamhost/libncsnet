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

#include <ncsnet/trace.h>

const char *arp_operation_info(const u8 *op, size_t oplen, u16 optype, u16 ptype, u8 plen, u8 hlen)
{
  static char arpopinfo[TRACE_PROTO_MAX_LEN]="";

  switch (optype) {
  case ARP_OP_REPLY:
  case ARP_OP_REQUEST: {
    char dst[TRACE_MAX_DATA_LEN];
    char src[TRACE_MAX_DATA_LEN];
    char dstp[TRACE_MAX_DATA_LEN];
    char srcp[TRACE_MAX_DATA_LEN];
    size_t skip=0;

    skip=plen+hlen;
    if (hlen==6) {
      mac_t sha, tha;
      mact_fill(&sha, op[0], op[1], op[2], op[3], op[4], op[5]);
      mact_fill(&tha, op[0+skip], op[1+skip], op[2+skip], op[3+skip], op[4+skip], op[5+skip]);
      mact_ntop(&tha, dst, TRACE_MAX_DATA_LEN);
      mact_ntop(&sha, src, TRACE_MAX_DATA_LEN);
    }
    /* it's real ??? */
    else {
      char hexdata[hexchar_len(hlen)];
      asciihex(op, hlen, NULL, hexdata);
      sprintf(src, "%s", hexdata);
      asciihex(op+skip, hlen, NULL, hexdata);
      sprintf(dst, "%s", hexdata);
    }
    if (plen==4) {
      sprintf(srcp, "%hhu.%hhu.%hhu.%hhu", op[0+hlen], op[1+hlen], op[2+hlen], op[3+hlen]);
      sprintf(dstp, "%hhu.%hhu.%hhu.%hhu", op[0+hlen+plen+hlen], op[1+hlen+plen+hlen], op[2+hlen+plen+hlen], op[3+hlen+plen+hlen]);      
    }
    else {
      char hexdata[hexchar_len(plen)];
      asciihex(op+hlen, plen, NULL, hexdata);
      sprintf(srcp, "%s", hexdata);
      asciihex(op+hlen+plen+hlen, plen, NULL, hexdata);
      sprintf(dstp, "%s", hexdata);
    }
    snprintf(arpopinfo, sizeof(arpopinfo), "%s|%s -> %s|%s", src, srcp, dst, dstp);
    break;
  }
  }

  return arpopinfo;
}
