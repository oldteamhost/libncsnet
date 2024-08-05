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

#include <ncsnet/sctp.h>

/* in header error */
#include <ncsnet/readpkt.h>

const char* sctp_info(const u8 *frame, size_t frmlen, int detail)
{
  static char protoinfo[1024] = "";
  struct abstract_iphdr hdr;
  int more_fragments = 0;
  const char *chunkinfo;
  sctph_t *sctp = NULL;
  int frag_off = 0;
  const u8 *data;
  u32 datalen;

  datalen = frmlen;
  data = (u8*)read_util_ip4getdata_any(frame, &datalen, &hdr);
  if (!data) {
    data=frame;
    goto sctp;
  }
  if (detail != LOW_DETAIL && detail != MEDIUM_DETAIL && detail != HIGH_DETAIL)
    detail = LOW_DETAIL;
  if (hdr.proto != IPPROTO_SCTP)
    return "The IP packet does not contain the SCTP protocol";
  if (hdr.version == 4) {
    const ip4h_t *ip;
    ip=(ip4h_t*)frame;
    frag_off=8*(ntohs(ip->off)&8191);
    more_fragments=ntohs(ip->off)&IP4_MF;
  }
  if (frag_off || more_fragments) {
    snprintf(protoinfo, sizeof(protoinfo), "SCTP: fragment offset=%d%s (incomplete)",
      frag_off, more_fragments ? "+" : "");
    return protoinfo;
  }
  
 sctp:  
  sctp=(sctph_t*)data;
  chunkinfo=sctp_chunk_info((data+sizeof(sctph_t)));
  if (detail == LOW_DETAIL)
    snprintf(protoinfo, sizeof(protoinfo), "SCTP: src=%hu dst=%hu (%s)",
      (u16)ntohs(sctp->srcport), (u16)ntohs(sctp->dstport), chunkinfo);
  else if (detail == MEDIUM_DETAIL)
    snprintf(protoinfo, sizeof(protoinfo), "SCTP: src=%hu dst=%hu vtag=%u (%s)",
      (u16)ntohs(sctp->srcport), (u16)ntohs(sctp->dstport), ntohs(sctp->vtag), chunkinfo);
  else if (detail == HIGH_DETAIL)
    snprintf(protoinfo, sizeof(protoinfo), "SCTP: src=%hu dst=%hu vtag=%lu csum=0x%08X (%s)",
      (u16)ntohs(sctp->srcport), (u16)ntohs(sctp->dstport), (unsigned long)ntohl(sctp->vtag),
      ntohl(sctp->check), chunkinfo);
  
  return protoinfo;
}
