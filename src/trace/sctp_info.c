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

const char* sctp_info(const u8 *sctp, size_t sctplen, int detail)
{
  static char sctpinfo[TRACE_PROTO_MAX_LEN]="";
  const char *chunkinfo="";
  sctph_t *sctph=NULL;

  if (sctplen<SCTP_HDR_LEN||!sctp)
    return "sctp (incorrect)";
  sctph=(sctph_t*)sctp;
  
  chunkinfo=sctp_chunk_info((sctp+sizeof(sctph_t)));
  if (detail==LOW_DETAIL)
    snprintf(sctpinfo, sizeof(sctpinfo), "sctp src=%hu dst=%hu (%s)",
      (u16)ntohs(sctph->srcport), (u16)ntohs(sctph->dstport), chunkinfo);
  else if (detail==MEDIUM_DETAIL)
    snprintf(sctpinfo, sizeof(sctpinfo), "sctp src=%hu dst=%hu vtag=%u (%s)",
      (u16)ntohs(sctph->srcport), (u16)ntohs(sctph->dstport), ntohs(sctph->vtag), chunkinfo);
  else if (detail==HIGH_DETAIL)
    snprintf(sctpinfo, sizeof(sctpinfo), "sctp src=%hu dst=%hu vtag=%lu csum=0x%08X (%s)",
      (u16)ntohs(sctph->srcport), (u16)ntohs(sctph->dstport), (unsigned long)ntohl(sctph->vtag),
      ntohl(sctph->check), chunkinfo);
  
  return sctpinfo;
}
