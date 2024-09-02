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

u8 *sctp6_build_pkt(const ip6_t src, const ip6_t dst, u8 tc, u32 flowlabel, u8 hoplimit,
                    u16 srcport, u16 dstport, u32 vtag, u8 *chunks, size_t chunkslen,
                    size_t *pktlen, bool adler32sum, bool badsum)
{
  size_t sctplen;
  sctph_t *sctp;
  u8 *pkt;

  sctp=(sctph_t*)sctp_build(srcport, dstport, vtag, chunks, chunkslen, &sctplen);
  if (!sctp)
    return NULL;
  sctp_check((u8*)sctp, sctplen, adler32sum, badsum);
  pkt=ip6_build(src, dst, tc, flowlabel, IPPROTO_SCTP,
      hoplimit, (u8*)sctp, sctplen, pktlen);

  free(sctp);
  return pkt;
}
