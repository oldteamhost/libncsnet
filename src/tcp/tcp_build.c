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

#include <ncsnet/tcp.h>

u8 *tcp_build(u16 srcport, u16 dstport, u32 seq, u32 ack, u8 reserved, u8 flags,
              u16 win, u16 urp, u8 *opt, size_t optlen, u8 *frame, size_t frmlen,
              size_t *pktlen)
{
  u8 *pkt;
  pkt=frmbuild(pktlen, NULL, "16(%hu), 16(%hu), 32(%u), 32(%u), 4(%hhu), 4(%hhu), 8(%hhu), 16(%hu), 16(0), 16(%hu)",
    htons(srcport), htons(dstport), htonl(seq), htonl(ack), (5+(optlen/4)),
    ((reserved)?(reserved&0xFF):0), flags, htons(win), htons(urp));
  if (pkt&&opt&&optlen)
    pkt=frmbuild_addfrm(opt, optlen, pkt, pktlen, NULL);
  if (pkt&&frame&&frmlen)
    pkt=frmbuild_addfrm(frame, frmlen, pkt, pktlen, NULL);
  return pkt;
}
