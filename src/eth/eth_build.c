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

#include <ncsnet/eth.h>

/* in header error */
#include <ncsnet/raw.h>

u8 *eth_build(mac_t src, mac_t dst, u16 type, u8 *frame,
	      size_t frmlen, size_t *pktlen)
{
  u8 *pkt;

  pkt = frmbuild(pktlen, NULL,
    "u8(%hhu), u8(%hhu), u8(%hhu), u8(%hhu), u8(%hhu), u8(%hhu)",
    dst.octet[0], dst.octet[1], dst.octet[2], dst.octet[3],
    dst.octet[4], dst.octet[5]);
  if (pkt)
    pkt = frmbuild_add(pktlen, pkt, NULL,
      "u8(%hhu), u8(%hhu), u8(%hhu), u8(%hhu), u8(%hhu), u8(%hhu)",
       src.octet[0], src.octet[1], src.octet[2], src.octet[3],
       src.octet[4], src.octet[5]);
  if (pkt)  
    pkt = frmbuild_add(pktlen, pkt, NULL, "u16(%hu)", htons(type));
  if (frame && frmlen && pkt)
    pkt = frmbuild_addfrm(frame, frmlen, pkt, pktlen, NULL);
  if (!pkt)
    return NULL;

  return pkt;
}
