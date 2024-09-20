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

#include <ncsnet/ip.h>

u8 *ip4_build(const ip4_t src, const ip4_t dst, u8 proto, int ttl, u16 id, u8 tos, u16 off,
              u8 *opts, int optslen, u8 *frame, size_t frmlen, size_t *pktlen)
{
  u8 *pkt;

  assert(optslen<=IP4_OPT_LEN_MAX);
  pkt=frmbuild(pktlen, NULL, "4(4), 4(%hhu), 8(%hhu), 16(%hu), 16(%hu), 16(%hu), 8(%hhu), 8(%hhu), 16(0)",
    (5+(optslen/4)), tos, htons(((sizeof(ip4h_t)+optslen)+frmlen)), htons(id), off, ttl, proto);
  if (pkt)
    pkt=frmbuild_add(pktlen, pkt, NULL, "8(%hhu), 8(%hhu), 8(%hhu), 8(%hhu)",
      ip4t_getid(&src, 0), ip4t_getid(&src, 1), ip4t_getid(&src, 2), ip4t_getid(&src, 3));
  if (pkt)
    pkt=frmbuild_add(pktlen, pkt, NULL, "8(%hhu), 8(%hhu), 8(%hhu), 8(%hhu)",
      ip4t_getid(&dst, 0), ip4t_getid(&dst, 1), ip4t_getid(&dst, 2), ip4t_getid(&dst, 3));
  if (pkt&&opts&&optslen)
    pkt=frmbuild_addfrm(opts, optslen, pkt, pktlen, NULL);
  if (pkt)
    ip4_check(pkt, sizeof(ip4h_t)+optslen, false);

  if (pkt&&frame&&frmlen)
    pkt=frmbuild_addfrm(frame, frmlen, pkt, pktlen, NULL);

  return pkt;
}
