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
#include <netinet/in.h>

u16 ip4_pseudocheck(u32 src, u32 dst, u8 proto, u16 len, const void *hstart)
{
  struct pseudo
  {
    u32 src;
    u32 dst;
    u8 zero;
    u8 proto;
    u16 length;
  } hdr;
  int sum;

  hdr.src    = src;
  hdr.dst    = dst;
  hdr.zero   = 0;
  hdr.proto  = proto;
  hdr.length = htons(len);

  sum = ip_check_add(&hdr, sizeof(hdr), 0);
  sum = ip_check_add(hstart, len, sum);
  sum = ip_check_carry(sum);

  /* RFC 768: "If the computed  checksum  is zero,  it is transmitted  as all
   * ones (the equivalent  in one's complement  arithmetic).   An all zero
   * transmitted checksum  value means that the transmitter  generated  no
   * checksum" */
  if (proto == IPPROTO_UDP && sum == 0)
    sum = 0xFFFF;

  return sum;
}
