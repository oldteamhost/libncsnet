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

u16 ip6_pseudocheck(const ip6_t src, const ip6_t dst, u8 nxt, u32 len, const void *hstart)
{
  int sum;
  struct pseudo
  {
    ip6_t src;
    ip6_t dst;
    u32   length;
    u8    z0, z1, z2;
    u8    nxt;
  } hdr;

  ip6t_copy(&hdr.src, &src);
  ip6t_copy(&hdr.dst, &dst);
  hdr.z0=hdr.z1=hdr.z2=0;
  hdr.length=htonl(len);
  hdr.nxt=nxt;

  sum=ip_check_add(&hdr, sizeof(hdr), 0);
  sum=ip_check_add(hstart, len, sum);
  sum=ip_check_carry(sum);

  /*
   * RFC 2460: "Unlike IPv4, when UDP packets are originated by an IPv6 node,
   * the UDP checksum is not optional.  That is, whenever originating a UDP
   * packet, an IPv6 node must compute a UDP checksum over the packet and the
   * pseudo-header, and, if that computation yields a result of zero, it must be
   * changed to hex FFFF for placement in the UDP header."
   */
  if (nxt==IPPROTO_UDP&&sum==0)
    sum=0xFFFF;

  return sum;
}
