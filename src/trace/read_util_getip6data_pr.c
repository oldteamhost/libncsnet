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

#define ip6_is_extension_header(type)                                          \
  ((type == IPPROTO_HOPOPTS) || (type == IPPROTO_DSTOPTS) ||                   \
   (type == IPPROTO_ROUTING) || (type == IPPROTO_FRAGMENT))

#define ip6_is_upperlayer(type)                                                \
  ((type == IPPROTO_NONE) || (type == IPPROTO_TCP) || (type == IPPROTO_UDP) || \
   (type == IPPROTO_ICMP) || (type == IPPROTO_ICMPV6) ||                       \
   (type == IPPROTO_SCTP))

const void *read_util_getip6data_pr(const struct ip6_hdr *ip6, u32 *len, u8 *nxt,
                          bool upperlayer_only)
{
  const unsigned char *p, *end;
  if (*len < sizeof(*ip6))
    return NULL;
  
  p = (unsigned char *) ip6;
  end = p + *len;
  *nxt = ip6->nxt;
  p += sizeof(*ip6);
  
  while (p < end && ip6_is_extension_header(*nxt)) {
    if (p + 2 > end)
      return NULL;
    *nxt = *p;
    p += (*(p + 1) + 1) * 8;
  }

  *len = end - p;
  if (upperlayer_only && !ip6_is_upperlayer(*nxt))
    return NULL;
  
  return (char*)p; 
}
