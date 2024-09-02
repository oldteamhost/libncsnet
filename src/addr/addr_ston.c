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

#include <ncsnet/addr.h>
#include <ncsnet/arp.h>

int addr_ston(const sockaddr_t *sa, addr_t *a)
{
  union sockunion *so=(union sockunion*)sa;
  memset(a, 0, sizeof(*a));
  switch (sa->sa_family) {
    case AF_UNSPEC:
    case ARP_HDR_ETH:
      a->type=ADDR_TYPE_ETH;
      a->bits=MAC_ADDR_BITS;
      memcpy(&a->addr_eth, sa->sa_data, MAC_ADDR_LEN);
      break;
    case AF_INET6:
      a->type=ADDR_TYPE_IP6;
      a->bits=IP6_ADDR_BITS;
      memcpy(&a->addr_ip6, &so->sin6.sin6_addr, IP6_ADDR_LEN);
      break;
    case AF_INET:
      a->type=ADDR_TYPE_IP;
      a->bits=IP4_ADDR_BITS;
      memcpy(&a->addr_ip4.octet, &so->sin.sin_addr.s_addr, IP4_ADDR_LEN);
      break;
    default:
      errno=EINVAL;
      return -1;
  }
  return 0;
}
