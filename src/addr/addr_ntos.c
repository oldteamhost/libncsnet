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

//#include <ncsnet/addr.h>
#include "../../ncsnet/addr.h"
#include <sys/socket.h>

int addr_ntos(const addr_t *a, sockaddr_t *sa)
{
  union sockunion *so=(union sockunion*)sa;
  switch (a->type) {
    case ADDR_TYPE_ETH:
      memset(sa, 0, sizeof(*sa));
      sa->sa_family=AF_UNSPEC;
      memcpy(sa->sa_data, &a->addr_eth, MAC_ADDR_LEN);
      break;
    case ADDR_TYPE_IP6:
      memset(&so->sin6, 0, sizeof(so->sin6));
      so->sin6.sin6_family=AF_INET6;
      memcpy(&so->sin6.sin6_addr, &a->addr_ip6, IP6_ADDR_LEN);
      break;
    case ADDR_TYPE_IP:
      memset(&so->sin, 0, sizeof(so->sin));
      so->sin.sin_family=AF_INET;
      memcpy(&so->sin.sin_addr.s_addr, &a->addr_ip4.octet, IP4_ADDR_LEN);
      break;
    default:
      errno=EINVAL;
      return -1;
  }
  return 0;
}
