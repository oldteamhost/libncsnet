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

char *addr_ntop(const addr_t *src, char *dst, size_t len)
{
  if (src->type==ADDR_TYPE_IP&&len>=20) {
    if (ip4t_ntop(&src->addr_ip4, dst, len)) {
      if (src->bits!=IP4_ADDR_BITS)
        sprintf(dst+strlen(dst), "/%d", src->bits);
      return dst;
    }
  }
  else if (src->type==ADDR_TYPE_IP6&&len>=42) {
    if (ip6t_ntop(&src->addr_ip6, dst, len)) {
      if (src->bits!=IP6_ADDR_BITS)
        sprintf(dst+strlen(dst), "/%d", src->bits);
      return dst;
    }
  }
  else if (src->type==ADDR_TYPE_ETH&&len>=18) {
    if (src->bits==MAC_ADDR_BITS) {
      mact_ntop((mac_t*)&src->addr_eth, dst, src->bits);
      return dst;
    }
  }
  errno=EINVAL;
  return NULL;
}
