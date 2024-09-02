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

int addr_pton(const char *src, addr_t *dst)
{
  char *ep, tmp[300];
  long bits=-1;
  int i;

  if (!src) {
    errno=EINVAL;
    return -1;
  }

  for (i=0;i<(int)sizeof(tmp)-1;i++) {
    if (src[i]=='/') {
      tmp[i]='\0';
      if (strchr(&src[i+1], '.')) {
        ip4_t m;
        u16 b;
        if (ip4t_pton(&src[i+1], &m)!=0) {
          errno=EINVAL;
          return -1;
        }
        addr_mtob(&m.octet, sizeof(m), &b);
        bits=b;
      }
      else {
        bits=strtol(&src[i+1], &ep, 10);
        if (ep==src||*ep!='\0'||bits<0) {
          errno=EINVAL;
          return -1;
        }
      }
      break;
    }
    else if ((tmp[i]=src[i])=='\0')
      break;
  }
  if (ip4t_pton(tmp, &dst->addr_ip4) == 0) {
    dst->type=ADDR_TYPE_IP;
    dst->bits=IP4_ADDR_BITS;
  }
  else if (mact_pton(tmp, &dst->addr_eth) == 0) {
    dst->type=ADDR_TYPE_ETH;
    dst->bits=MAC_ADDR_BITS;
  }
  else if (ip6t_pton(tmp, &dst->addr_ip6) == 0) {
    dst->type=ADDR_TYPE_IP6;
    dst->bits=IP6_ADDR_BITS;
  }
  else {
    errno=EINVAL;
    return -1;
  }
  if (bits>=0) {
    if (bits>dst->bits) {
      errno=EINVAL;
      return -1;
    }
    dst->bits=(u16)bits;
  }
  return 0;
}
