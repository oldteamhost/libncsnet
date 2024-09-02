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

int addr_net(const addr_t *a, addr_t *b)
{
  int i, j;
  u32 mask;

  if (a->type==ADDR_TYPE_IP) {
    addr_btom(a->bits, &mask, IP4_ADDR_LEN);
    b->type=ADDR_TYPE_IP;
    b->bits=IP4_ADDR_BITS;
    for (i=0;i<IP4_ADDR_LEN;++i)
      b->addr_ip4.octet[i]=a->addr_ip4.octet[i]&((mask>>(8*i))&0xFF);
  }
  else if (a->type==ADDR_TYPE_ETH) {
    memcpy(b, a, sizeof(*b));
    if (a->addr_data8[0] & 0x1)
      memset(b->addr_data8 + 3, 0, 3);
    b->bits=MAC_ADDR_BITS;
  }
  else if (a->type==ADDR_TYPE_IP6) {
    b->type=ADDR_TYPE_IP6;
    b->bits=IP6_ADDR_BITS;
    memset(&b->addr_ip6, 0, IP6_ADDR_LEN);
    switch ((i=a->bits/32)) {
      case 4: b->addr_data32[3]=a->addr_data32[3];
      case 3: b->addr_data32[2]=a->addr_data32[2];
      case 2: b->addr_data32[1]=a->addr_data32[1];
      case 1: b->addr_data32[0]=a->addr_data32[0];
    }
    if ((j=a->bits%32)>0) {
      addr_btom(j, &mask, sizeof(mask));
      b->addr_data32[i]=a->addr_data32[i] & mask;
    }
  }
  else
    return -1;

  return 0;
}
