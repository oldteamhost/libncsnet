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

int addr_bcast(const addr_t *a, addr_t *b)
{
  addr_t mask;
  int i;

  if (a->type==ADDR_TYPE_IP) {
    addr_btom(a->bits, &mask.addr_ip4, IP4_ADDR_LEN);
    b->type=ADDR_TYPE_IP;
    b->bits=IP4_ADDR_BITS;
    for (i=0;i<IP4_ADDR_LEN;++i)
      b->addr_ip4.octet[i]=(a->addr_ip4.octet[i]&mask.addr_ip4.octet[i])|(~mask.addr_ip4.octet[i]&0xFF);
  }
  else if (a->type==ADDR_TYPE_ETH) {
    b->type=ADDR_TYPE_ETH;
    b->bits=MAC_ADDR_BITS;
    memcpy(&b->addr_eth, MAC_ADDR_BROADCAST, MAC_ADDR_LEN);
  }
  else {
    errno=EINVAL;
    return -1;
  }
  return 0;
}
