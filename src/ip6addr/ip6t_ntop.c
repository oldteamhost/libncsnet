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

#include <ncsnet/ip6addr.h>
#include <ncsnet/ip4addr.h>

char *ip6t_ntop(const ip6_t *ip6, char *dst, size_t dstlen)
{
  struct { int base, len; } best, cur;
  u16 *ip6_data;
  char *p=dst;
  int i;

  cur.len=best.len=0;

  if (dstlen<IP6_ADDR_STRING_LEN)
   return NULL;

  best.base=cur.base=-1;

  /*
   * Algorithm borrowed from Vixie's inet_pton6()
   */
  for (i=0;i<IP6_ADDR_LEN;i+=2) {
    ip6_data=(u16*)&ip6->octet[i];
    if (*ip6_data==0) {
      if (cur.base==-1) {
        cur.base=i;
        cur.len=0;
      }
      else
        cur.len+=2;
    }
    else {
      if (cur.base!=-1) {
        if (best.base==-1||cur.len>best.len)
          best=cur;
        cur.base=-1;
      }
    }
  }
  if (cur.base!=-1&&(best.base==-1||cur.len>best.len))
    best=cur;
  if (best.base!=-1&&best.len<2)
    best.base=-1;
  if (best.base==0)
    *p++=':';

  for (i=0;i<IP6_ADDR_LEN;i+=2) {
    if (i==best.base) {
      *p++=':';
      i+=best.len;
    }
    else if (i==12&&best.base==0&&(best.len== 10||(best.len==8&&*(ip6_data=(u16*)&ip6->octet[10])==0xffff))) {
      if (!ip4t_ntop((ip4_t*)&ip6->octet[12], p, dstlen-(p-dst)))
        return NULL;
      return dst;
    }
    else
      p+=sprintf(p, "%x:", ntohs(*(ip6_data=(u16*)&ip6->octet[i])));
  }
  if (best.base+2+best.len==IP6_ADDR_LEN)
    *p = '\0';
  else
    p[-1] = '\0';

  return dst;
}



