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

int ip6t_pton(const char *p, ip6_t *ip6)
{
  u16 data[8], *u=(u16*)ip6->octet;
  int i, j, n, z=-1;
  char *ep;
  long l;

  if (*p==':')
    p++;

  for (n=0;n<8;n++) {
    l=strtol(p, &ep, 16);
    if (ep==p) {
      if (ep[0]==':'&&z==-1) {
        z=n;
        p++;
      }
      else if (ep[0]=='\0')
        break;
      else
        return -1;
    }
    else if (ep[0]=='.'&&n<=6) {
      if (ip4t_pton(p, (ip4_t*)(data+n)) < 0)
        return -1;
      n+=2;
      ep="";
      break;
    }
    else if (l>=0&&l<=0xffff) {
      data[n]=htons((u16)l);
      if (ep[0]=='\0') {
        n++;
        break;
      }
      else if (ep[0]!=':'||ep[1]=='\0')
        return -1;
      p=ep+1;
    }
    else
      return -1;
  }
  if (n==0||*ep!='\0'||(z==-1&&n!=8))
    return -1;
  for (i=0;i<z;i++)
    u[i]=data[i];
  while (i<8-(n-z-1))
    u[i++]=0;
  for (j=z+1;i<8;i++,j++)
    u[i]=data[j];

  return 0;
}


