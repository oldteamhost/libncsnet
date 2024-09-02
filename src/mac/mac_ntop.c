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

#include <ncsnet/mac.h>

void hexascii(u8 byte, char *str)
{
  u8 i=0;
  str[0]=(byte>>4)&0x0f;
  str[1]=byte&0x0f;
  for (;i<2;i++) {
    if (str[i]>9)
      str[i]+='a'-10;
    else
      str[i]+='0';
  }
}

int mact_ntop(const mac_t *mac, char *dst, size_t dstlen)
{
  char tmp[3];
  u8 i=0;

  if (dstlen<MAC_ADDR_STRING_LEN)
    return -1;

  dst[0]='\0';
  for (;i<MAC_ADDR_LEN;++i) {
    hexascii(mac->octet[i], tmp);
    if (tmp[0]=='\0') {
      tmp[0]='0';
      tmp[1]=tmp[2];
    }
    tmp[2]='\0';
    strcat(dst, tmp);
    if (i<MAC_ADDR_LEN-1)
      strcat(dst, ":");
  }

  return 0;
}
