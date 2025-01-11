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

//#include <ncsnet/hex.h>
#include "../../ncsnet/hex.h"

const char *util_bytesconv(size_t bytes)
{
  const char *sizes[]={
    "B", "KiB", "MiB", "GiB", "TiB",
    "PiB", "EiB"
  };
  static char buffer[32];
  double c=(double)bytes;
  int i=0;
  while (c>=1024&&i<6) { c/=1024; i++; }
  snprintf(buffer, sizeof(buffer), "%.2f %s", c, sizes[i]);
  return buffer;
}

void hexdump_pro(u8 *hex, size_t hexlen, hdopts *opts)
{
  size_t i, j, o, miss, oshift, offres;
  char *ascii;
  if (!hex||!hexlen||!opts)
    return;
  if (opts->asciiprint) {
    if (!(ascii=calloc(1, hexlen)))
      return;
    memset(ascii, 0, hexlen);
  }
  if (opts->asciiprint)
    for (i=oshift=0;i<hexlen;i++)
      ascii[i]=((isalnum(hex[i])||isdigit(hex[i])||
        ispunct(hex[i]))?hex[i]:'.');
  for (i=offres=0;i<hexlen;i++) {
    if ((i%opts->off)==0) {
      if (i!=0) {
        if (opts->asciiprint) {
          printf("  ");
          for (o=0;o<opts->off;o++)
            putchar(ascii[o+oshift]);
          oshift+=o;
        }
        putchar('\n');
      }
      if (opts->offprint)
        printf("%s%04lx  ", ((opts->hexprfx)?
          opts->hexprfx:""), offres);
      offres+=opts->off;
    }
    printf("%s%02x", ((opts->hexprfx)?
      opts->hexprfx:""), hex[i]);
    if (i+1<hexlen&&(i+1)%opts->off!=0)
      for (j=0;j<opts->snum;j++)
        putchar(' ');
  }
  if (opts->asciiprint&&oshift<hexlen) {
    j=hexlen%opts->off;
    if (j!=0) {
      miss=(j==0)?0:opts->off-j;
      o=((miss)*2)+2+(miss*opts->snum);
      if (opts->hexprfx)
        o+=((strlen(opts->hexprfx)==1)?
          miss:strlen(opts->hexprfx)*miss);
      for (j=0;j<o;j++)
        printf(" ");
    }
    else
      printf("  ");
    for (i=oshift;i<hexlen;i++)
      putchar(ascii[i]);
  }
  if (opts->infoprint)
    printf("\nLength %s (offset %ld)\n",
      util_bytesconv(hexlen), opts->off);
  else
    putchar('\n');
  if (ascii&&opts->asciiprint)
    free(ascii);
}
