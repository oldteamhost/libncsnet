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

#include <ncsnet/hex.h>

u8 *hex_ahtoh(char *txt, size_t *hexlen)
{
  static u8 dst[16384];
  size_t dstlen=16384;
  char auxbuff[1024];
  char *start=NULL;
  char twobytes[3];
  u32 i=0, j=0;

  if (!txt||!hexlen)
    return NULL;
  if (strlen(txt)==0)
    return NULL;
  memset(auxbuff,0,1024);
  if (!strncmp("0x", txt, 2)) {
    if (strlen(txt)==2)
      return NULL;
    start=txt+2;
  }
  else if(!strncmp("\\x", txt, 2)) {
    if (strlen(txt)==2)
      return NULL;
    for (i=0;i<strlen(txt)&&j<1023;i++)
      if(txt[i]!='\\'&&txt[i]!='x'&&txt[i]!='X')
        auxbuff[j++]=txt[i];
    auxbuff[j]='\0';
    start=auxbuff;
  }
  else
    start=txt;
  for (i=0;i<strlen(start);i++)
    if (!isxdigit(start[i]))
      return NULL;
  if (strlen(start)%2!=0)
    return NULL;
  for (i=0,j=0;j<dstlen&&i<strlen(start)-1;i+=2) {
    twobytes[0]=start[i];
    twobytes[1]=start[i+1];
    twobytes[2]='\0';
    dst[j++]=(u8)strtol(twobytes, NULL, 16);
  }

  *hexlen=j;
  return dst;
}
