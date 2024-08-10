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

#include <ncsnet/trace.h>

char *read_hexdump(const u8 *txt, size_t txtlen)
{
#define HEX_START 7
#define ASC_START 57
#define LINE_LEN 74  
  static char asciify[257];
  int asc_init=0;
  u32 i=0, hex=0, asc=0;
  u32 line_count=0;
  char *current_line=NULL;
  char *buffer=NULL;
  char line2print[LINE_LEN];
  char printbyte[16];
  int bytes2alloc;
  
  memset(line2print, ' ', LINE_LEN);
  if (asc_init==0){
    asc_init=1;
    for (i=0;i<256;i++){
      if (isalnum(i) || isdigit(i) || ispunct(i))
	asciify[i]=i;
      else
	asciify[i]='.';
    }
  }
  
  bytes2alloc=(txtlen%16==0)?(1+LINE_LEN*(txtlen/16)):(1+LINE_LEN*(1+(txtlen/16)));
  buffer=(char*)calloc(1, bytes2alloc);
  current_line=buffer;

  i=0;
  while (i<txtlen){
    memset(line2print, ' ', LINE_LEN);
    snprintf(line2print, sizeof(line2print), "%04x", (16*line_count++) % 0xFFFF);
    line2print[4]=' ';
    hex=HEX_START;
    asc=ASC_START;
    do {
        if (i%16==8)
	  hex++;
        snprintf(printbyte, sizeof(printbyte), "%02x", txt[i]);
        line2print[hex++]=printbyte[0];
        line2print[hex++]=printbyte[1];
        line2print[hex++]=' ';
        line2print[asc++]=asciify[txt[i]];
        i++;
    } while (i<txtlen&&i%16!=0);
    
    line2print[LINE_LEN-1]='\n';
    memcpy(current_line, line2print, LINE_LEN);
    current_line+=LINE_LEN;
  }
  
  buffer[bytes2alloc-1]='\0';
  return buffer;
}
