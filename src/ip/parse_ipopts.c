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

#include <ncsnet/utils.h>

int parse_ipopts(const char *txt, u8 *data, int datalen, int* firsthopoff,
    int* lasthopoff, char *errstr, size_t errstrlen)
{
  enum
  {
    NONE  = 0,
    SLASH = 1,
    MUL   = 2,
    RR    = 3,
    TIME  = 4,
  } s = NONE;

  char *n, lc;
  const char *c = txt;
  u8 *d = data;
  int i,j;
  int base = 10;
  u8 *dataend = &data[datalen];
  u8 *len = NULL;
  char buf[32];
  memset(data, 0, datalen);
  int sourcerouting = 0;
  long strtolbyte = 0;

  for(; *c; c++){
    switch(s){
    case SLASH:
      if(*c == 'x') {
        base = 16;
        break;
      }
      if(isxdigit(*c)) {
        strtolbyte = strtol(c, &n, base);
        if ((strtolbyte < 0) || (strtolbyte > 255)) {
          if (errstr)
            snprintf(errstr, errstrlen, "ipopts, invalid ipv4 address format");
          return -1;
        }
        *d++ = (u8) strtolbyte;
        c = n-1;
      }
      else {
          if (errstr)
            snprintf(errstr, errstrlen, "ipopts, not a digit after '\\'");
          return -1;
      }
      s = NONE;
      break;
    case MUL:
      if (d == data) {
        if(errstr) snprintf(errstr, errstrlen, "ipopts, nothing before '*' char");
          return -1;
      }
      i = strtol(c, &n, 10);
      if (i < 2) {
        if(errstr) snprintf(errstr, errstrlen, "ipopts, bad number after '*'");
        return -1;
      }
      c = n-1;
      lc = *(d-1);
      for(j=1; j<i; j++){
        *d++ = lc;
        if(d == dataend)
          goto after;
      }
      s = NONE;
      break;
    case RR:
      if(*c==' ' || *c==',')
        break;
      n = buf;
      while((*c=='.' || (*c>='0' && *c<='9')) && n-buf <= ((int)sizeof(buf)-1))
        *n++ = *c++;
      *n = '\0'; c--;
      if(d + 4 >= dataend){
        if(errstr) snprintf(errstr, errstrlen, "ipopts, buffer too small. Or input data too big :)");
        return -1;
      }
      i = inet_pton(AF_INET, buf, d);
      if(i < 1) {
        if(errstr) snprintf(errstr, errstrlen, "ipopts, not a valid ipv4 address '%s'",buf);
        return -1;
      }
      if(sourcerouting && !*firsthopoff)
        *firsthopoff = d - data;
      d+=4;
      if(*len<37)
        *len += 4;
      break;
    case TIME:
      if(errstr) snprintf(errstr, errstrlen, "ipopts, no more arguments allowed!");
      return -1;
    default:
      switch(*c){
      case '\\':s = SLASH;base=10;break;
      case '*':s = MUL;break;
      case 'R':
      case 'S':
      case 'L':
        if(d != data){
          if(errstr) snprintf(errstr, errstrlen, "ipopts, this option can't be used in that way");
          return -1;
        }
        *d++ = '\x01';
        switch(*c){
        case 'R':*d++ = 7;break;
        case 'S':*d++ = 137; sourcerouting=1; break;
        case 'L':*d++ = 131; sourcerouting=1; break;
        }
        len = d;
        *d++ = (*c=='R')? 39 : 3;
        *d++ = 4;
        s = RR;
        break;
      case 'T':
      case 'U':
        if(d != data){
          if(errstr) snprintf(errstr, errstrlen, "ipopts, this option can't be used in that way");
          return -1;
        }
        *d++ = 68;
        len = d;
        *d++ = (*c=='U') ? 36 : 40;
        *d++ = 5;
        *d++ = (*c=='U') ? 1 : 0;
        s = TIME;
        break;
      default:
        if(errstr) snprintf(errstr, errstrlen, "ipopts, bad character in ip option '%c'",*c);
          return -1;
      }
    }
    if(d == dataend)
      break;
    assert(d<dataend);
  }
  if(sourcerouting) {
    if(*len<37) {
      *len+=4;
      *lasthopoff = d - data;
      *d++ = 0;*d++ = 0;*d++ = 0;*d++ = 0;
    }
    else {
      if(errstr) snprintf(errstr, errstrlen, "ipopts, when using source routing you must leave at least one slot for target's ip.");
      return -1;
    }
  }
  if(s == RR)
    return(*len+1);
  if(s == TIME)
    return(*len);
after:
  return(d - data);
}
