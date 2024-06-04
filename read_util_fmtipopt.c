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

#include "ncsnet/readpkt.h"

int Vsnprintf(char *s, size_t n, const char *fmt, va_list ap)
{
  int ret;
  ret = vsnprintf(s, n, fmt, ap);
  if (ret < 0 || (unsigned)ret >= n)
    s[n - 1] = '\0';
  return ret;
}

static inline char *STRAPP(const char *fmt, ...)
{
  static char buf[256];
  static int bp;
  int left = (int)sizeof(buf)-bp;
  if(!fmt){
    bp = 0;
    return(buf);
  }
  if (left <= 0)
    return buf;
  va_list ap;
  va_start(ap, fmt);
  bp += Vsnprintf (buf+bp, left, fmt, ap);
  va_end(ap);

  return(buf);
}

#define BREAK()		\
  {option_type = HEXDUMP; break;}
#define CHECK(tt)                                                              \
  if (tt >= option_end) {                                                      \
    option_type = HEXDUMP;                                                     \
    break;                                                                     \
  }

#define HEXDUMP -2
#define UNKNOWN -1
char *read_util_fmtipopt(const u8 *ipopt, int ipoptlen)
{
  char ipstring[32];
  int option_type = UNKNOWN;
  int option_len  = 0;
  int option_pt   = 0;
  int option_fl   = 0;
  const u8 *tptr;
  u32 *tint;

  int option_sta = 0;
  int option_end = 0;
  int pt = 0;

  STRAPP(NULL,NULL);
  if(!ipoptlen)
    return(NULL);

  while (pt<ipoptlen) {
    if (option_type == UNKNOWN) {
      option_sta  = pt;
      option_type = ipopt[pt++];
      if (option_type != 0 && option_type != 1) {
        if (pt >= ipoptlen)
          {option_type = HEXDUMP;pt--; option_end = 255; continue;}
        option_len  = ipopt[pt++];
        option_end  = MIN(option_sta + option_len, ipoptlen);
        option_end  = MAX(option_end, option_sta+2);
      }
    }
    switch(option_type) {
    case 0:
      STRAPP(" EOL", NULL);
      option_type = UNKNOWN;
      break;
    case 1:
      STRAPP(" NOP", NULL);
      option_type = UNKNOWN;
      break;
    case 131:
    case 137:
    case 7:
      if (pt - option_sta == 2) {
	STRAPP(" %s%s{", (option_type==131)?"LS":(option_type==137)?"SS":"", "RR");
	CHECK(pt);
	option_pt = ipopt[pt++];
	if (option_pt%4 != 0 || (option_sta + option_pt-1)>option_end || option_pt<4)
	  STRAPP(" [bad ptr=%02i]", option_pt);
      }
      if (pt - option_sta > 2) { // ip's
	int i, s = (option_pt)%4;
	CHECK(pt+3);
	for (i=0; i<s; i++)
	  STRAPP("\\x%02x", ipopt[pt++]);
	option_pt -= i;
	CHECK(pt+3);
	tptr = &ipopt[pt]; pt+=4;
	if (ncs_inet_ntop(AF_INET, (char *) tptr, ipstring, sizeof(ipstring)) == NULL)
	  return NULL;
	STRAPP("%c%s",(pt-3-option_sta)==option_pt?'#':' ', ipstring);
	if (pt == option_end)
	  STRAPP("%s",(pt-option_sta)==(option_pt-1)?"#":"");
      }
      else BREAK();
      break;
    case 68:
      if (pt - option_sta == 2){
	STRAPP(" TM{");
	CHECK(pt);
	option_pt  = ipopt[pt++];
	if (option_pt%4 != 1 || (option_sta + option_pt-1)>option_end || option_pt<5)
	  STRAPP(" [bad ptr=%02i]", option_pt);
	CHECK(pt);
	option_fl  = ipopt[pt++];
	if ((option_fl&0x0C) || (option_fl&0x03)==2)
	  STRAPP(" [bad flags=\\x%01hhx]", option_fl&0x0F);
	STRAPP("[%i hosts not recorded]", option_fl>>4);
	option_fl &= 0x03;
      }
      if (pt - option_sta > 2) {// ip's
	int i, s = (option_pt+3)%(option_fl==0?4:8);
	CHECK(pt+(option_fl==0?3:7));
	for (i=0; i<s; i++)
	  STRAPP("\\x%02x", ipopt[pt++]);
	option_pt-=i;
	STRAPP("%c",(pt+1-option_sta)==option_pt?'#':' ');
	if (option_fl!=0){
	  CHECK(pt+3);
	  tptr = &ipopt[pt]; pt+=4;
	  if (ncs_inet_ntop(AF_INET, (char *) tptr, ipstring, sizeof(ipstring)) == NULL){
	    return NULL;
	  }
	  STRAPP("%s@", ipstring);
	}
	CHECK(pt+3);
	tint = (u32*)&ipopt[pt]; pt+=4;
	STRAPP("%lu", (unsigned long) ntohl(*tint));
	if (pt == option_end)
	  STRAPP("%s",(pt-option_sta)==(option_pt-1)?"#":" ");
      }
      else BREAK();
      break;
    case 136:
      if (pt - option_sta == 2){
	u16 *sh;
	STRAPP(" SI{",NULL);
	if (option_sta+option_len > ipoptlen || option_len!=4)
	  STRAPP("[bad len %02i]", option_len);
	CHECK(pt+1);
	sh = (u16*) &ipopt[pt]; pt+=2;
	option_pt  = ntohs(*sh);
	STRAPP("id=%hu", (u16) option_pt);
	if (pt != option_end)
	  BREAK();
      }
      else BREAK();
      break;
    case UNKNOWN:
    default:
      STRAPP(" ??{\\x%02hhx\\x%02hhx", option_type, option_len);
      if (option_len < ipoptlen)
	option_end = MIN(MAX(option_sta+option_len, option_sta+2),ipoptlen);
      else
	option_end = 255;
      option_type = HEXDUMP;
      break;
    case HEXDUMP:
      assert(pt<=option_end);
      if (pt == option_end){
	STRAPP("}",NULL);
	option_type=-1;
	break;
      }
      STRAPP("\\x%02hhx", ipopt[pt++]);
      break;
    }
    if (pt == option_end && option_type != UNKNOWN) {
      STRAPP("}",NULL);
      option_type = UNKNOWN;
    }
  }
  if (option_type != UNKNOWN)
    STRAPP("}");
  return(STRAPP("",NULL));
}
#undef CHECK
#undef BREAK
#undef UNKNOWN
#undef HEXDUMP
