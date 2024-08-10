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

//#include <ncsnet/trace.h>
#include "../../ncsnet/trace.h"

const char* udp_info(const u8 *udp, size_t udplen, int detail)
{
  static char  udpinfo[TRACE_PROTO_MAX_LEN]="";
  char         data[TRACE_MAX_DATA_LEN];
  udph_t      *udph=NULL;
  u8          *dataptr=NULL;
  size_t       datalen=0;

  data[0]='\0';
  if (udplen<UDP_HDR_LEN||!udp)
    return "udp (incorrect)";
  udph=(udph_t*)udp;
  
  if ((u16)ntohs(udph->len)>UDP_HDR_LEN) {
    datalen=(u16)ntohs(udph->len)-UDP_HDR_LEN;
    char asciidata[asciichar_len(datalen)];
    char hexdata[hexchar_len(datalen)];
    dataptr=(u8*)udp+((u16)ntohs(udph->len)-datalen);
    asciihex(dataptr, datalen, asciidata, hexdata);
    snprintf(data, sizeof(data), " data=%s(%s) datalen=%ld",
      hexdata, asciidata, datalen);
  }
  
  if (detail == LOW_DETAIL)
    snprintf(udpinfo, sizeof(udpinfo), "udp src=%hu dst=%hu%s",
      (u16)ntohs(udph->srcport), (u16)ntohs(udph->dstport), data);
  else if (detail == MEDIUM_DETAIL)
    snprintf(udpinfo, sizeof(udpinfo), "udp src=%hu dst=%hu csum=0x%04X%s",
      (u16)ntohs(udph->srcport), (u16)ntohs(udph->dstport), ntohs(udph->check), data);
  else if (detail == HIGH_DETAIL)
    snprintf(udpinfo, sizeof(udpinfo), "udp src=%hu dst=%hu len=%hu csum=0x%04X%s",
      (u16)ntohs(udph->srcport), (u16)ntohs(udph->dstport), (u16)ntohs(udph->len),
      ntohs(udph->check),data);
  
  return udpinfo;
}
