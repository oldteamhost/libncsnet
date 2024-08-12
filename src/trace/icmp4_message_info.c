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

const char *icmp4_message_info(const u8 *msg, size_t msglen, u8 type, u8 code)
{
  static char icmp4info[TRACE_PROTO_MAX_LEN]="";
  size_t datalen=0;
  
  switch (type) {
  case ICMP4_ECHOREPLY:
  case ICMP4_ECHO: {
    icmp4_msg_echo *echo=(icmp4_msg_echo*)msg;
    datalen=(msglen-sizeof(icmp4_msg_echo));
    char asciidata[asciichar_len(datalen)];
    char hexdata[hexchar_len(datalen)];
    if (msglen>sizeof(icmp4_msg_echo)) {
      asciihex(msg+sizeof(icmp4_msg_echo), datalen, asciidata, hexdata);
      snprintf(icmp4info, sizeof(icmp4info), "id=%hu seq=%hu data=%s(%s) datalen=%ld",
        (u16)ntohs(echo->id), (u16)ntohs(echo->seq), hexdata, asciidata, datalen);
    }
    else
      snprintf(icmp4info, sizeof(icmp4info), "id=%hu seq=%hu data=empty", (u16)ntohs(echo->id),
        (u16)ntohs(echo->seq));
    break;
  }
  case ICMP4_INFO:
  case ICMP4_INFOREPLY: {
    icmp4_msg_info *info=(icmp4_msg_info*)msg;
    snprintf(icmp4info, sizeof(icmp4info), "id=%hu seq=%hu", (u16)ntohs(info->id),
      (u16)ntohs(info->seq));    
    break;
  }
  case ICMP4_TSTAMP:
  case ICMP4_TSTAMPREPLY: {
    icmp4_msg_tstamp *tstamp=(icmp4_msg_tstamp*)msg;
    snprintf(icmp4info, sizeof(icmp4info), "id=%hu seq=%hu orig=%u rx=%u tx=%u",
      (u16)ntohs(tstamp->id), (u16)ntohs(tstamp->seq), (u32)ntohl(tstamp->orig),
      (u32)ntohl(tstamp->rx), (u32)ntohl(tstamp->tx)); 
    break;
  }
  case ICMP4_SRCQUENCH: {
    icmp4_msg_quench *src=(icmp4_msg_quench*)msg;
    snprintf(icmp4info, sizeof(icmp4info), "unsed=%u (Source Quench)", (u32)ntohl(src->unsed));
    break;
  }
  case ICMP4_TIMEXCEED: {
    switch (code) {
    case ICMP4_TIMEXCEED_INTRANS:
      snprintf(icmp4info, sizeof(icmp4info), "(Time to live exceeded in transit)");
      break;
    case ICMP4_TIMEXCEED_REASS:
      snprintf(icmp4info, sizeof(icmp4info), "(Fragment reassembly time exceeded)");
      break;
    default:
      snprintf(icmp4info, sizeof(icmp4info), "(Time exceeded, Bad Code: 0x%x)", code);      
      break;
    break;
  }
  }
  case ICMP4_PARAMPROB: {
    u32 *unsed=NULL;
    u8 *ptr=NULL;
    ptr=(u8*)(msg);
    unsed=(u32*)(msg+sizeof(u8));
    snprintf(icmp4info, sizeof(icmp4info), "ptr=%hhu unsed=%u (Parameter problem: error detected at byte)", *ptr, (u32)ntohl(*unsed));      
    break;
  }
  case ICMP4_REDIRECT: {
    break;
  }
  case ICMP4_MASK:
  case ICMP4_MASKREPLY: {
    icmp4_msg_mask *mask=(icmp4_msg_mask*)msg;
    char auxbuf[128]="";
    ncs_inet_ntop(AF_INET, &mask->mask, auxbuf, 128);
    snprintf(icmp4info, sizeof(icmp4info), "id=%hu seq=%hu mask=%s", (u16)ntohs(mask->id), (u16)ntohs(mask->seq), auxbuf);      
    break;
  }
  case ICMP4_UNREACH: {
    break;
  }
  }
  return icmp4info;
}
