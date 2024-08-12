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

static bool icmp4checkcksum(const u8 *icmp4, size_t icmp4len, u16 *correct)
{
  u8 tmp[icmp4len];
  memcpy(tmp, icmp4, icmp4len);
  *correct=0;
  tmp[sizeof(u8)*2]=0;
  tmp[sizeof(u8)*2+1]=0;
  *correct=((u16)ntohs(in_check((u16*)tmp, (int)icmp4len)));
  if ((u16)ntohs(*(u16*)(icmp4+(sizeof(u8)*2)))==*correct)
    return true;
  return false;
}

const char *icmp4_info(const u8 *icmp4, size_t icmp4len, int detail)
{
  static char icmp4info[TRACE_PROTO_MAX_LEN]="";
  char validcksum[128]="";
  const char *msginfo="";
  icmph_t *icmp4h=NULL;
  u16 correctcksum=0;

  if (icmp4len<ICMP4_HDR_LEN||!icmp4)
    return "icmp4 (incorrect)";
  icmp4h=(icmph_t*)icmp4;

  if (icmp4len>ICMP4_HDR_LEN)
    msginfo=icmp4_message_info(icmp4+ICMP4_HDR_LEN, icmp4len-ICMP4_HDR_LEN,
      icmp4h->type, icmp4h->code);
  if (detail==LOW_DETAIL)
    snprintf(icmp4info, sizeof(icmp4info), "icmp type=%hhu code=%hhu (%s)",
      icmp4h->type, icmp4h->code, msginfo);
  else {
    if (icmp4checkcksum(icmp4, icmp4len, &correctcksum))
      snprintf(validcksum, sizeof(validcksum), " [good]");
    else
      snprintf(validcksum, sizeof(validcksum), " [bad(correct=0x%04x]", correctcksum);
    snprintf(icmp4info, sizeof(icmp4info), "icmp type=%hhu code=%hhu csum=0x%04x%s (%s)",
      icmp4h->type, icmp4h->code, (u16)ntohs(icmp4h->check), validcksum, msginfo);
  }

  return icmp4info;
}
