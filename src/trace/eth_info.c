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

const char *eth_info(const u8 *eth, size_t ethlen, int detail)
{
  static char  ethinfo[TRACE_PROTO_MAX_LEN]="";
  char         dst[MAC_ADDR_STRING_LEN];
  char         src[MAC_ADDR_STRING_LEN];
  mach_t      *ethh=NULL;

  if (ethlen<ETH_HDR_LEN||!eth)
    return "eth (incorrect)";
  ethh=(mach_t*)eth;

  mact_ntop(&ethh->dst, dst, MAC_ADDR_STRING_LEN);
  mact_ntop(&ethh->src, src, MAC_ADDR_STRING_LEN);

  if (detail==LOW_DETAIL)
    snprintf(ethinfo, sizeof(ethinfo), "eth %s -> %s", src, dst);
  else
    snprintf(ethinfo, sizeof(ethinfo), "eth %s -> %s (%#hx)",
      src, dst, (u16)ntohs(ethh->type));

  return ethinfo;
}
