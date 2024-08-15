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

const char *arp_info(const u8 *arp, size_t arplen, int detail)
{
  static char arpinfo[TRACE_PROTO_MAX_LEN]="";
  const char *arpopinfo="";
  arph_t *arph=NULL;

  if (arplen<sizeof(arph_t)||!arp)
    return "arp (incorrect)";
  arph=(arph_t*)arp;

  if (arplen>sizeof(arph_t))
    arpopinfo=arp_operation_info(arp+sizeof(arph_t), arplen-sizeof(arph_t), ntohs(arph->op),
      ntohs(arph->pro), arph->pln, arph->hln);
  if (detail==LOW_DETAIL)
    snprintf(arpinfo, sizeof(arpinfo), "arp hdr=%hu pro=%hu op=%hu (%s)", (u16)ntohs(arph->hdr),
      (u16)ntohs(arph->pro), (u16)ntohs(arph->op), arpopinfo);
  else
    snprintf(arpinfo, sizeof(arpinfo), "arp hdr=%hu pro=%hu hln=%hhu pln=%hhu op=%hu (%s)",
      (u16)ntohs(arph->hdr), (u16)ntohs(arph->pro), arph->hln, arph->pln,
      (u16)ntohs(arph->op), arpopinfo);

  return arpinfo;
}
