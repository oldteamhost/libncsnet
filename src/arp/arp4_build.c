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

#include <ncsnet/arp.h>

u8 *arp4_build(u16 hdr, u16 pro, u8 hln, u8 pln, u16 op, mac_t sha,
               ip4_t spa, mac_t tha, ip4_t tpa,
               u32 *pktlen)
{
  struct arp_hdr *arp;
  int packetlen;
  u8* pkt;

  packetlen = sizeof(struct arp_hdr);
  pkt = (u8*)malloc(packetlen);
  if (!pkt)
    return NULL;
  arp = (struct arp_hdr*)pkt;

  arp->hdr = htons(hdr);
  arp->pro = htons(pro);
  arp->hln = hln;
  arp->pln = pln;
  arp->op  = htons(op);

  memcpy(arp->data,     sha.octet, MAC_ADDR_LEN);
  memcpy(arp->data+6,   spa.octet,  IP4_ADDR_LEN);
  memcpy(arp->data+10,  tha.octet, MAC_ADDR_LEN);
  memcpy(arp->data+16,  tpa.octet,  IP4_ADDR_LEN);

  *pktlen = packetlen;
  return pkt;
}
