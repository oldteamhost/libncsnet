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

u8 *arp_ethip4_build_pkt(mac_t src, mac_t dst, u16 op, mac_t sha, ip4_t spa, mac_t tha,
  ip4_t tpa, size_t *pktlen)
{
  size_t ethiplen, arplen;
  u8 *arp, *ethip, *pkt;

  ethip=arp_op_request_build(6, 4, sha.octet, spa.octet, tha.octet,
    tpa.octet, &ethiplen);
  if (!ethip)
    return NULL;
  arp = arp_build(ARP_HDR_ETH, ARP_PRO_IP, MAC_ADDR_LEN,
    IP4_ADDR_LEN, op, (u8*)ethip, ethiplen, &arplen);
  free(ethip);
  if (!arp)
    return NULL;
  pkt = eth_build(src, dst, ETH_TYPE_ARP, (u8*)arp,
      arplen, pktlen);
  free(arp);
  if (!pkt)
    return NULL;

  return pkt;
}
