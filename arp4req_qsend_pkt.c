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

#include "ncsnet/arp.h"

int arp4req_qsend_pkt(eth_t *eth, mac_t ethsrc, ip4_addreth_t ipsrc,
                      ip4_addreth_t ipdst)
{
  mac_t macdst, macsrc;
  u32 pktlen;
  u8 *pkt;
  int res;

  mac_aton(&macdst, MAC_ADDR_BROADCAST);
  mac_aton(&macsrc, "\x00\x00\x00\x00\x00\x00");
  
  pkt = arp4_build_pkt(ethsrc, macdst,
      ARP_HDR_ETH, ARP_PRO_IP, MAC_ADDR_LEN, IP4_ADDR_LEN,
      ARP_OP_REQUEST, ethsrc, ipsrc, macsrc,
      ipdst, &pktlen);
  if (!pkt)
    return -1;

  res = eth_send(eth, pkt, pktlen);

  free(pkt);
  return res;
}
