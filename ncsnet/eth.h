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

#ifndef NCSETHHDR
#define NCSETHHDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mt19937.h"
#include "mac.h"

#include "sys/nethdrs.h"
#include "sys/types.h"
#include "../ncsnet-config.h"

#define ETH_TYPE_LEN        2
#define ETH_CRC_LEN         4
#define ETH_HDR_LEN         14
#define ETH_LEN_MIN         64   /* minimum frame length with CRC */
#define ETH_LEN_MAX         1518 /* maximum frame length with CRC */

#define ETH_MTU             (ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN)
#define ETH_MIN             (ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN)

#define ETH_TYPE_IPV4       0x0800 /* Internet Protocol Version 4              */
#define ETH_TYPE_ARP        0x0806 /* Address Resolution Protocol              */
#define ETH_TYPE_FRAMERELAY 0x0808 /* Frame Relay ARP                          */
#define ETH_TYPE_PPTP       0x880B /* Point-to-Point Tunneling Protocol        */
#define ETH_TYPE_GSMP       0x880C /* General Switch Management Protocol       */
#define ETH_TYPE_RARP       0x8035 /* Reverse Address Resolution Protocol      */
#define ETH_TYPE_IPV6       0x86DD /* Internet Protocol Version 6              */
#define ETH_TYPE_MPLS       0x8847 /* MPLS                                     */
#define ETH_TYPE_MPS_UAL    0x8848 /* MPLS with upstream-assigned label        */
#define ETH_TYPE_MCAP       0x8861 /* Multicast Channel Allocation Protocol    */
#define ETH_TYPE_PPPOE_D    0x8863 /* PPP over Ethernet Discovery Stage        */
#define ETH_TYPE_PPOE_S     0x8864 /* PPP over Ethernet Session Stage          */
#define ETH_TYPE_CTAG       0x8100 /* Customer VLAN Tag Type                   */
#define ETH_TYPE_EPON       0x8808 /* Ethernet Passive Optical Network         */
#define ETH_TYPE_PBNAC      0x888E /* Port-based network access control        */
#define ETH_TYPE_STAG       0x88A8 /* Service VLAN tag identifier              */
#define ETH_TYPE_ETHEXP1    0x88B5 /* Local Experimental Ethertype             */
#define ETH_TYPE_ETHEXP2    0x88B6 /* Local Experimental Ethertype             */
#define ETH_TYPE_ETHOUI     0x88B7 /* OUI Extended Ethertype                   */
#define ETH_TYPE_PREAUTH    0x88C7 /* Pre-Authentication                       */
#define ETH_TYPE_LLDP       0x88CC /* Link Layer Discovery Protocol (LLDP)     */
#define ETH_TYPE_MACSEC     0x88E5 /* Media Access Control Security            */
#define ETH_TYPE_MVRP       0x88F5 /* Multiple VLAN Registration Protocol      */
#define ETH_TYPE_MMRP       0x88F6 /* Multiple Multicast Registration Protocol */
#define ETH_TYPE_FRRR       0x890D /* Fast Roaming Remote Request              */

/*
 * IEEE 802.3
 * Ethernet/Ethernet II
 */
struct eth_hdr
{
  mac_t dst;
  mac_t src;
  u16   type;
};

typedef struct eth_hdr ethh_t;
typedef struct eth_hdr eth2h_t;
typedef struct eth_hdr mach_t;
typedef struct eth_handle eth_t;

struct ethtmp
{
  eth_t *ethsd;
  mac_t  dst;
  mac_t  src;
  char   devname[16];
};

__BEGIN_DECLS

eth_t   *eth_open(const char *device);
int      eth_fd(eth_t *e);
ssize_t  eth_read(eth_t *e, u8 *buf, ssize_t len, int flags);
ssize_t  eth_send(eth_t *e, const void *buf, size_t len);
int      eth_get(eth_t *e, mac_t *ea);
int      eth_set(eth_t *e, const mac_t *ea);
u8      *eth_build(mac_t src, mac_t dst, u16 type, u8 *frame,
  size_t frmlen, size_t *pktlen);
eth_t   *eth_open_cached(const char *device);
void     eth_close_cached(void);
eth_t   *eth_close(eth_t *e);

__END_DECLS

#endif
