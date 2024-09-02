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

#ifndef NCSARPHDR
#define NCSARPHDR

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

#include "ip.h"
#include "eth.h"
#include "mt19937.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define ARP_HEADER_LEN    8
#define ARP_ETHIP_LEN     20
#define ARP_HDR_LEN       28
#define ARP_PRO_IP        0x0800

#define ARP_HDR_RESERVED      0x00  /* [RFC5494]                                   */
#define ARP_HDR_ETH10MB       0x01  /* Ethernet (10Mb)                             */
#define ARP_HDR_ETH                 ARP_HDR_ETH10MB
#define ARP_HDR_ETH3MB        0x02  /* Experimental Ethernet (3Mb)                 */
#define ARP_HDR_AX25          0x03  /* Amateur Radio AX.25                         */
#define ARP_HDR_PRONET_TR     0x04  /* Proteon ProNET Token Ring                   */
#define ARP_HDR_CHAOS         0x05  /* Chaos                                       */
#define ARP_HDR_IEEE802       0x06  /* IEEE 802 Networks                           */
#define ARP_HDR_ARCNET        0x07  /* ARCNET [RFC1201]                            */
#define ARP_HDR_HYPERCHANNEL  0x08  /* Hyperchannel                                */
#define ARP_HDR_LANSTAR       0x09  /* Lanstar                                     */
#define ARP_HDR_AUTONET       0x0A  /* Autonet Short Address                       */
#define ARP_HDR_LOCALTALK     0x0B  /* LocalTalk                                   */
#define ARP_HDR_LOCALNET      0x0C  /* LocalNet (IBM PCNet or SYTEK LocalNET)      */
#define ARP_HDR_ULTRALINK     0x0D  /* Ultra link                                  */
#define ARP_HDR_SMDS          0x0E  /* SMDS                                        */
#define ARP_HDR_FRAMERELAY    0x0F  /* Frame Relay                                 */
#define ARP_HDR_ATM           0x10  /* Asynchronous Transmission Mode (ATM)        */
#define ARP_HDR_HDLC          0x11  /* HDLC                                        */
#define ARP_HDR_FIBRE         0x12  /* Fibre Channel [RFC4338]                     */
#define ARP_HDR_ATMb          0x13  /* Asynchronous Transmission Mode (ATM)        */
#define ARP_HDR_SERIAL        0x14  /* Serial Line                                 */
#define ARP_HDR_ATMc          0x15  /* Asynchronous Transmission Mode [RFC2225]    */
#define ARP_HDR_MILSTD        0x16  /* MIL-STD-188-220                             */
#define ARP_HDR_METRICOM      0x17  /* Metricom                                    */
#define ARP_HDR_IEEE1394      0x18  /* IEEE 1394.199                               */
#define ARP_HDR_MAPOS         0x19  /* MAPOS [RFC2176]                             */
#define ARP_HDR_TWINAXIAL     0x1A  /* Twinaxial                                   */
#define ARP_HDR_EUI64         0x1B  /* EUI-64                                      */
#define ARP_HDR_HIPARP        0x1C  /* HIPARP                                      */
#define ARP_HDR_ISO7816       0x1D  /* IP and ARP over ISO 7816-3                  */
#define ARP_HDR_ARPSEC        0x1E  /* ARPSec                                      */
#define ARP_HDR_IPSEC         0x1F  /* IPsec tunnel                                */
#define ARP_HDR_INFINIBAND    0x20  /* InfiniBand (TM)                             */
#define ARP_HDR_TIA102        0x21  /* TIA-102 Project 25 Common Air Interface     */
#define ARP_HDR_WIEGAND       0x22  /* Wiegand Interface                           */
#define ARP_HDR_PUREIP        0x23  /* Pure IP                                     */
#define ARP_HDR_HW_EXP1       0x24  /* HW_EXP1 [RFC5494]                           */
#define ARP_HDR_HW_EXP2       0x25  /* HW_EXP2 [RFC5494]                           */

#define ARP_OP_REQUEST        1     /* request to resolve ha given pa */
#define ARP_OP_REPLY          2     /* response giving hardware address */
#define ARP_OP_RARP_REQUEST   3     /* Reverse ARP Request                        */
#define ARP_OP_RARP_REPLY     4     /* Reverse ARP Reply                          */
#define ARP_OP_DRARP_REQUEST  5     /* DRARP-Request                              */
#define ARP_OP_DRARP_REPLY    6     /* DRARP-Reply                                */
#define ARP_OP_DRARP_ERROR    7     /* DRARP-Error                                */
#define ARP_OP_INARP_REQUEST  8     /* InARP-Request                              */
#define ARP_OP_INARP_REPLY    9     /* InARP-Reply                                */
#define ARP_OP_ARPNAK         10    /* ARP-NAK                                    */
#define ARP_OP_MARS_REQUEST   11    /* MARS-Request                               */
#define ARP_OP_MARS_MULTI     12    /* MARS-Multi                                 */
#define ARP_OP_MARS_MSERV     13    /* MARS-MServ                                 */
#define ARP_OP_MARS_JOIN      14    /* MARS-Join                                  */
#define ARP_OP_MARS_LEAVE     15    /* MARS-Leave                                 */
#define ARP_OP_MARS_NAK       16    /* MARS-NAK                                   */
#define ARP_OP_MARS_UNSERV    17    /* MARS-Unserv                                */
#define ARP_OP_MARS_SJOIN     18    /* MARS-SJoin                                 */
#define ARP_OP_MARS_SLEAVE    19    /* MARS-SLeave                                */
#define ARP_OP_MARS_GL_REQ    20    /* MARS-Grouplist-Request                     */
#define ARP_OP_MARS_GL_REP    21    /* MARS-Grouplist-Reply                       */
#define ARP_OP_MARS_REDIR_MAP 22    /* MARS-Redirect-Map                          */
#define ARP_OP_MAPOS_UNARP    23    /* MAPOS-UNARP [RFC2176]                      */
#define ARP_OP_EXP1           24    /* OP_EXP1 [RFC5494]                          */
#define ARP_OP_EXP2           25    /* OP_EXP2 [RFC5494]                          */
#define ARP_OP_RESERVED       65535 /* Reserved [RFC5494]                         */

struct arp_hdr
{
  u16 hdr;
  u16 pro;
  u8  hln;
  u8  pln;
  u16 op;
};

typedef struct arp_hdr arph_t;

struct arp_ethip4 {
  u8 data[ARP_ETHIP_LEN];
};

typedef struct arp_op_hdr_request{
  u8 sha[sizeof(u8)];
  u8 spa[sizeof(u8)];
  u8 tha[sizeof(u8)];
  u8 tpa[sizeof(u8)];
} arp_op_request;

typedef struct arp_op_hdr_request_ethip {
  mac_t sha;
  ip4_t spa;
  mac_t tha;
  ip4_t tpa;
} arp_op_request_ethip;

__BEGIN_DECLS

u8 *arp_build(u16 hdr, u16 pro, u8 hln, u8 pln, u16 op,
    u8 *frame, size_t frmlen, size_t *pktlen);

u8 *arp_op_request_build(u8 hln, u8 pln, u8 *sha, u8 *spa,
    u8 *tha, u8 *tpa, size_t *oplen);

u8 *arp_ethip4_build_pkt(mac_t src, mac_t dst, u16 op,
     mac_t sha, ip4_t spa, mac_t tha, ip4_t tpa, size_t *pktlen);

__END_DECLS

#endif

