/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
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

#ifndef NCSINTFHDR
#define NCSINTFHDR

#include "addr.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "sys/debianfix.h"
#include "../ncsnet-config.h"

#define INTF_NAME_LEN 32
#define INTF_VERS_LEN 32

#define INTF_TYPE_OTHER       1   /* other */
#define INTF_TYPE_ETH         6   /* Ethernet */
#define INTF_TYPE_TOKENRING   9   /* Token Ring */
#define INTF_TYPE_FDDI        15  /* FDDI */
#define INTF_TYPE_PPP         23  /* Point-to-Point Protocol */
#define INTF_TYPE_LOOPBACK    24  /* software loopback */
#define INTF_TYPE_SLIP        28  /* Serial Line Interface Protocol */
#define INTF_TYPE_TUN         53  /* proprietary virtual/internal */
#define INTF_TYPE_802_11      99

#define INTF_FLAG_UP          0x01 /* enable interface */
#define INTF_FLAG_LOOPBACK    0x02 /* is a loopback net (r/o) */
#define INTF_FLAG_POINTOPOINT 0x04 /* point-to-point link (r/o) */
#define INTF_FLAG_NOARP       0x08 /* disable ARP */
#define INTF_FLAG_BROADCAST   0x10 /* supports broadcast (r/o) */
#define INTF_FLAG_MULTICAST   0x20 /* supports multicast (r/o) */

#define NEXTIFR(i) (i + 1)

typedef struct intf_entry_hdr {
  u32    intf_len;
  char   intf_name[INTF_NAME_LEN];
  char   os_intf_name[INTF_NAME_LEN];
  char   pcap_intf_name[INTF_NAME_LEN];
  char   driver_name[INTF_VERS_LEN];
  char   driver_vers[INTF_VERS_LEN];
  char   firmware_vers[INTF_VERS_LEN];
  u32    intf_index;
  u16    intf_type;
  u16    intf_flags;
  u32    intf_mtu;
  addr_t intf_addr;
  addr_t intf_dst_addr;
  addr_t intf_link_addr;
  u32    intf_alias_num;
  addr_t intf_alias_addrs __flexarr;
} intf_entry;

typedef struct dnet_ifaliasreq_hdr {
  char   ifra_name[IFNAMSIZ];
  struct sockaddr ifra_addr;
  struct sockaddr ifra_brdaddr;
  struct sockaddr ifra_mask;
  int    ifra_cookie;
} dnet_ncs_ifalreq;

typedef struct intf_handle {
  int    fd;
  int    fd6;
  struct ifconf ifc;
  u8     ifcbuf[4192];
} intf_t;

typedef int (*intf_handler)(const intf_entry *entry, void *arg);

__BEGIN_DECLS

intf_t *intf_open(void);
int     intf_get(intf_t *i, intf_entry *entry);
int     intf_get_src(intf_t *i, intf_entry *entry, addr_t *src);
int     intf_get_dst(intf_t *i, intf_entry *entry, addr_t *dst);
int     intf_set(intf_t *i, const intf_entry *entry);
int     intf_loop(intf_t *i, intf_handler callback, void *arg);
intf_t *intf_close(intf_t *i);

const char* intf_getupintf(void);
int intf_flags_to_iff(u8 flags, int iff);
u32 intf_iff_to_flags(int iff);
void _intf_set_type(intf_entry *entry);

__END_DECLS

#endif
