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

#ifndef NCSMACHDR
#define NCSMACHDR

#include "ip4addr.h"
#include "ip6addr.h"

#include "sys/nethdrs.h"
#include "sys/types.h"
#include "../ncsnet-config.h"

#define MAC_ADDR_LEN          6  /* 6 octets */
#define MAC_ADDR_BITS         48 /* addrs bits 48 */
#define MAC_ADDR_STRING_LEN   17 /* xx:xx:xx:xx:xx:xx*/
#define MAC_ADDR_STRING_FMT   "%02X:%02X:%02X:%02X:%02X:%02X"

typedef struct macaddr {
  u8 octet[MAC_ADDR_LEN];
} mac_t;

#define MAC_ADDR_BROADCAST  "\xff\xff\xff\xff\xff\xff"
#define MAC_ADDR_ZERO       "\x00\x00\x00\x00\x00\x00"

/*
 * functions
 */
#define mact_getid(addr, index)        (addr)->octet[(index)]
#define mact_setid(addr, index, val)   (addr)->octet[(index)]=(val)
#define mact_compare(addr1, addr2)     (memcmp((addr1).octet,(addr2).octet,sizeof(mac_t))==0)
#define mact_copy(addrdst, addrsrc)    (memcpy((addrdst),(addrsrc),sizeof(mac_t)))
#define mact_clear(addr)               (memset(addr,0,sizeof(mac_t)))
#define mact_ismulticast(addr)         (*(addr)&0x01)

#define mact_fill(addr, one, two, three, four, five, six) \
  mact_setid(addr, 0, one);                               \
  mact_setid(addr, 1, two);                               \
  mact_setid(addr, 2, three);                             \
  mact_setid(addr, 3, four);                              \
  mact_setid(addr, 4, five);                              \
  mact_setid(addr, 5, six)

#define mact_ip4multicast(addr, ip4taddr)                 \
  mact_setid(addr, 0, 0x01);                              \
  mact_setid(addr, 1, 0x00);                              \
  mact_setid(addr, 2, 0x5e);                              \
  mact_setid(addr, 3, (ip4t_getid(ip4taddr,1)&0x7f));     \
  mact_setid(addr, 4, (ip4t_getid(ip4taddr,2)));          \
  mact_setid(addr, 5, (ip4t_getid(ip4taddr,3)))

#define mact_ip6multicast(addr, ip6taddr)                 \
  mact_setid(addr, 0, 0x33);                              \
  mact_setid(addr, 1, 0x33);                              \
  mact_setid(addr, 2, (ip6t_getid(ip6taddr,12)));         \
  mact_setid(addr, 3, (ip6t_getid(ip6taddr,13)));         \
  mact_setid(addr, 4, (ip6t_getid(ip6taddr,14)));         \
  mact_setid(addr, 5, (ip6t_getid(ip6taddr,15)))

__BEGIN_DECLS

#define hwaddr_aton(addr, txt) mac_aton((addr), (txt))
#define hwaddr_ntoa(addr, str) mac_aton((addr), (str))

const char* mact_ntop_c(mac_t *mac);
int         mact_pton(const char *txt, mac_t *mac);
int         mact_ntop(const mac_t *mac, char *dst, size_t dstlen);

__END_DECLS

#endif
