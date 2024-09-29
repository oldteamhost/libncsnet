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

#ifndef NCSIP6ADDRHDR
#define NCSIP6ADDRHDR

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define IP6_ADDR_LEN          16  /* 16 octets */
#define IP6_ADDR_BITS         128 /* addrs bits 128 */
#define IP6_ADDR_STRING_LEN   39  /* xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx */
#define IP6_ADDR_STRING_FMT   "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"

typedef struct ip6_addr {
  u8 octet[IP6_ADDR_LEN];
} ip6_t;

#define IP6_ADDR_UNSPEC \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define IP6_ADDR_LOOPBACK \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
#define IP6_ADDR_BROADCAST \
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
#define IP6_ADDR_LINK_LOCAL_BROADCAST \
  "\xfe\x80\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
#define IP6_ADDR_UNIQUE_LOCAL \
  "\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

/*
 * functions
 */
#define ip6t_isglobal(addr)           ((addr->octet[0]&0xE0)==0x20)
#define ip6t_getid(addr, index)       (addr)->octet[(index)]
#define ip6t_setid(addr, index, val)  (addr)->octet[(index)]=(u8)(val)
#define ip6t_compare(addr1, addr2)    (memcmp((addr1).octet,(addr2).octet,sizeof(ip6_t))==0)
#define ip6t_copy(addrdst, addrsrc)   (memcpy((addrdst),(addrsrc),sizeof(ip6_t)))
#define ip6t_clear(addr)              (memset(addr,0,sizeof(ip6_t)))

#define ip6t_fill(addr, one, two, three, four, five, six, \
    seven, eight, nine, ten, eleven, twelve, thirteen,    \
    fourteen, fifteen, sixteen)                           \
  ip6t_setid(addr,  0, one);                              \
  ip6t_setid(addr,  1, two);                              \
  ip6t_setid(addr,  2, three);                            \
  ip6t_setid(addr,  3, four);                             \
  ip6t_setid(addr,  4, five);                             \
  ip6t_setid(addr,  5, six);                              \
  ip6t_setid(addr,  6, seven);                            \
  ip6t_setid(addr,  7, eight);                            \
  ip6t_setid(addr,  8, nine);                             \
  ip6t_setid(addr,  9, ten);                              \
  ip6t_setid(addr, 10, eleven);                           \
  ip6t_setid(addr, 11, twelve);                           \
  ip6t_setid(addr, 12, thirteen);                         \
  ip6t_setid(addr, 13, fourteen);                         \
  ip6t_setid(addr, 14, fifteen);                          \
  ip6t_setid(addr, 15, sixteen)

__BEGIN_DECLS

const char *ip6t_ntop_c(const ip6_t *ip6);
int         ip6t_pton(const char *p, ip6_t *ip6);
char       *ip6t_ntop(const ip6_t *ip6, char *dst, size_t dstlen);

__END_DECLS

#endif
