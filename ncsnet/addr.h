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

#ifndef _NCSADDRHDR
#define _NCSADDRHDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>

#include "mac.h"
#include "ip.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define ADDR_TYPE_NONE  0 /* No address set */
#define ADDR_TYPE_ETH   1 /* Ethernet */
#define ADDR_TYPE_IP    2 /* Internet Protocol v4 */
#define ADDR_TYPE_IP6   3 /* Internet Protocol v6 */

struct addr {
  u16 type, bits;
  union {
    mac_t __eth;
    ip4_t __ip4;
    ip6_t __ip6;
    u8  __data8[16];
    u16 __data16[8];
    u32 __data32[4];
  } __addr_u;
};

typedef struct addr addr_t;
typedef struct sockaddr sockaddr_t;

union sockunion {
  struct sockaddr_in  sin;
  struct sockaddr_in6 sin6;
  struct sockaddr     sa;
};

#define addr_eth    __addr_u.__eth
#define addr_ip4    __addr_u.__ip4
#define addr_ip6    __addr_u.__ip6
#define addr_data8  __addr_u.__data8
#define addr_data16 __addr_u.__data16
#define addr_data32 __addr_u.__data32

#define addr_pack(addr, _type, _bits, data, len) do { \
  (addr)->type=(_type);                               \
  (addr)->bits=(_bits);                               \
  memmove((addr)->addr_data8, (char*)data, len);      \
} while (0)

__BEGIN_DECLS

int     addr_cmp(const addr_t *a, const addr_t *b);
int     addr_btom(uint16_t bits, void *mask, size_t size);
int     addr_mtob(const void *mask, size_t size, uint16_t *bits);
int     addr_stob(const sockaddr_t *sa, u16 *bits);
int     addr_btos(u16 bits, struct sockaddr *sa);
int     addr_ston(const sockaddr_t *sa, addr_t *a);
int     addr_ntos(const addr_t *a, sockaddr_t *sa);
char   *addr_ntop(const addr_t *src, char *dst, size_t len);
int     addr_pton(const char *src, addr_t *dst);
char   *addr_ntoa(const addr_t *a);
int     addr_bcast(const addr_t *a, addr_t *b);
int     addr_net(const addr_t *a, addr_t *b);
#define addr_aton addr_pton

__END_DECLS


#endif
