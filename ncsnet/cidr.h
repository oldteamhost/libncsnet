/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 * Copyright (c) 2005-2012, Matthew D. Fuller <fullermd@over-yonder.net>. All rights reserved.
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

#ifndef NCSCIDRHDR
#define NCSCIDRHDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "sys/nethdrs.h"
#include "sys/types.h"
#include "../ncsnet-config.h"

#define CIDR_NOFLAGS      (0)
#define CIDR_NOCOMPACT    (1)     /* Don't do :: compaction */
#define CIDR_VERBOSE      (1<<1)  /* Don't minimize leading zeros */
#define CIDR_USEV6        (1<<2)  /* Use v6 form for v4 addresses */
#define CIDR_USEV4COMPAT  (1<<3)  /* Use v4-compat rather than v4-mapped */
#define CIDR_NETMASK      (1<<4)  /* Show netmask instead of pflen */
#define CIDR_ONLYADDR     (1<<5)  /* Only show the address */
#define CIDR_ONLYPFLEN    (1<<6)  /* Only show the pf/mask */
#define CIDR_WILDCARD     (1<<7)  /* Show wildcard-mask instead of netmask */
#define CIDR_FORCEV6      (1<<8)  /* Force treating as v6 address */
#define CIDR_FORCEV4      (1<<9)  /* Force treating as v4 address */
#define CIDR_REVERSE      (1<<10) /* Return a DNS PTR name */

#define CIDR_NOPROTO        0
#define CIDR_IPV4           1
#define CIDR_IPV6           2

#define RANGE_CHAR_LEN_MAX 31

typedef struct cidrblock {
  int version;
  u8  addr[16];
  u8  mask[16];
  int proto;
} cidr_t;

__BEGIN_DECLS

char            *cidr_to_str(const cidr_t *block, int flags);
cidr_t          *cidr_from_str(const char *addr);
struct in_addr  *cidr_to_inaddr(const cidr_t *addr, struct in_addr *uptr);
cidr_t          *cidr_from_inaddr(const struct in_addr *uaddr);
struct in6_addr *cidr_to_in6addr(const cidr_t *addr, struct in6_addr *uptr);
cidr_t          *cidr_from_in6addr(const struct in6_addr *uaddr);
cidr_t          *cidr_addr_network(const cidr_t *addr);
cidr_t          *cidr_addr_broadcast(const cidr_t *addr);
cidr_t          *cidr_addr_hostmin(const cidr_t *addr);
cidr_t          *cidr_addr_hostmax(const cidr_t *addr);
cidr_t          *cidr_alloc(void);
cidr_t          *cidr_dup(const cidr_t *src);
#define          cidr_free(tofree) free(tofree)
u8              *__cidr_get_data(const cidr_t *addr, const uint8_t *data);
int              cidr_get_pflen(const cidr_t *block);
#define cidr_get_addr(_addr) __cidr_get_data((_addr), (_addr)->addr)
#define cidr_get_mask(_addr) __cidr_get_data((_addr), (_addr)->mask)
#define          cidr_get_proto(_addr) ((!_addr) ? (-1) : (_addr)->proto)
int              cidr_contains(const cidr_t *big, const cidr_t *little);
int              cidr_equals(const cidr_t *one, const cidr_t *two);
const char      *cidr_numaddr(const cidr_t *addr);
const char      *cidr_numhost(const cidr_t *addr);
const char      *cidr_numaddr_pflen(int pflen);
const char      *cidr_numhost_pflen(int pflen);
int              cidr_is_v4mapped(const cidr_t *addr);
cidr_t          *cidr_net_supernet(const cidr_t *addr);
cidr_t         **cidr_net_subnets(const cidr_t *addr);
void             cidr_to_str_range(const cidr_t *addr, char* buf, u32 buflen);
__int128_t       cidr_get_numhost(const cidr_t *addr);

__END_DECLS

#endif
