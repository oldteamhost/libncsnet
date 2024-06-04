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

#include <string.h>

#include "sys/nethdrs.h"
#include "sys/types.h"
#include "../ncsnet-config.h"

#define MAC_ADDR_BITS 48
#define MAC_ADDR_LEN  6

#define MAC_ADDR_BROADCAST  "\xff\xff\xff\xff\xff\xff"
#define MAC_ADDR_STRING_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_STRING_LEN 17

#define mac_ismulticast(ea)         (*(ea) & 0x01)
#define mac_getid(buf, index)       (buf)->octet[(index)]
#define mac_setid(buf, index, val)  (buf)->octet[(index)] = (val)
#define mac_copy(dst, src)          (memcpy((dst), (src), sizeof(mac_t)))

#define mac_fill(buf, one, two, three, four, five, six)			\
  mac_setid(buf, 0, one);						\
  mac_setid(buf, 1, two);						\
  mac_setid(buf, 2, three);						\
  mac_setid(buf, 3, four);						\
  mac_setid(buf, 4, five);						\
  mac_setid(buf, 5, six);

#define mac_ip6mult(buf, ip)						\
  mac_setid(buf, 0, 0x33);						\
  mac_setid(buf, 1, 0x33);						\
  mac_setid(buf, 2, ip[12]);						\
  mac_setid(buf, 3, ip[13]);						\
  mac_setid(buf, 4, ip[14]);						\
  mac_setid(buf, 5, ip[15]);						\
  
typedef struct macaddr {
  u8 octet[MAC_ADDR_LEN];
} mac_t;

__BEGIN_DECLS

int mac_aton(mac_t *addr, const char *txt);
int mac_ntoa(mac_t *addr, char *str);

#define hwaddr_aton(addr, txt) mac_aton((addr), (txt))
#define hwaddr_ntoa(addr, str) mac_aton((addr), (str))

__END_DECLS

#endif
