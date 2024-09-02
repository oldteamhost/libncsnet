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

#ifndef NCSIP4ADDRHDR
#define NCSIP4ADDRHDR

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define IP4_ADDR_LEN          4   /* 4 octets */
#define IP4_ADDR_BITS         32  /* addrs bits 32 */
#define IP4_ADDR_STRING_LEN   16  /* xxx.xxx.xxx.xxx */
#define IP4_ADDR_STRING_FMT   "%hhu.%hhu.%hhu.%hhu"

typedef struct ip4_addr {
  u8 octet[IP4_ADDR_LEN];
} ip4_t;

#define IP4_ADDR_ANY          (htonl(0x00000000)) /* 0.0.0.0 */
#define IP4_ADDR_BROADCAST    (htonl(0xffffffff)) /* 255.255.255.255 */
#define IP4_ADDR_LOOPBACK     (htonl(0x7f000001)) /* 127.0.0.1 */
#define IP4_ADDR_MCAST_ALL    (htonl(0xe0000001)) /* 224.0.0.1 */
#define IP4_ADDR_MCAST_LOCAL  (htonl(0xe00000ff)) /* 224.0.0.255 */

#define IP4_CLASSA(i)         (((u32)(i)&htonl(0x80000000))==htonl(0x00000000))
#define IP4_CLASSB(i)         (((u32)(i)&htonl(0xc0000000))==htonl(0x80000000))
#define IP4_CLASSC(i)         (((u32)(i)&htonl(0xe0000000))==htonl(0xc0000000))
#define IP4_CLASSD(i)         (((u32)(i)&htonl(0xf0000000))==htonl(0xe0000000))
#define IP4_EXPERIMENTAL(i)   (((u32)(i)&htonl(0xf0000000))==htonl(0xf0000000))
#define IP4_BADCLASS(i)       (((u32)(i)&htonl(0xf0000000))==htonl(0xf0000000))
#define IP4_LOCAL_GROUP(i)    (((u32)(i)&htonl(0xffffff00))==htonl(0xe0000000))
#define IP4_MULTICAST(i)      IP4_CLASSD(i)
#define IP4_CLASSA_NET        (htonl(0xff000000))
#define IP4_CLASSA_NSHIFT     24
#define IP4_CLASSA_HOST       (htonl(0x00ffffff))
#define IP4_CLASSA_MAX        128
#define IP4_CLASSB_NET        (htonl(0xffff0000))
#define IP4_CLASSB_NSHIFT     16
#define IP4_CLASSB_HOST       (htonl(0x0000ffff))
#define IP4_CLASSB_MAX        65536
#define IP4_CLASSC_NET        (htonl(0xffffff00))
#define IP4_CLASSC_NSHIFT     8
#define IP4_CLASSC_HOST       (htonl(0x000000ff))
#define IP4_CLASSD_NET        (htonl(0xf0000000))
#define IP4_CLASSD_NSHIFT     28
#define IP4_CLASSD_HOST       (htonl(0x0fffffff))

/*
 * functions
 */
#define ip4t_getid(addr, index)       (addr)->octet[(index)]
#define ip4t_setid(addr, index, val)  (addr)->octet[(index)]=(u8)(val)
#define ip4t_compare(addr1, addr2)    (memcmp((addr1).octet,(addr2).octet,sizeof(ip4_t))==0)
#define ip4t_copy(addrdst, addrsrc)   (memcpy((addrdst),(addrsrc),sizeof(ip4_t)))
#define ip4t_clear(addr)              (memset(addr,0,sizeof(ip4_t)))
#define ip4t_u32(addr)                (ntohl((u32)((addr)->octet[0]<<24|(addr)->octet[1]<<16|(addr)->octet[2]<<8|(addr)->octet[3])))

#define ip4t_fill(addr, one, two, three, four)            \
  ip4t_setid(addr, 0, one);                               \
  ip4t_setid(addr, 1, two);                               \
  ip4t_setid(addr, 2, three);                             \
  ip4t_setid(addr, 3, four)

#define u32_ip4t(u32addr, addr)                           \
  ip4t_setid(addr, 0, (u8)((ntohl(u32addr))>>24));        \
  ip4t_setid(addr, 1, (u8)(((ntohl(u32addr))>>16)&0xFF)); \
  ip4t_setid(addr, 2, (u8)(((ntohl(u32addr))>>8)&0xFF));  \
  ip4t_setid(addr, 3, (u8)((ntohl(u32addr))&0xFF))

__BEGIN_DECLS

const char *ip4t_ntop_c(const ip4_t *ip4);
char       *ip4t_ntop(const ip4_t *ip4, char *dst, size_t dstlen);
int         ip4t_pton(const char *p, ip4_t *ip4);

__END_DECLS

#endif
