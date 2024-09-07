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

#ifndef NCSSOCKS5HDR
#define NCSSOCKS5HDR

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "socket.h"
#include "ip.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

/*
 * RFC 1928, RFC 1929, RFC 1961
 * AUTH 0x0A–0x7F IANA Unassigned
 * AUTH 0x80–0xFE methods reserved for private use
 */

#define SOCKS5_VERSION                      0x05
#define SOCKS5_VERSION_AUTH                 0x01
#define SOCKS5_RESERVED                     0x00

#define SOCKS5_CMD_CONNECT                  0x01
#define SOCKS5_CMD_BIND                     0x02
#define SOCKS5_CMD_UDPASSOCIATE             0x03

#define SOCKS5_AUTH_NO                      0x00
#define SOCKS5_AUTH_GSSAPI                  0x01
#define SOCKS5_AUTH_USERPASS                0x02
#define SOCKS5_AUTH_IANA_UNASSIGNED         0x04
#define SOCKS5_AUTH_IANA_CHALLENGE_HADSHAKE 0x03
#define SOCKS5_AUTH_IANA_CHALLENGE_RESPONSE 0x05
#define SOCKS5_AUTH_IANA_SEC_SOCKETS_LAYER  0x06
#define SOCKS5_AUTH_IANA_NDS                0x07
#define SOCKS5_AUTH_IANA_MULTI_FRAMEWORK    0x08
#define SOCKS5_AUTH_IANA_JSON_PARAM_BLOCK   0x09
#define SOCKS5_AUTH_NOT_FOUND               0xFF

#define SOCKS5_CODE_SUCCEEDED               0x00
#define SOCKS5_CODE_GENERAL_FAILURE         0x01
#define SOCKS5_CODE_CONNCTION_NOW_ALLOWED   0x02
#define SOCKS5_CODE_NETWORK_UNCREACHABLE    0x03
#define SOCKS5_CODE_HOST_UNCREACHABLE       0x04
#define SOCKS5_CODE_CONNECTION_REFUSED      0x05
#define SOCKS5_CODE_TTL_EXPIRED             0x06
#define SOCKS5_CODE_COMMAND_NOT_SUPPORT     0x07
#define SOCKS5_CODE_ADDR_NOT_SUPPORT        0x08

#define SOCKS5_ADDR_TYPE_IP4                0x01
#define SOCKS5_ADDR_TYPE_DOMAIN             0x03
#define SOCKS5_ADDR_TYPE_IP6                0x04

struct socks5_hdr
{
  u8 version;
  u8 cmd; /* or reply */
  u8 reserved;
  u8 addrtype;
  
};

typedef struct {
  int fd;
  const char *proxy, *dst;
  u16 proxy_port, dstport;
  const char *login, *pass;
  u8 addrtype, authtype;
} socks5_t;

typedef struct
{
  const char *proxy_host;
  int proxy_port;
  const char *target_host;
  int target_port;
  int socket;
} socks_5_connection;

__BEGIN_DECLS

socks5_t *socks5_open(long long ns, const char *proxy, u16 proxyport, const char *login, const char *pass);
u8       *socks5_build(u8 version, u8 cmd, u8 addrtype, const char *data, u32 datalen, u32 *pktlen);
bool      socks5_bind(socks5_t *s, const char *dst, u16 dstport);
bool      socks5_send(socks_5_connection *connection, const char *data, size_t size);
void      socks5_close(socks5_t *s);


__END_DECLS

#endif

