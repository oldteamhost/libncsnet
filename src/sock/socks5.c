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

#include "ncsnet/socks5.h"

static bool socks5_handshake(socks5_t *s);
static bool socks5_connect(struct sockaddr_storage *addr, socks5_t *s);
static bool socks5_auth(socks5_t *s);

u8 *socks5_build(u8 version, u8 cmd, u8 addrtype, const char *data, u32 datalen, u32 *pktlen)
{
  struct socks5_hdr *socks5;
  u8 *pkt = NULL;

  *pktlen = sizeof(struct socks5_hdr) + datalen;
  pkt = (u8*)malloc(*pktlen);
  if (!pkt)
    return NULL;
  
  socks5           = (struct socks5_hdr*)pkt;
  socks5->cmd      = cmd;
  socks5->addrtype = addrtype;
  socks5->reserved = SOCKS5_RESERVED;
  socks5->version  = version;
  
  if (data && datalen)
    memcpy((u8*)socks5 + sizeof(struct socks5_hdr), data, datalen);
  
  return pkt;
}

socks5_t *socks5_open(long long ns, const char *proxy, u16 proxyport,
		      const char *login, const char *pass)
{
  struct sockaddr_storage addr;
  socks5_t *res;
    
  res = calloc(1, sizeof(socks5_t));
  if (!res)
    return NULL;
  res->fd = socket(AF_INET, SOCK_STREAM, 0);
  if (res->fd == -1) {
    free(res);
    return NULL;
  }
  sock_util_timeoutns(res->fd, ns, true, true);
  res->proxy = proxy;
  res->proxy_port = proxyport;
  res->login = login ? login : NULL;
  res->pass = pass ? pass : NULL;

  switch(this_is(proxy)) {
    case IPv6: {
      struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&addr;
      addr6->sin6_family = AF_INET6;
      addr6->sin6_port = htons(res->proxy_port);
      inet_pton(AF_INET6, proxy, &addr6->sin6_addr);
      break;
    }
    case IPv4: {
      struct sockaddr_in *addr4 = (struct sockaddr_in*)&addr;
      addr4->sin_family = AF_INET;
      addr4->sin_port = htons(res->proxy_port);
      addr4->sin_addr.s_addr = inet_addr(proxy);
      break;
    }
    case DNS: {
      struct sockaddr_in *addr4 = (struct sockaddr_in*)&addr;
      char ipbuf[16];
      ip4_util_strdst(proxy, ipbuf, sizeof(ipbuf));
      addr4->sin_family = AF_INET;
      addr4->sin_port = htons(res->proxy_port);
      addr4->sin_addr.s_addr = inet_addr(ipbuf);
      break;
    }
  }
  if (!socks5_connect(&addr, res))
    goto fail;
  return res;
  
 fail:
  socks5_close(res);
  return NULL;
}

bool socks5_bind(socks5_t *s, const char *dst, u16 dstport)
{
  s->dst = dst;
  s->dstport = dstport;
  s->addrtype = 0;

  switch(this_is(s->dst)) {
    case IPv6: s->addrtype = SOCKS5_ADDR_TYPE_IP6; break;
    case IPv4: s->addrtype = SOCKS5_ADDR_TYPE_IP4; break;
    case DNS:  s->addrtype = SOCKS5_ADDR_TYPE_DOMAIN; break;        
  }

  return(socks5_auth(s));
}

void socks5_close(socks5_t *s)
{
  close(s->fd);
  free(s);
}

static bool socks5_auth(socks5_t *s)
{
  u8 handshake_response[CMD_BUFFER];
  struct socks5_hdr *hdr = NULL;
  char *hostinfo = NULL;
  u32 pktlen, hostinfolen;
  u8 *pkt = NULL;
  
  hostinfolen = 0;
  switch(s->addrtype) {
  case SOCKS5_ADDR_TYPE_DOMAIN: {
    hostinfolen = strlen(s->dst) + 1 + sizeof(u16);
    hostinfo = malloc(hostinfolen);
    hostinfo[0] = (u16)strlen(s->dst);
    memcpy(hostinfo + 1, s->dst, strlen(s->dst));
    u16 port = htons(s->dstport);
    memcpy(hostinfo + 1 + strlen(s->dst), &port, sizeof(port));
    break;
  }
  }
  printf("%s and %d\n", hostinfo, hostinfolen);
  pkt = socks5_build(((s->authtype == SOCKS5_AUTH_USERPASS)
      ? SOCKS5_VERSION_AUTH : SOCKS5_VERSION),
     SOCKS5_CMD_CONNECT, s->addrtype, hostinfo, hostinfolen, &pktlen);
  if (!pkt)
      return false;
  free(hostinfo);
  if (send(s->fd, pkt, pktlen, 0) == -1) {
    free(pkt);
    return false;
  }
  free(pkt);
  if (recv(s->fd, handshake_response, CMD_BUFFER, 0) == -1)
    return false;
  hdr = (struct socks5_hdr*)handshake_response;
  if (!hdr || hdr->version != SOCKS5_VERSION ||
      hdr->cmd != SOCKS5_CODE_SUCCEEDED) {
    printf("jdsl\n");
    return false;
  }

  return true;
}

static bool socks5_handshake(socks5_t *s)
{
  u8 handshake_response[CMD_BUFFER];
  u8 *pkt = NULL;
  struct socks5_hdr *hdr;
  u32 pktlen;
  
  pkt = socks5_build(SOCKS5_VERSION, SOCKS5_CMD_CONNECT,
     0, NULL, 0, &pktlen);
  if (!pkt)
    return false;
  if (send(s->fd, pkt, pktlen, 0) == -1) {
    free(pkt);
    return false;
  }
  free(pkt);
  
  if (recv(s->fd, handshake_response, CMD_BUFFER, 0) == -1)
    return false;
  hdr = (struct socks5_hdr*)handshake_response;
  if (!hdr || hdr->version != SOCKS5_VERSION ||
      hdr->cmd == SOCKS5_AUTH_NOT_FOUND)
    return false;
  
  s->authtype = hdr->cmd;
  return true;
}

static bool socks5_connect(struct sockaddr_storage *addr, socks5_t *s)
{
  if (connect(s->fd, (struct sockaddr*)addr, sizeof(*addr)) == -1)
    return false;
  return (socks5_handshake(s));
}
