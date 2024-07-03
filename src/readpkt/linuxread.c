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

#include <ncsnet/linuxread.h>

#if defined(IS_LINUX) && (HAVE_LINUX_READ == 1)
#include <linux/if_ether.h>
linuxread_t *linuxread_open(long long ns)
{
  linuxread_t *lr;
  
  lr = calloc(1, sizeof(linuxread_t));
  if (!lr)
    return NULL;
  lr->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (lr->fd == -1)
    goto fail;
  if (!(sock_util_timeoutns(lr->fd, ns, true, true)))
    goto fail;
  lr->ms = to_ms(ns);
  
  return lr;
 fail:
  free(lr);
  return NULL;
}

void linuxread_filter(linuxread_t *lr, int proto, struct sockaddr_storage *src) 
{
  lr->proto = proto;
  lr->src = src;
}

ssize_t linuxread_live(linuxread_t *lr, u8 **buf, size_t buflen)
{
  struct sockaddr_in6 *dest6, source6;
  struct sockaddr_in  *dest, source;
  time_t run, current;
  bool ip6, fuckyeah;
  ssize_t res;
  int elapsed;
  u8 *tmpbuf;

  tmpbuf = *buf;
  if (lr->src->ss_family == AF_INET6)
    ip6 = true;
  else
    ip6 = false;
  if (ip6)
    dest6 = (struct sockaddr_in6*)lr->src;
  else
    dest = (struct sockaddr_in*)lr->src;

  run = time(NULL);
  for (;;) {
    res = recv(lr->fd, tmpbuf, buflen, 0);
    if (res == -1)
      return -1;
    if (!ip6) {
      ip4h_t *ip4 = (ip4h_t*)(tmpbuf + sizeof(ethh_t));
      memset(&source, 0, sizeof(source));
      source.sin_addr.s_addr = ip4->src;
      if (source.sin_addr.s_addr == dest->sin_addr.s_addr)
        fuckyeah = true;
      if (ip4->proto != lr->proto)
	fuckyeah = false;
    }
    else {
      ip6h_t *ip6 = (ip6h_t*)(tmpbuf + sizeof(ethh_t));
      memset(&source6, 0, sizeof(source6));
      memcpy(&source6.sin6_addr.s6_addr, ip6->ip6_src.octet, sizeof(ip6->ip6_src.octet));
      if (memcmp(&source6.sin6_addr, &dest6->sin6_addr, sizeof(struct in6_addr)) == 0)
        fuckyeah = true;
      if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != lr->proto)
	fuckyeah = false;
    }
    if (!fuckyeah) {
      current = time(NULL);
      elapsed = (int)(current - run) * 1000;
      if (elapsed >= lr->ms)
	return -1;
      continue;
    }
    else {
      *buf = tmpbuf;
      return res;
    }
  }
  return -1; /* ??? */
}

void linuxread_close(linuxread_t *lr)
{
  close(lr->fd);
  free(lr);
}
#else
linuxread_t *linuxread_open(long long ns) { return NULL; }
void linuxread_filter(linuxread_t *lr, int proto, struct sockaddr_storage *src) { return; }
ssize_t linuxread_live(linuxread_t *lr, u8 **buf, size_t buflen) { return -1; }
void linuxread_close(linuxread_t *lr) { return; }
#endif
