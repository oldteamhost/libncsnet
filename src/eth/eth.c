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

//#include <ncsnet/eth.h>
#include "../../ncsnet/eth.h"
#include "../../ncsnet/sys/debianfix.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

struct eth_handle { int fd; struct ifreq ifr; struct sockaddr_ll sll; };
int eth_fd(eth_t *e) { return e->fd; }

eth_t *eth_open(const char *device)
{
  eth_t *e;
  if (!device)
    return NULL;
  e=calloc(1, sizeof(*e));
  if (!e)
    return e;
  if ((e->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0)
    return (eth_close(e));
#ifdef SO_BROADCAST
  int n;
  n=1;
  if (setsockopt(e->fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n))<0)
    return (eth_close(e));
#endif
  _strlcpy(e->ifr.ifr_name, device, sizeof(e->ifr.ifr_name));
  if (ioctl(e->fd, SIOCGIFINDEX, &e->ifr)<0)
    return (eth_close(e));
  memset(&e->sll, 0, sizeof(e->sll));
  e->sll.sll_family=AF_PACKET;
  e->sll.sll_ifindex=e->ifr.ifr_ifindex;

  return e;
}

ssize_t eth_send(eth_t *e, const void *buf, size_t len)
{
  mach_t *eth;

  if (!e||!buf||!len||
    len<sizeof(mach_t))
    return -1;

  eth=(mach_t*)buf;
  e->sll.sll_protocol=eth->type;

  return (sendto(e->fd, buf, len, 0,
        (const struct sockaddr*)&e->sll, sizeof(e->sll)));
}

#include <ncsnet/addr.h>
int eth_get(eth_t *e, mac_t *ea)
{
  addr_t ha;
  if (ioctl(e->fd, SIOCGIFHWADDR, &e->ifr) < 0)
    return -1;
  if (addr_ston(&e->ifr.ifr_hwaddr, &ha) < 0)
    return (-1);
  memcpy(ea, &ha.addr_eth, sizeof(*ea));
  return 0;
}

int eth_set(eth_t *e, const mac_t *ea)
{
  addr_t ha;
  ha.type=ADDR_TYPE_ETH;
  ha.bits=MAC_ADDR_BITS;
  memcpy(&ha.addr_eth, ea, MAC_ADDR_LEN);
  addr_ntos(&ha, &e->ifr.ifr_hwaddr);
  return (ioctl(e->fd, SIOCSIFHWADDR, &e->ifr));
}

ssize_t eth_read(eth_t *e, u8 *buf, ssize_t len, int flags)
{
  return recv(e->fd, buf, len, flags);
}

eth_t *eth_close(eth_t *e)
{
  if (e) {
    if (e->fd>=0)
      close(e->fd);
    free(e);
  }
  return NULL;
}
