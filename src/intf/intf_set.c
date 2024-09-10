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

#include <ncsnet/intf.h>

static int _intf_delete_addrs(intf_t *intf, intf_entry *entry)
{
  dnet_ncs_ifalreq ifra;

  memset(&ifra, 0, sizeof(ifra));
  _strlcpy(ifra.ifra_name, entry->intf_name, sizeof(ifra.ifra_name));
  if (entry->intf_addr.type==ADDR_TYPE_IP) {
    addr_ntos(&entry->intf_addr, &ifra.ifra_addr);
    ioctl(intf->fd, SIOCDIFADDR, &ifra);
  }
  if (entry->intf_dst_addr.type==ADDR_TYPE_IP) {
    addr_ntos(&entry->intf_dst_addr, &ifra.ifra_addr);
    ioctl(intf->fd, SIOCDIFADDR, &ifra);
  }

  return 0;
}

static int _intf_delete_aliases(intf_t *intf, intf_entry *entry)
{
  struct ifreq ifr;
  int i;
  for (i=0;i<entry->intf_alias_num;i++) {
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s:%d", entry->intf_name, i+1);
    ifr.ifr_flags=0;
    ioctl(intf->fd, SIOCSIFFLAGS, &ifr);
  }
  return 0;
}

static int _intf_add_aliases(intf_t *intf, const intf_entry *entry)
{
  struct ifreq ifr;
  int i=0,n=1;

  for (;i<entry->intf_alias_num;i++) {
    if (entry->intf_alias_addrs[i].type!=ADDR_TYPE_IP)
      continue;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s:%d", entry->intf_name, n++);
    if (addr_ntos(&entry->intf_alias_addrs[i], &ifr.ifr_addr)<0)
      return -1;
    if (ioctl(intf->fd, SIOCSIFADDR, &ifr)<0)
      return -1;
  }

  _strlcpy(ifr.ifr_name, entry->intf_name, sizeof(ifr.ifr_name));
  return 0;
}

int intf_set(intf_t *intf, const intf_entry *entry)
{
  intf_entry *orig;
  struct ifreq ifr;
  u8 buf[BUFSIZ];
  addr_t bcast;

  orig=(intf_entry*)buf;
  orig->intf_len=sizeof(buf);
  strcpy(orig->intf_name, entry->intf_name);

  if (intf_get(intf, orig)<0)
    return -1;
  if (_intf_delete_aliases(intf, orig)<0)
    return -1;
  if (_intf_delete_addrs(intf, orig)<0)
    return -1;

  memset(&ifr, 0, sizeof(ifr));
  _strlcpy(ifr.ifr_name, entry->intf_name, sizeof(ifr.ifr_name));

  if (entry->intf_mtu!=0) {
    ifr.ifr_mtu=entry->intf_mtu;
    if (ioctl(intf->fd, SIOCSIFMTU, &ifr)<0)
      return -1;
  }
  if (entry->intf_addr.type==ADDR_TYPE_IP) {
    if (addr_ntos(&entry->intf_addr, &ifr.ifr_addr)<0)
      return -1;
    if (ioctl(intf->fd, SIOCSIFADDR, &ifr)<0&&errno!=EEXIST)
      return -1;
  if (addr_btos(entry->intf_addr.bits, &ifr.ifr_addr)==0&&ip4t_u32(&entry->intf_addr.addr_ip4)!=0)
    if (ioctl(intf->fd, SIOCSIFNETMASK, &ifr)<0)
        return -1;
  if (addr_bcast(&entry->intf_addr, &bcast)==0) {
    if (addr_ntos(&bcast, &ifr.ifr_broadaddr)==0)
      ioctl(intf->fd, SIOCSIFBRDADDR, &ifr);
    }
  }
  if (entry->intf_link_addr.type==ADDR_TYPE_ETH&&addr_cmp(&entry->intf_link_addr, &orig->intf_link_addr)!=0) {
    if (addr_ntos(&entry->intf_link_addr, &ifr.ifr_hwaddr)<0)
      return -1;
    if (ioctl(intf->fd, SIOCSIFHWADDR, &ifr)<0)
      return -1;
  }
  if (entry->intf_dst_addr.type==ADDR_TYPE_IP) {
    if (addr_ntos(&entry->intf_dst_addr, &ifr.ifr_dstaddr)<0)
      return -1;
    if (ioctl(intf->fd, SIOCSIFDSTADDR, &ifr)<0&&errno!=EEXIST)
      return -1;
  }
  if (_intf_add_aliases(intf, entry)<0)
    return -1;
  if (ioctl(intf->fd, SIOCGIFFLAGS, &ifr)<0)
    return -1;
  ifr.ifr_flags=intf_flags_to_iff(entry->intf_flags, ifr.ifr_flags);
  if (ioctl(intf->fd, SIOCSIFFLAGS, &ifr)<0)
    return -1;

  return 0;
}
