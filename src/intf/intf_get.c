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
#include <linux/wireless.h>

int _intf_get_noalias(intf_t *intf, intf_entry *entry)
{
  char buffer[2*IF_NAMESIZE+1];
  struct ifreq ifr;

  entry->intf_index=if_nametoindex(entry->intf_name);
  if (entry->intf_index==0)
    return -1;
  strlcpy(ifr.ifr_name, entry->intf_name, sizeof(ifr.ifr_name));
  if (ioctl(intf->fd, SIOCGIFFLAGS, &ifr)<0)
    return -1;

  entry->intf_flags=intf_iff_to_flags(ifr.ifr_flags);
  _intf_set_type(entry);

  if (ioctl(intf->fd, SIOCGIFMTU, &ifr)<0)
    return -1;
  entry->intf_mtu=ifr.ifr_mtu;
  entry->intf_addr.type=entry->intf_dst_addr.type=
    entry->intf_link_addr.type=ADDR_TYPE_NONE;

  if (ioctl(intf->fd, SIOCGIFADDR, &ifr)==0) {
    addr_ston(&ifr.ifr_addr, &entry->intf_addr);
    if (ioctl(intf->fd, SIOCGIFNETMASK, &ifr)<0)
      return -1;
    addr_stob(&ifr.ifr_addr, &entry->intf_addr.bits);
  }
  if (entry->intf_type==INTF_TYPE_TUN) {
    if (ioctl(intf->fd, SIOCGIFDSTADDR, &ifr)==0)
     if (addr_ston(&ifr.ifr_addr, &entry->intf_dst_addr)<0)
      return -1;
  }
  else if (entry->intf_type==INTF_TYPE_ETH) {
    if (ioctl(intf->fd, SIOCGIFHWADDR, &ifr)<0)
      return -1;
    if (addr_ston(&ifr.ifr_addr, &entry->intf_link_addr)<0)
      return -1;
  }
  memset(buffer, 0, sizeof(buffer));
  strncpy(buffer, entry->intf_name, sizeof(buffer));
  if (ioctl(intf->fd, SIOCGIWNAME, &buffer)==0)
    entry->intf_type=INTF_TYPE_802_11;

  return 0;
}


int _intf_get_aliases(intf_t *intf, intf_entry *entry)
{
  struct ifreq *ifr, *lifr;
  struct ifreq tmpifr;
  addr_t *ap, *lap;
  char *p;

  if (intf->ifc.ifc_len<(int)sizeof(*ifr)) {
    errno=EINVAL;
    return -1;
  }
  entry->intf_alias_num=0;
  ap=entry->intf_alias_addrs;
  lifr=(struct ifreq*)intf->ifc.ifc_buf+(intf->ifc.ifc_len/sizeof(*lifr));
  lap=(addr_t*)((u8*)entry+entry->intf_len);

  for (ifr=intf->ifc.ifc_req;ifr<lifr&&(ap+1)<lap;ifr=NEXTIFR(ifr)) {
    if ((p=strchr(ifr->ifr_name, ':')))
      *p='\0';
    if (strcmp(ifr->ifr_name, entry->intf_name)!=0)
      if (p) *p = ':';
        continue;

    if (p) *p = ':';
    if (addr_ston(&ifr->ifr_addr, ap)<0)
      continue;

    if (ap->type==ADDR_TYPE_ETH) {
      memcpy(&entry->intf_link_addr, ap, sizeof(*ap));
      continue;
    }
    else if (ap->type==ADDR_TYPE_IP) {
      if (ip4t_compare(ap->addr_ip4, entry->intf_addr.addr_ip4)||ip4t_compare(ap->addr_ip4,entry->intf_dst_addr.addr_ip4))
        continue;
      strlcpy(tmpifr.ifr_name, ifr->ifr_name, sizeof(tmpifr.ifr_name));
      if (ioctl(intf->fd, SIOCGIFNETMASK, &tmpifr)==0)
        addr_stob(&tmpifr.ifr_addr, &ap->bits);
    }
#ifdef SIOCGIFNETMASK_IN6
    else if (ap->type==ADDR_TYPE_IP6&&intf->fd6!= -1) {
      struct in6_ifreq ifr6;

      memcpy(&ifr6, ifr, sizeof(ifr6));

      if (ioctl(intf->fd6, SIOCGIFNETMASK_IN6, &ifr6)==0)
        addr_stob((struct sockaddr*)&ifr6.ifr_addr, &ap->bits);
      else perror("SIOCGIFNETMASK_IN6");
    }
#else
#ifdef SIOCGIFNETMASK6
    else if (ap->type==ADDR_TYPE_IP6&&intf->fd6!=-1) {
      struct in6_ifreq ifr6;

      memcpy(&ifr6, ifr, sizeof(ifr6));

      if (ioctl(intf->fd6, SIOCGIFNETMASK6, &ifr6)==0) {
        ifr6.ifr_Addr.sin6_family=AF_INET6;
        addr_stob((struct sockaddr *)&ifr6.ifr_Addr, &ap->bits);
      }
      else perror("SIOCGIFNETMASK6");
    }
#endif
#endif
    ap++, entry->intf_alias_num++;
  }
#define PROC_INET6_FILE "/proc/net/if_inet6"
  FILE *f;
  char buf[256], s[8][5], name[INTF_NAME_LEN+1];
  u32 idx, bits, scope, flags;
  if ((f=fopen(PROC_INET6_FILE, "r"))) {
    while (ap<lap&&fgets(buf, sizeof(buf), f)) {
      sscanf(buf, "%04s%04s%04s%04s%04s%04s%04s%04s %x %02x %02x %02x %32s\n",
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        &idx, &bits, &scope, &flags, name);
      if (strcmp(name, entry->intf_name)==0) {
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s:%s:%s/%d",
          s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], bits);
        addr_aton(buf, ap);
        ap++, entry->intf_alias_num++;
      }
    }
    fclose(f);
  }
  entry->intf_len=(u8*)ap-(u8*)entry;
  return 0;
}

int intf_get(intf_t *i, intf_entry *entry)
{
  if (_intf_get_noalias(i, entry)<0)
    return -1;
  i->ifc.ifc_buf=(caddr_t)i->ifcbuf;
  i->ifc.ifc_len=sizeof(i->ifcbuf);
  if (ioctl(i->fd, SIOCGIFCONF, &i->ifc)<0)
    return -1;
  return (_intf_get_aliases(i, entry));
}

int
intf_get_index(intf_t *intf, intf_entry *entry, int af, unsigned int index)
{
  char namebuf[IFNAMSIZ];
  char *devname;
  devname=if_indextoname(index, namebuf);
  if (!devname)
    return -1;
  strlcpy(entry->intf_name, devname, sizeof(entry->intf_name));
  return intf_get(intf, entry);
}
