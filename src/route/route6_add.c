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

#include <ncsnet/route.h>

int route6_add(route_t *r, const route_entry *entry, int intf_index)
{
  struct in6_rtmsg rt;
  struct addr dst;
  int ret;

  memset(&rt, 0, sizeof(rt));
  rt.rtmsg_flags = RTF_UP;

  if (ADDR_ISHOST(&entry->route_dst)) {
    rt.rtmsg_flags|=RTF_HOST;
    memcpy(&dst, &entry->route_dst, sizeof(dst));
  }
  else
    addr_net(&entry->route_dst, &dst);

  rt.rtmsg_dst_len=entry->route_dst.bits;
  rt.rtmsg_ifindex=intf_index;
  rt.rtmsg_metric=1;

  memcpy(&rt.rtmsg_dst, &dst.addr_ip6, sizeof(rt.rtmsg_dst));

  if (!IN6_IS_ADDR_UNSPECIFIED(&entry->route_gw.addr_ip6)) {
    rt.rtmsg_flags|=RTF_GATEWAY;
    memcpy(&rt.rtmsg_gateway, &entry->route_gw.addr_ip6, sizeof(rt.rtmsg_gateway));
  }

  ret=(ioctl(r->fd6, SIOCADDRT, &rt));
  return ret;
}


