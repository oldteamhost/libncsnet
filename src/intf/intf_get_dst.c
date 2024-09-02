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

//#include <ncsnet/intf.h>
#include "../../ncsnet/intf.h"

int _match_intf_src(const intf_entry *entry, void *arg)
{
  intf_entry *save=(intf_entry*)arg;
  int matched=0, cnt;

  if (entry->intf_addr.type==ADDR_TYPE_IP&&
      ip4t_compare(entry->intf_addr.addr_ip4,save->intf_addr.addr_ip4))
    matched=1;

  for (cnt=0;!matched&&cnt<(int)entry->intf_alias_num;cnt++) {
    if (entry->intf_alias_addrs[cnt].type!=ADDR_TYPE_IP)
      continue;
    if (ip4t_compare(entry->intf_alias_addrs[cnt].addr_ip4,save->intf_addr.addr_ip4))
      matched=1;
  }

  if (matched) {
    if (save->intf_len<entry->intf_len)
      memcpy(save, entry, save->intf_len);
    else
      memcpy(save, entry, entry->intf_len);
    return 1;
  }
  return 0;
}

int intf_get_dst(intf_t *i, intf_entry *entry, addr_t *dst)
{
  struct sockaddr_in sin;
  socklen_t n;

  if (dst->type!=ADDR_TYPE_IP) {
    errno=EINVAL;
    return -1;
  }
  addr_ntos(dst, (struct sockaddr *)&sin);
  sin.sin_port = htons(666);

  if (connect(i->fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    return -1;

  n=sizeof(sin);
  if (getsockname(i->fd, (struct sockaddr *)&sin, &n)<0)
    return -1;

  addr_ston((struct sockaddr *)&sin, &entry->intf_addr);
  if (intf_loop(i, _match_intf_src, entry)!=1)
    return -1;

  return 0;
}

