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

int intf_flags_to_iff(u8 flags, int iff)
{
  if (flags&INTF_FLAG_UP)
    iff|=IFF_UP;
  else
    iff&=~IFF_UP;
  if (flags&INTF_FLAG_NOARP)
    iff|=IFF_NOARP;
  else
    iff&=~IFF_NOARP;
  return iff;
}

u32 intf_iff_to_flags(int iff)
{
  u32 n=0;
  if (iff&IFF_UP)
    n|=INTF_FLAG_UP;
  if (iff&IFF_LOOPBACK)
    n|=INTF_FLAG_LOOPBACK;
  if (iff&IFF_POINTOPOINT)
    n|=INTF_FLAG_POINTOPOINT;
  if (iff&IFF_NOARP)
    n|=INTF_FLAG_NOARP;
  if (iff&IFF_BROADCAST)
    n|=INTF_FLAG_BROADCAST;
  if (iff&IFF_MULTICAST)
    n|=INTF_FLAG_MULTICAST;
  return n;
}

/* XXX - this is total crap. how to do this without walking ifnet? */
void _intf_set_type(intf_entry *entry)
{
  if ((entry->intf_flags&INTF_FLAG_LOOPBACK)!=0)
    entry->intf_type=INTF_TYPE_LOOPBACK;
  else if ((entry->intf_flags&INTF_FLAG_BROADCAST)!=0)
    entry->intf_type=INTF_TYPE_ETH;
  else if ((entry->intf_flags&INTF_FLAG_POINTOPOINT)!=0)
    entry->intf_type=INTF_TYPE_TUN;
  else entry->intf_type=INTF_TYPE_OTHER;
}
