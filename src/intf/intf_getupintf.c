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

static char
intf[IF_NAMESIZE]="";

static int up_noloopback_noppp_intf(const intf_entry *entry, void *arg)
{
  if (entry->intf_flags&INTF_FLAG_LOOPBACK||
    entry->intf_flags&INTF_FLAG_POINTOPOINT)
    return 0;
  if (entry->intf_flags&INTF_FLAG_UP) {
    snprintf(intf, IF_NAMESIZE, "%s", entry->intf_name);
    return 1;
  }
  return 0;
}

const char* intf_getupintf(void)
{
  intf_t *i;
  i=intf_open();
  if (!i)
    return NULL;
  memset(intf, 0, sizeof(intf));
  if (intf_loop(i, up_noloopback_noppp_intf, NULL)<0)
    return NULL;
  intf_close(i);
  return intf;
}

