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

intf_t *intf_open(void)
{
  intf_t *intf;
  int one=1, tmpfd;

  intf=calloc(1, sizeof(*intf));
  if (!intf)
    return NULL;
  tmpfd=socket(AF_INET, SOCK_DGRAM, 0);
  intf->fd=tmpfd;
  if (intf->fd<0)
    return (intf_close(intf));
  setsockopt(intf->fd, SOL_SOCKET, SO_BROADCAST, (const char*)&one, sizeof(one));

#if defined(SIOCGLIFCONF)||defined(SIOCGIFNETMASK_IN6)||defined(SIOCGIFNETMASK6)
    if ((intf->fd6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
#ifdef EPROTONOSUPPORT
    if (errno != EPROTONOSUPPORT)
#endif
      return (intf_close(intf));
    }
#endif

  return intf;
}
