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

//#include <ncsnet/icmp.h>
#include "../../ncsnet/icmp.h"

u8 *icmp6_msg_ndadvert_build(u8 flags, ip6_t target, u8 *opts, size_t optslen, size_t *msglen)
{
  icmp6_msg_ndadvert *ndadvert;
  u8 *msg;

  *msglen=sizeof(icmp6_msg_ndadvert)+optslen;
  msg=calloc(1, *msglen);
  if (!msg)
    return NULL;
  ndadvert=(icmp6_msg_ndadvert*)msg;
  memset(ndadvert, 0, *msglen);

  if (flags&ICMP6_NDADVERT_RF)
    ndadvert->rf=1;
  if (flags&ICMP6_NDADVERT_SF)
    ndadvert->sf=1;
  if (flags&ICMP6_NDADVERT_OF)
    ndadvert->of=1;

  ndadvert->reserved=0;
  ndadvert->target=target;

  if (opts&&optslen)
    memcpy((u8*)ndadvert+sizeof(icmp6_msg_ndadvert),
      opts, optslen);

  return msg;
}
