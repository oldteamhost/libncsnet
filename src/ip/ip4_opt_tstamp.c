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

#include <ncsnet/ip.h>

u8 *ip4_opt_tstamp(u8 ptr, u8 flags, u32 tstamps[], u16 numtstamps, size_t *optlen)
{
  size_t tstamplen, i;
  u8 *res, *tstamp;

  tstamp=frmbuild(&tstamplen, NULL, "u8(%hhu), u8(%hhu), u8(%hhu)",
    ((numtstamps*4)+4), ptr, flags);
  for (i=0;i<numtstamps&&tstamp;i++)
    tstamp=frmbuild_add(&tstamplen, tstamp,
      NULL, "32(%u)", htonl(tstamp[i])); /* htonl ??? */
  if (tstamp)
    res=ip4_opt_type(0, 2, IP4_OPT_TS, optlen);
  if (tstamp&&res)
    res=frmbuild_addfrm(tstamp, tstamplen, res,
      optlen, NULL);
  if (tstamp)
    free(tstamp);
  return res;
}
