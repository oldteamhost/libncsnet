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

#include <ncsnet/udplite.h>

void udplite6_check(u8 *frame, size_t frmlen, const ip6_t src, const ip6_t dst,
    u16 checkcrg, bool badsum)
{
  udpliteh_t *udplite;

  udplite=(udpliteh_t*)frame;
  udplite->checkcrg=htons(checkcrg);
  udplite->check=0;

  if (!checkcrg)
    udplite->check=ip6_pseudocheck(src, dst, IPPROTO_UDPLITE, frmlen, udplite);
  else if (checkcrg>=8&&checkcrg<=frmlen)
    udplite->check=ip6_pseudocheck(src, dst, IPPROTO_UDPLITE, sizeof(udpliteh_t)+checkcrg, udplite);
  else
    udplite->check=0xffff;

  if (badsum) {
    udplite->check--;
    udplite->checkcrg--;
  }
}
