/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 * Copyright (c) 2005-2012, Matthew D. Fuller <fullermd@over-yonder.net>. All rights reserved.
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

#include "ncsnet/cidr.h"

int cidr_contains(const cidr_t *big, const cidr_t *little)
{
  int i, oct, bit;
  int pflen;

  if (!big || !little)
    return -1;
  if (big->proto != little->proto)
    return -1;
  if (big->proto != CIDR_IPV4 && big->proto != CIDR_IPV6)
    return -1;
  if (cidr_get_pflen(little) < (pflen = cidr_get_pflen(big)))
    return -1;
  if (big->proto == CIDR_IPV4) {
    i = 96;
    pflen += 96;
  }
  else if(big->proto==CIDR_IPV6)
    i = 0;
  else
    return -1;
  for (; i < pflen; i++ ) {
    oct = i / 8;
    bit = 7 - (i % 8);
    if ((big->addr[oct] & (1 << bit)) != (little->addr[oct] & (1 << bit)))
      return -1;
  }

  return 0;
}
