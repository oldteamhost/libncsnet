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

cidr_t **cidr_net_subnets(const cidr_t *addr)
{
  cidr_t **toret;
  int pflen;
  int i, j;

  if (!addr)
    return NULL;

  pflen = cidr_get_pflen(addr);
  if((addr->proto==CIDR_IPV4 && pflen==32)
     || (addr->proto==CIDR_IPV6 && pflen==128))
    return NULL;
  
  toret = malloc(2 * sizeof(cidr_t*));
  if(!toret)
    return NULL;
  
  toret[0] = cidr_addr_network(addr);
  if (!toret[0]) {
    free(toret);
    return NULL;
  }
  
  if (toret[0]->proto == CIDR_IPV4)
    pflen += 96;
  
  i = pflen / 8;
  j = 7 - (pflen % 8);
  (toret[0])->mask[i] |= 1<<j;

  toret[1] = cidr_dup(toret[0]);
  if(!toret[1]) {
    cidr_free(toret[0]);
    free(toret);
    return NULL;
  }
  
  (toret[1])->addr[i] |= 1<<j;
  return toret;
}
