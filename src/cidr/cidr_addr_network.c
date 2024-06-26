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

#include <ncsnet/cidr.h>

cidr_t *cidr_addr_network(const cidr_t *addr)
{
  int i, j;
  cidr_t *toret;
  
  if (!addr)
    return NULL;
  
  toret = cidr_alloc();
  if (!toret)
    return NULL;
  toret->proto = addr->proto;
  memcpy(toret->mask, addr->mask,
	 (16 * sizeof(toret->mask[0])) );
  
  for (i = 0; i <= 15; i++) {
    for (j = 7; j >= 0; j--) {
      if ((addr->mask[i] & 1 << j) == 0)
	return(toret);
      toret->addr[i] |= (addr->addr[i] & 1 << j);
    }
  }
  
  return toret;
}
