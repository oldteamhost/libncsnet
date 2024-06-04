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

cidr_t *cidr_from_inaddr(const struct in_addr *uaddr)
{
  in_addr_t taddr;
  cidr_t *toret;
  int i;
  
  if(!uaddr)
    return NULL;

  toret = cidr_alloc();
  if(!toret)
    return NULL;
  toret->proto = CIDR_IPV4;
  
  taddr = ntohl(uaddr->s_addr);
  toret->addr[15] = (taddr & 0xff);
  toret->addr[14] = ((taddr>>8) & 0xff);
  toret->addr[13] = ((taddr>>16) & 0xff);
  toret->addr[12] = ((taddr>>24) & 0xff);
  
  toret->mask[15] = toret->mask[14] =
    toret->mask[13] = toret->mask[12] = 0xff;
  
  for(i=0; i<=9; i++)
    toret->addr[i] = 0;
  for(i=10; i<=11; i++)
    toret->addr[i] = 0xff;
  for(i=0; i<=11; i++)
    toret->mask[i] = 0xff;
  
  return(toret);
}
