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

struct in6_addr *cidr_to_in6addr(const cidr_t *addr, struct in6_addr *uptr)
{
  struct in6_addr *toret;
  int i;
  
  if (!addr)
    return NULL;
  if (addr->proto != CIDR_IPV6 && addr->proto != CIDR_IPV4)
    return NULL;
  toret = uptr;
  if (!toret)
    toret = malloc(sizeof(struct in6_addr));
  if (!toret)
    return NULL;

  memset(toret, 0, sizeof(struct in6_addr));
  for (i=0; i<=15; i++)
    toret->s6_addr[i] = addr->addr[i];
  
  return toret;
}
