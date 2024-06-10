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

#include "ncsnet/sys/debianfix.h"

size_t _strlcpy(char *dst, const char *src, size_t dlen)
{
#ifdef OLD
  const char *osrc = src;
  u64 nleft = dlen;
  if (nleft != 0)
    while (--nleft != 0)
      if ((*dst++ = *src++) == '\0')
        break;
  if (nleft == 0) {
    if (dlen != 0)
      *dst = '\0';
    while (*src++);
  }
  return(src - osrc - 1);
#endif
  
  register char *d = dst;
  register const char *s = src;
  register size_t n = dlen;

  if (n != 0 && --n != 0) {
    do {
      if ((*d++ = *s++) == 0)
	break;
    } while (--n != 0);
  }
  if (n == 0) {
    if (dlen != 0)
      *d = '\0';
    while (*s++);
  }
  
  return(s - src - 1);	
}
