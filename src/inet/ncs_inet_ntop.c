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

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ncsnet/inet.h>

static const char *inet_ntop4(const u8 *src, char *dst, u32 len)
{
  static const char fmt[] = "%u.%u.%u.%u";
  char tmp[sizeof "255.255.255.255"];
  int l;
  
  l = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
  if (l <= 0 || (u32)l >= len)
    return NULL;
  strlcpy(dst, tmp, len);
  return dst;
}

static const char *inet_ntop6(const u8 *src, char *dst, u32 len)
{
  char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
  u32 words[IP6_ADDR_LEN / 2];
  struct { int base, len; } best, cur;
  int i;
  
  memset(words, '\0', sizeof words);
  for (i = 0; i < IP6_ADDR_LEN; i++)
    words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
  best.base = -1;
  best.len = 0;
  cur.base = -1;
  cur.len = 0;
  for (i = 0; i < (IP6_ADDR_LEN / 2); i++) {
    if (words[i] == 0) {
      if (cur.base == -1)
	cur.base = i, cur.len = 1;
      else
	cur.len++;
    }
    else {
      if (cur.base != -1) {
	if (best.base == -1 || cur.len > best.len)
	  best = cur;
	cur.base = -1;
      }
    }
  }
  if (cur.base != -1) {
    if (best.base == -1 || cur.len > best.len)
      best = cur;
  }
  if (best.base != -1 && best.len < 2)
    best.base = -1;
  tp = tmp;
  for (i = 0; i < (IP6_ADDR_LEN / 2); i++) {
    if (best.base != -1 && i >= best.base &&
	i < (best.base + best.len)) {
      if (i == best.base)
	*tp++ = ':';
      continue;
    }
    if (i != 0)
      *tp++ = ':';
    if (i == 6 && best.base == 0 && (best.len == 6 ||
				     (best.len == 7 && words[7] != 0x0001) ||
				     (best.len == 5 && words[5] == 0xffff))) {
      if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
	return NULL;
      tp += strlen(tp);
      break;
    }
    tp += sprintf(tp, "%x", words[i]);
  }
  if (best.base != -1 && (best.base + best.len) == 
      (IP6_ADDR_LEN / 2))
    *tp++ = ':';
  *tp++ = '\0';
  
  if ((u32)(tp - tmp) > len) {
    return NULL;
  }
  strcpy(dst, tmp);
  return dst;
}

const char *ncs_inet_ntop(int af, const void * __restrict src, char * __restrict dst, u32 len)
{
  switch (af) {
    case AF_INET:
      return (inet_ntop4(src, dst, len));
    case AF_INET6:
      return (inet_ntop6(src, dst, len));
    default: break;
  }
  return NULL;
}
