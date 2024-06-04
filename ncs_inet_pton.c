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
 * Copyright (c) 1996,1999 by Internet Software Consortium.
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

#include "ncsnet/inet.h"

static int inet_pton4(const char *src, u_char *dst)
{
  static const char digits[] = "0123456789";
  int saw_digit, octets, ch;
  u8 tmp[IP4_ADDR_LEN], *tp;

  saw_digit = 0;
  octets = 0;
  *(tp = tmp) = 0;
  while ((ch = *src++) != '\0') {
    const char *pch;
    if ((pch = strchr(digits, ch)) != NULL) {
      u32 new = *tp * 10 + (pch - digits);
      if (saw_digit && *tp == 0)
	return (0);
      if (new > 255)
	return (0);
      *tp = new;
      if (!saw_digit) {
	if (++octets > 4)
	  return 0;
	saw_digit = 1;
      }
    }
    else if (ch == '.' && saw_digit) {
      if (octets == 4)
	return 0;
      *++tp = 0;
      saw_digit = 0;
    }
    else
      return 0;
  }
  if (octets < 4)
    return (0);
  memcpy(dst, tmp, IP4_ADDR_LEN);
  return 1;
}

static int inet_pton6(const char *src, u_char *dst)
{
  static const char xdigits_l[] = "0123456789abcdef",
    xdigits_u[] = "0123456789ABCDEF";
  u8 tmp[IP6_ADDR_LEN], *tp, *endp, *colonp;
  const char *xdigits, *curtok;
  int ch, seen_xdigits;
  u32 val;

  memset((tp = tmp), '\0', IP6_ADDR_LEN);
  endp = tp + IP6_ADDR_LEN;
  colonp = NULL;
  if (*src == ':')
    if (*++src != ':')
      return (0);
  curtok = src;
  seen_xdigits = 0;
  val = 0;
  while ((ch = *src++) != '\0') {
    const char *pch;
    if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
      pch = strchr((xdigits = xdigits_u), ch);
    if (pch != NULL) {
      val <<= 4;
      val |= (pch - xdigits);
      if (++seen_xdigits > 4)
	return 0;
      continue;
    }
    if (ch == ':') {
      curtok = src;
      if (!seen_xdigits) {
	if (colonp)
	  return (0);
	colonp = tp;
	continue;
      }
      else if (*src == '\0') {
	return 0;
      }
      if (tp + 2 > endp)
	return (0);
      *tp++ = (u8)(val >> 8) & 0xff;
      *tp++ = (u8)val & 0xff;
      seen_xdigits = 0;
      val = 0;
      continue;
    }
    if (ch == '.' && ((tp + IP4_ADDR_LEN) <= endp) &&
	inet_pton4(curtok, tp) > 0) {
      tp += IP4_ADDR_LEN;
      seen_xdigits = 0;
      break;
    }
    return 0;
  }
  if (seen_xdigits) {
    if (tp + 2 > endp)
      return 0;
    *tp++ = (u8)(val >> 8) & 0xff;
    *tp++ = (u8)val & 0xff;
  }
  if (colonp != NULL) {
    const int n = tp - colonp;
    int i;
    if (tp == endp)
      return (0);
    for (i = 1; i <= n; i++) {
      endp[- i] = colonp[n - i];
      colonp[n - i] = 0;
    }
    tp = endp;
  }
  if (tp != endp)
    return 0;
  memcpy(dst, tmp, IP6_ADDR_LEN);
  return 1;
}

int ncs_inet_pton(int af, const char * __restrict src, void * __restrict dst)
{
  switch (af) {
    case AF_INET:
      return (inet_pton4(src, dst));
    case AF_INET6:
      return (inet_pton6(src, dst));
    default: break;
  }
  return -1;
}
