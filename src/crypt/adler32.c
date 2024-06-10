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

#include <ncsnet/adler32.h>

u32 adler32(u32 adler, const u8 *buf, size_t len)
{
  unsigned long sum2;
  u32 n;

  sum2 = (adler >> 16) & 0xffff;
  adler &= 0xffff;
  
  if (len == 1) {
    adler += buf[0];
    if (adler >= BASE)
      adler -= BASE;
    sum2 += adler;
    if (sum2 >= BASE)
      sum2 -= BASE;
    return adler | (sum2 << 16);
  }

  if (buf == 0)
    return 1L;

  if (len < 16) {
    while (len--) {
      adler += *buf++;
      sum2 += adler;
    }
    if (adler >= BASE)
      adler -= BASE;
    MOD28(sum2);
    return adler | (sum2 << 16);
  }
  
  while (len >= NMAX) {
    len -= NMAX;
    n = NMAX / 16;
    do {
      DO16(buf);
      buf += 16;
    } while (--n);
    MOD(adler);
    MOD(sum2);
  }
  
  if (len) {
    while (len >= 16) {
      len -= 16;
      DO16(buf);
      buf += 16;
    }
    while (len--) {
      adler += *buf++;
      sum2 += adler;
    }
    MOD(adler);
    MOD(sum2);
  }
  
  return adler | (sum2 << 16);
}

u32 adler32combine(u32 adler1, u32 adler2, i64 len2)
{
  unsigned long sum1;
  unsigned long sum2;
  u32 rem;

  if (len2 < 0)
    return 0xffffffffUL;
  
  MOD63(len2);
  rem = (u32)len2;
  sum1 = adler1 & 0xffff;
  sum2 = rem * sum1;
  MOD(sum2);
  sum1 += (adler2 & 0xffff) + BASE - 1;
  sum2 += ((adler1 >> 16) & 0xffff) + ((adler2 >> 16) & 0xffff) + BASE - rem;
  
  if (sum1 >= BASE)
    sum1 -= BASE;
  if (sum1 >= BASE)
    sum1 -= BASE;
  if (sum2 >= ((unsigned long)BASE << 1))
    sum2 -= ((unsigned long)BASE << 1);
  if (sum2 >= BASE)
    sum2 -= BASE;
  
  return sum1 | (sum2 << 16);
}
