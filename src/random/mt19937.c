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

#include <ncsnet/mt19937.h>

static u32 mt[MT19937_N];
static int mti = MT19937_N + 1;

void mt19937_seed(u32 seed)
{
  mt[0] = seed;
  for (mti = 1; mti < MT19937_N; mti++) {
    mt[mti] = 1812433253 * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) + mti;
  }
  return;
}

u32 mt19937_random(void)
{
  int i;
  if (mti >= MT19937_N) {
    for (i = 0; i < MT19937_N - MT19937_M; i++) {
      u32 y = (mt[i] & MT19937_UPPER_MASK) | (mt[i + 1] & MT19937_LOWER_MASK);
      mt[i] = mt[i + MT19937_M] ^ (y >> 1) ^ ((y & 1) * 0x9908B0DF);
    }
    for (; i < MT19937_N - 1; i++) {
      u32 y = (mt[i] & MT19937_UPPER_MASK) | (mt[i + 1] & MT19937_LOWER_MASK);
      mt[i] = mt[i + MT19937_M - MT19937_N] ^ (y >> 1) ^ ((y & 1) * 0x9908B0DF);
    }
    u32 y = (mt[MT19937_N - 1] & MT19937_UPPER_MASK) | (mt[0] & MT19937_LOWER_MASK);
    mt[MT19937_N - 1] = mt[MT19937_M - 1] ^ (y >> 1) ^ ((y & 1) * 0x9908B0DF);
    mti = 0;
  }

  u32 y = mt[mti++];
  y ^= (y >> 11);
  y ^= ((y << 7) & 0x9D2C5680);
  y ^= ((y << 15) & 0xEFC60000);
  y ^= (y >> 18);

  return y;
}
