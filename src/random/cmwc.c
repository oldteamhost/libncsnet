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

#include <ncsnet/cmwc.h>

#include <time.h>
u64 random_seed_u64(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return -1;
  return ((u64)(ts.tv_sec * 1000000000ULL + ts.tv_nsec));
}

static u64 Q[4096], c = 362436;
void cmwc_seed(u64 seed)
{
  int i;
  
  Q[0] = seed;
  Q[1] = seed + PHI;
  Q[2] = seed + PHI + PHI;
  
  for (i = 3; i < 4096; i++)
    Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

u64 cmwc_random(void)
{
  u64 x, r = 0xfffffffe;
  u64 t, a = 18782LL;
  static u64 i = 4095;
  
  i = (i + 1) & 4095;
  t = a * Q[i] + c;
  c = (t >> 32);
  x = t + c;
  
  if (x < c) {
    x++;
    c++;
  }
  
  return (Q[i] = r - x);
}

u64 cmwc_random_num(u64 min, u64 max)
{
  u64 range=0;
  if (min>max)
    return 1;
  range=(max>=min)?(max-min):(sizeof(u64)-min);
  return (min+(cmwc_random()%range+1));
}

size_t __cmwc_random_num_call(size_t min, size_t max)
{
  cmwc_seed(random_seed_u64());
  return cmwc_random_num((u64)min, (u64)max);
}
