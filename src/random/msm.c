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

#include <ncsnet/msm.h>

static u32 _seed;

#include <time.h>
u32 random_seed_u32_(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return -1;
  return ((u32)(ts.tv_sec * 1000000000ULL + ts.tv_nsec));
}

static u32 num_of_digit(u32 n)
{
  u32 digits=0;
  do {
    n/=10;
    digits++;
  } while (n!=0);
  return digits;
}

static u32 int_pow(u32 base, u32 exp)
{
  u32 result=1;
  while (exp!=0) {
    if (exp%2==1)
      result*=base;
    exp/=2;
    base*=base;
  }
  return result;
}

void msm_seed(u32 seed) { _seed = seed; }

u32 msm(void)
{
  int digits, sqd, start;
  u32 res;
  u64 sq;

  res=_seed;
  digits=num_of_digit(_seed);

  sq=(u64)res*res;
  sqd=num_of_digit(sq);
  start=(sqd/2)-(digits/2);
  if (start<0)
    start=0;
  res=(sq/((u64)int_pow(10, start)))%((u64)int_pow(10, digits));

  return res;
}

u32 msm_random_num(u32 min, u32 max)
{
  u32 range=0;
  if (min>max)
    return 1;
  range=(max>=min)?(max-min):(UINT_MAX-min);
  return (min+(msm()%range+1));
}

size_t __msm_random_num_call(size_t min, size_t max)
{
  msm_seed(random_seed_u32_());
  return msm_random_num((u64)min, (u64)max);
}
