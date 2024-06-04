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

#include "ncsnet/utils.h"

u32 random_seed_u32(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return -1;
  return ((u32)(ts.tv_sec * 1000000000ULL + ts.tv_nsec));
}

u32 random_num_u32(u32 min, u32 max)
{
  u32 range;
  if (min > max)
    return 1;

  range = (max >= min) ? (max - min) : (UINT_MAX - min);
  mt19937_seed(random_seed_u32());
  return (min + (mt19937_random() % range + 1));
}

const char *random_ip4(void)
{
  static char ip[16];
  mt19937_seed(random_seed_u32());

  snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
      mt19937_random() % 256, mt19937_random() % 256,
      mt19937_random() % 256, mt19937_random() % 256);

  return ip;
}

char *random_str(int len, const char* dictionary)
{
  int dict_len, i;
  char *result;

  mt19937_seed(random_seed_u32());
  result = (char*)malloc(len + 1);
  if (!result)
    return NULL;

  dict_len = strlen(dictionary);
  for (i = 0; i < len; i++)
    result[i] = dictionary[mt19937_random() % dict_len];

  result[len] = '\0';
  return result;
}

u32 random_u32(void) { return random_num_u32(1, UINT_MAX); }
u16 random_u16(void) { return (u16)random_num_u32(1, USHRT_MAX); }
u8  random_u8(void) { return (u8)random_num_u32(1, UCHAR_MAX); }
u16 random_check(void) { return ((u16)random_num_u32(1, 0xFFFF - 1)); }
u16 random_srcport(void) { return((u16)random_num_u32(49151, USHRT_MAX)); }
