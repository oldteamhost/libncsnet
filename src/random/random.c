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

#include <ncsnet/random.h>

static random_t r=__mt19937_random_num_call;
void randutils_open(random_t rand) { r=rand; }

u32 random_num_u32(u32 min, u32 max)
{
  if (min>UINT_MAX)
    min=UINT_MAX;
  if (max>UINT_MAX)
    max=UINT_MAX;
  return (u32)r(min, max);
}

u32 random_u32(void) { return (u32)random_num_u32(0, UINT_MAX); }
u16 random_u16(void) { return (u16)random_num_u32(0, USHRT_MAX); }
u8 random_u8(void) { return (u8)random_num_u32(0, UCHAR_MAX); }
u16 random_check(void) { return random_u16(); }
u16 random_srcport(void) { return((u16)random_num_u32(49151, USHRT_MAX)); }

char *random_str(size_t len, const char *dictionary)
{
  size_t dict_len, i;
  char *result=NULL;
  result=(char*)malloc(len+1);
  if (!result)
    return NULL;
  dict_len =strlen(dictionary);
  for (i=0;i<len;i++)
    result[i]=dictionary[random_u32()%dict_len];
  result[len]='\0';
  return result;
}

ip4_t random_ip4t(void)
{
  ip4_t res;
  ip4t_fill(&res, random_u8(), random_u8(), random_u8(), random_u8());
  return res;
}

const char *random_ip4(void)
{
  ip4_t tmp;
  tmp=random_ip4t();
  return (ip4t_ntop_c(&tmp));
}
