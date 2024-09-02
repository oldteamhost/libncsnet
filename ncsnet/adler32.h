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

#ifndef NCSADLERHDR
#define NCSADLERHDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define BASE 65521U
#define NMAX 5552

#define DO1(buf,i)  {adler += (buf)[i]; sum2 += adler;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

#if defined (HAVE_DIVIDE_SUPPORT)
  #define MOD(a) a %= BASE
  #define MOD28(a) a %= BASE
  #define MOD63(a) a %= BASE
#else
#define CHOP(a)					\
  do {						\
    unsigned long tmp = a >> 16;		\
    a &= 0xffffUL;				\
    a += (tmp << 4) - tmp;			\
  } while (0)
#define MOD28(a)				\
  do {						\
    CHOP(a);					\
    if (a >= BASE) a -= BASE;			\
  } while (0)
#define MOD(a)					\
  do {						\
    CHOP(a);					\
    MOD28(a);					\
  } while (0)
#define MOD63(a)				\
  do {						\
    i64 tmp = a >> 32;				\
    a &= 0xffffffffL;				\
    a += (tmp << 8) - (tmp << 5) + tmp;		\
    tmp = a >> 16;				\
    a &= 0xffffL;				\
    a += (tmp << 4) - tmp;			\
    tmp = a >> 16;				\
    a &= 0xffffL;				\
    a += (tmp << 4) - tmp;			\
    if (a >= BASE) a -= BASE;			\
  } while (0)
#endif

__BEGIN_DECLS

u32 adler32(u32 adler, const u8 *buf, size_t len);
u32 adler32combine(u32 adler1, u32 adler2, i64 len2);

__END_DECLS

#endif
