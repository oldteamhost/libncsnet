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

#ifndef NCSSHA512HDR
#define NCSSHA512HDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sys/types.h"
#include "../ncsnet-config.h"

struct sha512_ctx
{
  u64 H[8];
  union
  {
    #if WORD_SIZE == 64
      #define USE_TOTAL128
      u32 total128 __attribute__ ((__mode__ (TI)));
    #endif
    #if defined(LITTLE_ENDIAN_SYSTEM)
      #define TOTAL128_low 1
      #define TOTAL128_high 0
    #else
      #define TOTAL128_low 0
       #define TOTAL128_high 1
    #endif
    u64 total[2];
  };
  u64 buflen;
  union
  {
    char buffer[256];
    u64 buffer64[32];
  };
};

__BEGIN_DECLS

void *sha512(const void *buf, size_t buflen);
char *sha512str(const void *buf, size_t buflen);

void sha512_init_ctx(struct sha512_ctx *ctx);
void sha512_process_bytes(const void *buffer, size_t len, struct sha512_ctx *ctx);
void sha512_process_block(const void *buffer, size_t len, struct sha512_ctx *ctx);
void *sha512_finish_ctx(struct sha512_ctx *ctx, void *resbuf);

__END_DECLS

#endif

