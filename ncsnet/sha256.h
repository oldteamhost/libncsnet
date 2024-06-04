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

#ifndef NCSSHA256HDR
#define NCSSHA256HDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sys/types.h"
#include "../ncsnet-config.h"

struct sha256_ctx
{
  u32 H[8];
  union
  {
    u64 total64;
    #if defined(LITTLE_ENDIAN_SYSTEM)
      #define TOTAL64_low 1
     #else
      #define TOTAL64_high 1
    #endif
    u32 total[2];
  };
  u32 buflen;
  union
  {
    char buffer[128];
    u32 buffer32[32];
    u64 buffer64[16];
  };
};

__BEGIN_DECLS

void *sha256(const void *buf, size_t buflen);
char *sha256str(const void *buf, size_t buflen);

void sha256_init_ctx(struct sha256_ctx *ctx);
void sha256_process_bytes(const void *buffer, size_t len, struct sha256_ctx *ctx);
void sha256_process_block(const void *buffer, size_t len, struct sha256_ctx *ctx);
void *sha256_finish_ctx(struct sha256_ctx *ctx, void *resbuf);

__END_DECLS

#endif

