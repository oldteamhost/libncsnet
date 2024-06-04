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

#ifndef NCSMD5HDR
#define NCSMD5HDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sys/types.h"
#include "../ncsnet-config.h"

#define UINT_MAX_32_BITS 4294967295U

typedef u32 md5_uint32;
typedef uintptr_t md5_uintptr;

struct md5_ctx
{
  md5_uint32 A;
  md5_uint32 B;
  md5_uint32 C;
  md5_uint32 D;
  md5_uint32 total[2];
  md5_uint32 buflen;
  union {
    char buffer[128];
    md5_uint32 buffer32[32];
  };
};

__BEGIN_DECLS

void *md5(const void *buf, size_t buflen);
char *md5str(const void *buf, size_t buflen);

void md5_init_ctx(struct md5_ctx *ctx);
void md5_process_block(const void *buffer, size_t len, struct md5_ctx *ctx);
void md5_process_bytes(const void *buffer, size_t len, struct md5_ctx *ctx);
void *md5_finish_ctx(struct md5_ctx *ctx, void *resbuf);
void *md5_read_ctx(const struct md5_ctx *ctx, void *resbuf);
void *md5_buffer(const char *buffer, size_t len, void *resblock);

__END_DECLS

#endif
