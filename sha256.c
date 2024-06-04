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

#include "ncsnet/sha256.h"

#if defined(LITTLE_ENDIAN_SYSTEM)
  #if defined(IS_LINUX)
    #include <byteswap.h>
    #define SWAP(n) __bswap_32(n)
    #define SWAP64(n) __bswap_64(n)
  #elif defined(IS_BSD)
    #include <sys/endian.h>
    #define SWAP(n) bswap32(n)
    #define SWAP64(n) bswap64(n)
  #endif
#else
  #define SWAP(n) (n)
  #define SWAP64(n) (n)
#endif

static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */ };

static const u32 K[64] =
{
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* encrypt buf to md5 (void) */
void *sha256(const void *buf, size_t buflen)
{
  struct sha256_ctx ctx;
  void *ebuf = NULL;

  sha256_init_ctx(&ctx);

  sha256_process_bytes(buf, buflen, &ctx);
  ebuf = malloc(32);
  if (!ebuf)
    return NULL;

  sha256_finish_ctx(&ctx, ebuf);
  return ebuf;
}

/* encrypt buf to md5 string (char) */
char *sha256str(const void *buf, size_t buflen)
{
  char *hexstr = NULL;
  void *ebuf = NULL;
  int i = 0;
  
  ebuf = sha256(buf, buflen);
  if (!ebuf)
    return NULL;
  hexstr = malloc(65);
  if (!hexstr) {
    free(ebuf);
    return NULL;
  }
  for (; i < 32; i++)
    sprintf(hexstr + (i * 2), "%02x", ((u8*)ebuf)[i]);
  hexstr[64] = '\0';

  free(ebuf);
  return hexstr;
}

void sha256_process_block(const void *buffer, size_t len, struct sha256_ctx *ctx)
{
  const u32 *words = buffer;
  size_t nwords = len / sizeof (u32);
  u32 a = ctx->H[0];
  u32 b = ctx->H[1];
  u32 c = ctx->H[2];
  u32 d = ctx->H[3];
  u32 e = ctx->H[4];
  u32 f = ctx->H[5];
  u32 g = ctx->H[6];
  u32 h = ctx->H[7];

  ctx->total64 += len;
  while (nwords > 0) {
    u32 W[64];
    u32 a_save = a;
    u32 b_save = b;
    u32 c_save = c;
    u32 d_save = d;
    u32 e_save = e;
    u32 f_save = f;
    u32 g_save = g;
    u32 h_save = h;
    u32 t, T1 = 0, T2 = 0;

    #define Ch(x, y, z) ((x & y) ^ (~x & z))
    #define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
    #define S0(x) (CYCLIC (x, 2) ^ CYCLIC (x, 13) ^ CYCLIC (x, 22))
    #define S1(x) (CYCLIC (x, 6) ^ CYCLIC (x, 11) ^ CYCLIC (x, 25))
    #define R0(x) (CYCLIC (x, 7) ^ CYCLIC (x, 18) ^ (x >> 3))
    #define R1(x) (CYCLIC (x, 17) ^ CYCLIC (x, 19) ^ (x >> 10))

    #define CYCLIC(w, s) ((w >> s) | (w << (32 - s)))

    for (t = 0; t < 16; ++t) {
      W[t] = SWAP(*words);
      ++words;
    }
    for (t = 16; t < 64; ++t)
      W[t] = R1 (W[t - 2]) + W[t - 7] + R0 (W[t - 15]) + W[t - 16];

    for (t = 0; t < 64; ++t) {
      T1 = h + S1 (e) + Ch (e, f, g) + K[t] + W[t];
      T2 = S0 (a) + Maj (a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }

    a += a_save;
    b += b_save;
    c += c_save;
    d += d_save;
    e += e_save;
    f += f_save;
    g += g_save;
    h += h_save;

    nwords -= 16;
  }

  ctx->H[0] = a;
  ctx->H[1] = b;
  ctx->H[2] = c;
  ctx->H[3] = d;
  ctx->H[4] = e;
  ctx->H[5] = f;
  ctx->H[6] = g;
  ctx->H[7] = h;
}

void *sha256_finish_ctx(struct sha256_ctx *ctx, void *resbuf)
{
  u32 bytes = ctx->buflen, i;
  size_t pad;
  ctx->total64 += bytes;

  pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
  memcpy (&ctx->buffer[bytes], fillbuf, pad);
  ctx->buffer64[(bytes + pad) / 8] = SWAP64 (ctx->total64 << 3);

  sha256_process_block (ctx->buffer, bytes + pad + 8, ctx);

  for (i = 0; i < 8; ++i)
    ((u32 *) resbuf)[i] = SWAP (ctx->H[i]);

  return resbuf;
}

void sha256_init_ctx(struct sha256_ctx *ctx)
{
  ctx->H[0] = 0x6a09e667;
  ctx->H[1] = 0xbb67ae85;
  ctx->H[2] = 0x3c6ef372;
  ctx->H[3] = 0xa54ff53a;
  ctx->H[4] = 0x510e527f;
  ctx->H[5] = 0x9b05688c;
  ctx->H[6] = 0x1f83d9ab;
  ctx->H[7] = 0x5be0cd19;

  ctx->total64 = 0;
  ctx->buflen = 0;
}

void sha256_process_bytes(const void *buffer, size_t len, struct sha256_ctx *ctx)
{
  if (ctx->buflen != 0) {
    size_t left_over = ctx->buflen;
    size_t add = 128 - left_over > len ? len : 128 - left_over;

    memcpy (&ctx->buffer[left_over], buffer, add);
    ctx->buflen += add;

    if (ctx->buflen > 64) {
      sha256_process_block (ctx->buffer, ctx->buflen & ~63, ctx);

      ctx->buflen &= 63;
      memcpy (ctx->buffer, &ctx->buffer[(left_over + add) & ~63], ctx->buflen);
    }

      buffer = (const char *) buffer + add;
      len -= add;
    }

  if (len >= 64) {
    #define UNALIGNED_P(p) (((uintptr_t) p) % sizeof (u32) != 0)
    if (UNALIGNED_P(buffer)) while (len > 64) {
      sha256_process_block (memcpy (ctx->buffer, buffer, 64), 64, ctx);
      buffer = (const char *) buffer + 64;
      len -= 64;
    }
    else {
      sha256_process_block (buffer, len & ~63, ctx);
      buffer = (const char *) buffer + (len & ~63);
      len &= 63;
    }
  }
  if (len > 0) {
    size_t left_over = ctx->buflen;
    memcpy (&ctx->buffer[left_over], buffer, len);
    left_over += len;
    if (left_over >= 64) {
      sha256_process_block (ctx->buffer, 64, ctx);
      left_over -= 64;
      memcpy (ctx->buffer, &ctx->buffer[64], left_over);
    }
    ctx->buflen = left_over;
  }
}
