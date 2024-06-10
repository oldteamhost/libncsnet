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


/* When no other crypto library is available, or the crypto library doesn't
 * support MD4, we use this code segment this implementation of it
 *
 * This is an OpenSSL-compatible implementation of the RSA Data Security, Inc.
 * MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Homepage:
 https://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 *
 * Author:
 * Alexander Peslyak, better known as Solar Designer <solar at openwall.com>
 *
 * This software was written by Alexander Peslyak in 2001.  No copyright is
 * claimed, and the software is hereby placed in the public domain.  In case
 * this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2001
 * Alexander Peslyak and it is hereby released to the general public under the
 * following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 *
 * This differs from Colin Plumb's older public domain implementation in that
 * no exactly 32-bit integer data type is required (any 32-bit or wider
 * unsigned integer data type will do), there's no compile-time endianness
 * configuration, and the function prototypes match OpenSSL's.  No code from
 * Colin Plumb's implementation has been reused; this comment merely compares
 * the properties of the two independent implementations.
 *
 * The primary goals of this implementation are portability and ease of use.
 * It is meant to be fast, but not as fast as possible.  Some known
 * optimizations are not included to reduce source code size and avoid
 * compile-time configuration.
 */

#include <ncsnet/md4.h>

#define MD4_F(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
#define MD4_G(x, y, z)  (((x) & ((y) | (z))) | ((y) & (z)))
#define MD4_H(x, y, z)  ((x) ^ (y) ^ (z))

#define MD4_STEP(f, a, b, c, d, x, s)					\
  (a) += f((b), (c), (d)) + (x);					\
  (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

#if defined(LITTLE_ENDIAN_SYSTEM)
#define MD4_SET(n) (*(u32*)(void *)&ptr[(n) * 4])
#define MD4_GET(n) MD4_SET(n)
#else
#define MD4_SET(n)			\
  (ctx->block[(n)] =			\
   (u32)ptr[(n) * 4] |			\
   ((u32)ptr[(n) * 4 + 1] << 8) |	\
   ((u32)ptr[(n) * 4 + 2] << 16) |	\
   ((u32)ptr[(n) * 4 + 3] << 24))
#define MD4_GET(n) (ctx->block[(n)])
#endif

static void *md4_body(struct md4_ctx *ctx, const void *data, size_t datalen)
{
  u32 saved_a, saved_b, saved_c, saved_d;
  const u8 *ptr;
  u32 a, b, c, d;
  ptr = (const u8 *)data;

  a = ctx->a;
  b = ctx->b;
  c = ctx->c;
  d = ctx->d;

  do {

    saved_a = a;
    saved_b = b;
    saved_c = c;
    saved_d = d;

    MD4_STEP(MD4_F, a, b, c, d, MD4_SET(0), 3)
    MD4_STEP(MD4_F, d, a, b, c, MD4_SET(1), 7)
    MD4_STEP(MD4_F, c, d, a, b, MD4_SET(2), 11)
    MD4_STEP(MD4_F, b, c, d, a, MD4_SET(3), 19)
    MD4_STEP(MD4_F, a, b, c, d, MD4_SET(4), 3)
    MD4_STEP(MD4_F, d, a, b, c, MD4_SET(5), 7)
    MD4_STEP(MD4_F, c, d, a, b, MD4_SET(6), 11)
    MD4_STEP(MD4_F, b, c, d, a, MD4_SET(7), 19)
    MD4_STEP(MD4_F, a, b, c, d, MD4_SET(8), 3)
    MD4_STEP(MD4_F, d, a, b, c, MD4_SET(9), 7)
    MD4_STEP(MD4_F, c, d, a, b, MD4_SET(10), 11)
    MD4_STEP(MD4_F, b, c, d, a, MD4_SET(11), 19)
    MD4_STEP(MD4_F, a, b, c, d, MD4_SET(12), 3)
    MD4_STEP(MD4_F, d, a, b, c, MD4_SET(13), 7)
    MD4_STEP(MD4_F, c, d, a, b, MD4_SET(14), 11)
    MD4_STEP(MD4_F, b, c, d, a, MD4_SET(15), 19)

    MD4_STEP(MD4_G, a, b, c, d, MD4_GET(0) + 0x5a827999, 3)
    MD4_STEP(MD4_G, d, a, b, c, MD4_GET(4) + 0x5a827999, 5)
    MD4_STEP(MD4_G, c, d, a, b, MD4_GET(8) + 0x5a827999, 9)
    MD4_STEP(MD4_G, b, c, d, a, MD4_GET(12) + 0x5a827999, 13)
    MD4_STEP(MD4_G, a, b, c, d, MD4_GET(1) + 0x5a827999, 3)
    MD4_STEP(MD4_G, d, a, b, c, MD4_GET(5) + 0x5a827999, 5)
    MD4_STEP(MD4_G, c, d, a, b, MD4_GET(9) + 0x5a827999, 9)
    MD4_STEP(MD4_G, b, c, d, a, MD4_GET(13) + 0x5a827999, 13)
    MD4_STEP(MD4_G, a, b, c, d, MD4_GET(2) + 0x5a827999, 3)
    MD4_STEP(MD4_G, d, a, b, c, MD4_GET(6) + 0x5a827999, 5)
    MD4_STEP(MD4_G, c, d, a, b, MD4_GET(10) + 0x5a827999, 9)
    MD4_STEP(MD4_G, b, c, d, a, MD4_GET(14) + 0x5a827999, 13)
    MD4_STEP(MD4_G, a, b, c, d, MD4_GET(3) + 0x5a827999, 3)
    MD4_STEP(MD4_G, d, a, b, c, MD4_GET(7) + 0x5a827999, 5)
    MD4_STEP(MD4_G, c, d, a, b, MD4_GET(11) + 0x5a827999, 9)
    MD4_STEP(MD4_G, b, c, d, a, MD4_GET(15) + 0x5a827999, 13)

    MD4_STEP(MD4_H, a, b, c, d, MD4_GET(0) + 0x6ed9eba1, 3)
    MD4_STEP(MD4_H, d, a, b, c, MD4_GET(8) + 0x6ed9eba1, 9)
    MD4_STEP(MD4_H, c, d, a, b, MD4_GET(4) + 0x6ed9eba1, 11)
    MD4_STEP(MD4_H, b, c, d, a, MD4_GET(12) + 0x6ed9eba1, 15)
    MD4_STEP(MD4_H, a, b, c, d, MD4_GET(2) + 0x6ed9eba1, 3)
    MD4_STEP(MD4_H, d, a, b, c, MD4_GET(10) + 0x6ed9eba1, 9)
    MD4_STEP(MD4_H, c, d, a, b, MD4_GET(6) + 0x6ed9eba1, 11)
    MD4_STEP(MD4_H, b, c, d, a, MD4_GET(14) + 0x6ed9eba1, 15)
    MD4_STEP(MD4_H, a, b, c, d, MD4_GET(1) + 0x6ed9eba1, 3)
    MD4_STEP(MD4_H, d, a, b, c, MD4_GET(9) + 0x6ed9eba1, 9)
    MD4_STEP(MD4_H, c, d, a, b, MD4_GET(5) + 0x6ed9eba1, 11)
    MD4_STEP(MD4_H, b, c, d, a, MD4_GET(13) + 0x6ed9eba1, 15)
    MD4_STEP(MD4_H, a, b, c, d, MD4_GET(3) + 0x6ed9eba1, 3)
    MD4_STEP(MD4_H, d, a, b, c, MD4_GET(11) + 0x6ed9eba1, 9)
    MD4_STEP(MD4_H, c, d, a, b, MD4_GET(7) + 0x6ed9eba1, 11)
    MD4_STEP(MD4_H, b, c, d, a, MD4_GET(15) + 0x6ed9eba1, 15)

    a += saved_a;
    b += saved_b;
    c += saved_c;
    d += saved_d;

    ptr += 64;
  } while(datalen -= 64);

  ctx->a = a;
  ctx->b = b;
  ctx->c = c;
  ctx->d = d;

  return (void*)ptr;
}

void md4_init_ctx(struct md4_ctx *ctx)
{
  ctx->a = 0x67452301;
  ctx->b = 0xefcdab89;
  ctx->c = 0x98badcfe;
  ctx->d = 0x10325476;
  ctx->lo = ctx->hi = 0;
}

void md4_update(struct md4_ctx *ctx, const void *data, size_t datalen)
{
  u32 saved_lo;
  size_t used, available;

  saved_lo = ctx->lo;
  if ((ctx->lo = (saved_lo + datalen) & 0x1fffffff) < saved_lo)
    ctx->hi++;
  ctx->hi += (u32)(datalen >> 29);
  
  used = saved_lo & 0x3f;
  
  if (used) {
    available = 64 - used;
    
    if (datalen < available) {
      memcpy(&ctx->buffer[used], data, datalen);
      return;
    }
    
    memcpy(&ctx->buffer[used], data, available);
    data = (const u8*)data + available;
    datalen -= available;
    md4_body(ctx, ctx->buffer, 64);
  }
  
  if (datalen >= 64) {
    data = md4_body(ctx, data, datalen & ~(size_t)0x3f);
    datalen &= 0x3f;
  }
  
  memcpy(ctx->buffer, data, datalen);
}

#define OUT(dst, src)		 \
  (dst)[0] = (u8)(src);		 \
  (dst)[1] = (u8)((src) >> 8);	 \
  (dst)[2] = (u8)((src) >> 16);	 \
  (dst)[3] = (u8)((src) >> 24);

void md4_final(struct md4_ctx *ctx, u8 *resbuf)
{
  size_t used, available;

  used = ctx->lo & 0x3f;
  ctx->buffer[used++] = 0x80;
  available = 64 - used;
  
  if (available < 8) {
    memset(&ctx->buffer[used], 0, available);
    md4_body(ctx, ctx->buffer, 64);
    used = 0;
    available = 64;
  }
  
  memset(&ctx->buffer[used], 0, available - 8);
  
  ctx->lo <<= 3;
  OUT(&ctx->buffer[56], ctx->lo)
  OUT(&ctx->buffer[60], ctx->hi)
    
  md4_body(ctx, ctx->buffer, 64);
  
  OUT(&resbuf[0], ctx->a)
  OUT(&resbuf[4], ctx->b)
  OUT(&resbuf[8], ctx->c)
  OUT(&resbuf[12], ctx->d)
}

#undef OUT

void *md4(const void *buf, size_t buflen)
{
  struct md4_ctx ctx;
  u8 *digest;

  digest = NULL;

  digest = malloc(16);
  if (!digest)
    return NULL;

  md4_init_ctx(&ctx);
  md4_update(&ctx, buf, buflen);
  md4_final(&ctx, digest);
  
  return digest;
}

char *md4str(const void *buf, size_t buflen)
{
  char *hexstr;
  u8 *digest;
  int i;
  
  digest = md4(buf, buflen);
  if (!digest)
    return NULL;
  hexstr = malloc(33);
  if (!hexstr) {
    free(digest);
    return NULL;
  }
  for (i = 0; i < 16; i++)
    sprintf(hexstr + i * 2, "%02x", digest[i]);
  hexstr[32] = '\0';
  free(digest);
  
  return hexstr;
}

