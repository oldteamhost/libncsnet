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

#include <ncsnet/base64.h>

static const char base64[64 + 1] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64encode(const void *raw, size_t rawlen, char *data, size_t len)
{
  const u8 *rawbytes = ((const u8*)raw);
  u32 bit, byte, shift, tmp;
  size_t used;

  used = 0;
  bit = 0;
  
  for (; bit < (8 * rawlen); bit += 6, used++) {
    byte = (bit / 8);
    shift = (bit % 8);
    tmp = (rawbytes[byte] << shift);
    if ((byte + 1) < rawlen)
      tmp |= (rawbytes[byte + 1] >> (8 - shift));
    tmp = ((tmp >> 2) & 0x3f);
    if (used < len)
      data[used] = base64[tmp];
  }
  for (; (bit % 8) != 0 ; bit += 6, used++) {
    if (used < len)
      data[used] = '=';
  }
  if (used < len)
    data[used] = '\0';
  if (len)
    data[len - 1] = '\0';
  
  return used;
}

int base64decode(const char *encoded, void *data, size_t len)
{
  const char *in = encoded;
  u32 bit, pad_count;
  u8 in_char, *out;
  size_t offset;
  char *match;
  int in_bits;

  out = data;
  bit = pad_count = 0;
  
  memset(data, 0, len);
  while ((in_char = *(in++))) {
    if (isspace(in_char))
      continue;
    if (in_char == '=') {
      if (pad_count >= 2)
	return -1;
      pad_count++;
      bit -= 2;
      continue;
    }
    if (pad_count)
      return -1;
    match = strchr (base64, in_char);
    if (!match)
      return -1;
    in_bits = (match - base64);
    in_bits <<= 2;
    offset = (bit / 8);
    if (offset < len)
      out[offset] |= (in_bits >> (bit % 8));
    offset++;
    if (offset < len)
      out[offset] |= (in_bits << (8 - (bit % 8)));
    bit += 6;
  }
  if ((bit % 8) != 0)
    return -1;
  
  return (bit / 8);
}

size_t base64decoded_maxlen(const char *encoded) {
  return (((strlen(encoded) + 4 - 1) / 4) * 3);
}

size_t base64encoded_len(size_t rawlen) {
  return (((rawlen + 3 - 1) / 3) * 4);
}
