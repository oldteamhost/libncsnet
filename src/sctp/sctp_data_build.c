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

#include <ncsnet/sctp.h>

u8 *sctp_data_build(u8 reserved, u32 tsn, u16 s, u16 n, u32 protoload, u8 *data, size_t datalen, size_t *chunklen)
{
  u8 *chunk, *value;
  size_t valuelen;

  value = frmbuild(&valuelen, NULL, "u32(%u), u16(%hu), u16(%hu), u32(%u)",
    htonl(tsn), htons(s), htons(n), htonl(protoload));
  if (data && datalen && value)
    value = frmbuild_addfrm(data, datalen, value, &valuelen, NULL);
  if (!value)
    return NULL;
  chunk = sctp_chunk_build(SCTP_DATA, reserved, value, valuelen, chunklen);

  free(value);
  return chunk;
}
