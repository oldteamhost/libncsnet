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

u8 *sctp_error_build(u8 flags, u8 code, u8 *info, u16 infolen, u16 *chunklen)
{
  struct sctp_chunk_hdr_error *sctp_e;
  u8 *res;
  
  *chunklen = sizeof(struct sctp_chunk_hdr_error) + infolen;
  res = (u8*)malloc(*chunklen);
  if (!res)
    return NULL;
  
  sctp_e = (struct sctp_chunk_hdr_error*)res;
  sctp_e->chunkhdr.flags = flags;
  sctp_e->chunkhdr.type = SCTP_ERROR;
  sctp_e->chunkhdr.len = htons(*chunklen);
  sctp_e->ec.code = code;
  sctp_e->ec.len = htons(sizeof(struct sctp_error_cause_op_hdr) + infolen);

  if (info && infolen)
    memcpy((u8*)sctp_e + sizeof(struct sctp_chunk_hdr_error), info, infolen);
  
  return res;
}
