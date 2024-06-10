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

u8 *sctp_init_build(u8 type, u8 flags, u32 itag, u32 arwnd, u16 nos, u16 nis, u32 itsn,
		    u16 *chunklen)
{
  struct sctp_chunk_hdr_init *sctp_i;
  u8 *res;
  
  *chunklen = sizeof(struct sctp_chunk_hdr_init);
  res = (u8*)malloc(*chunklen);
  if (!res)
    return NULL;

  sctp_i = (struct sctp_chunk_hdr_init*)res;
  sctp_i->arwnd = htonl(arwnd);
  sctp_i->itag = htonl(itag);
  sctp_i->itsn = htonl(itsn);
  sctp_i->nis = htons(nis);
  sctp_i->nos = htons(nos);
  sctp_i->chunkhdr.flags = flags;
  sctp_i->chunkhdr.type = SCTP_INIT;
  sctp_i->chunkhdr.len = htons(*chunklen);
  sctp_i->chunkhdr.type = type;

  return res;
}
