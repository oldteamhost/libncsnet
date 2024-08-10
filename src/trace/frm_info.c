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

#include <ncsnet/trace.h>

const char *frm_info(const u8 *frame, size_t frmlen, bool *valid)
{
  static char frminfo[TRACE_PROTO_MAX_LEN]="";
  char hex[TRACE_MAX_DATA_LEN]="";
  size_t i=0;

  for (;i<frmlen;i++)
    sprintf(hex+(i*2), "%02x", frame[i]);
  hex[frmlen*2]='\0';
  if (frmlen>=ETH_HDR_LEN) {
    snprintf(frminfo, sizeof(frminfo), "frame <%ld bytes/%ld bits> [%s]",
      frmlen, frmlen*8, hex);
    if (valid)
      *valid=1;
  }
  else {
    snprintf(frminfo, sizeof(frminfo), "FRAME (incorrect) %ld bytes (%ld bit) [%s]",
      frmlen, frmlen*8, hex);
    if (valid)
      *valid=0;
  }
  
  return frminfo;
}
