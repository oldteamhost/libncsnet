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

#include "ncsnet/ip.h"
#include <ncsnet/utils.h>

int getipv4(const char *node, char *res, u8 reslen)
{
  const char *tres;
  char tbuf[16];
  char *turl;
  int is;
  
  is = this_is(node);

  if (is == IPv4) {
    tres = node;
    goto write;
  }
  else if (is == DNS) {
    if (ip4_util_strdst(node, tbuf, 16) != -1) {
      tres = tbuf;
      goto write;
    }
    goto fail;
  }
  else if (is == _URL_) {
    turl = clean_url(node);
    if (!turl)
      goto fail;
    if (ip4_util_strdst(turl, tbuf, 16) != -1) {
      tres = tbuf;
      goto write;
    }
    free(turl);
  }
  
 fail:
  return -1;
  
 write:
  strncpy(res, tres, reslen - 1);
  res[reslen - 1] = '\0';
  return 0;
}

