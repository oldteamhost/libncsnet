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

#include <ncsnet/raw.h>

ssize_t frmwrite(int fd, char *errbuf, u8 *frame, size_t frmlen)
{
  char tmp[ERRBUF_MAXLEN];
  ssize_t ret;

  if (!errbuf)
    errbuf = tmp;
  
  if (fd == -1) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "File descriptor error \"write_frame\"");
    return -1;
  }
  if (!frame) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Frame error, it is NULL \"write_frame\"");
    return -1;
  }
  if (frmlen <= 0) {
     snprintf(errbuf, ERRBUF_MAXLEN,
       "Frame len error, it is \"%ld\" in \"write_frame\"",
       frmlen);
    return -1;
  }
  
  ret = write(fd, frame, frmlen);
  if (ret < 0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Write error, errno \"%s\" in \"write_frame\"",
      strerror(errno));
  }

  return ret;
}
