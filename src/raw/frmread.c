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

ssize_t frmread(int fd, char *errbuf, u8 *buf, size_t buflen)
{
  char tmp[ERRBUF_MAXLEN];
  ssize_t ret;

  if (!errbuf)
    errbuf = tmp;
  
  if (fd == -1) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "File descriptor error \"read_frame\"");
    return -1;
  }
  if (!buf) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Buffer error, it is NULL \"read_frame\"");
    return -1;
  }
  if (buflen <= 0) {
     snprintf(errbuf, ERRBUF_MAXLEN,
       "Buffer len error, it is \"%ld\" in \"read_frame\"",
       buflen);
    return -1;
  }
  
  ret = read(fd, buf, buflen);
  if (ret < 0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Read error, errno \"%s\" in \"read_frame\"",
      strerror(errno));
  }

  return ret;
}
