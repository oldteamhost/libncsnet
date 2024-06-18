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

#include <ncsnet/html.h>

static void ____addbuf(char *buf, size_t buflen, const char *txt)
{
  size_t curlen = 0, txtlen = 0, tmp = 0;

  curlen = strlen(buf);
  txtlen = strlen(txt);
  
  tmp = buflen - curlen;
  if (txtlen > tmp)
    txtlen = tmp;
  
  strncpy(buf + curlen, txt, txtlen);
  buf[curlen + txtlen] = '\0';
}

bool ___html_add(char *buf, size_t buflen, const char *fmt, va_list args)
{
  size_t maxchars;
  maxchars = buflen - strlen(buf);
  char tmpbuf[maxchars];
  if (!buf || !fmt)
    return 0;
  vsnprintf(tmpbuf, maxchars, fmt, args);
  ____addbuf(buf, buflen, tmpbuf);
  return 1;
}

bool html_add(char *buf, size_t buflen, const char *fmt, ...)
{
  va_list args;
  bool res;
  
  va_start(args, fmt);
  res = ___html_add(buf, buflen, fmt, args);
  va_end(args);
  
  return res;
}

static bool ____add(int fd, char *buf, size_t buflen, const char *txt)
{
  ____addbuf(buf, buflen, txt);
  return 1;
}

int descriptor_general(char *buf, size_t buflen, int fd, const char *openq,
		       const char *closeq, bool close, const char *key,
		       const char *fmt, va_list args)
{
  size_t len, maxlen;
  char *str;

  maxlen = buflen - (strlen(openq) + (close ? 1 : 0) + strlen(key) + strlen(closeq) + 1);
  if (!____add(fd, buf, buflen, openq))
    return -1;
  if (close)
    if (!____add(fd, buf, buflen, "/"))
      return -1;
  if (!____add(fd, buf, buflen, key))
    return -1;
  if (fmt && *fmt != '\0') {
    if (!____add(fd, buf, buflen, " "))
      return -1;
    str = (char*)calloc(1, maxlen * sizeof(char));
    if (!str)
      return -1;
    len = vsnprintf(str, maxlen, fmt, args);
    if (len < 0 || (size_t)len >= maxlen) {
      free(str);
      return -1;
    }
    if (!____add(fd, buf, buflen, str)) {
      free(str);
      return -1;
    }
    free(str);
  }
  if (!____add(fd, buf, buflen, closeq))
    return -1;
  
  return 0;
}
