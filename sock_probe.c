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

#include "ncsnet/socket.h"

ssize_t sock_recv(int fd, void *pkt, size_t pktlen) {
  return (recv(fd, pkt, pktlen, MSG_NOSIGNAL));
}

ssize_t sock_probe(int fd, u8 *pkt, size_t pktlen, const char *fmt, ...)
{
  ssize_t s, r, datalen;
  va_list args;
  char *data;

  data = NULL;
  va_start(args, fmt);
  datalen = vsnprintf(NULL, 0, fmt, args);
  va_end(args);
  if (datalen < 0)
    return -1;
  data = (char*)malloc(datalen+1);
  if (!data)
    return -1;
  va_start(args, fmt);
  vsnprintf(data, datalen + 1, fmt, args);
  va_end(args);

  s = sock_send(fd, data, datalen);
  free(data);
  if (s == -1)
    return -1;
  r = sock_recv(fd, pkt, pktlen - 1);
  if (r == -1)
    return -1;
  else
    pkt[r] = '\0';
  
  return r;
}
