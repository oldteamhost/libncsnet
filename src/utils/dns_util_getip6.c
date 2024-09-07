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

#include <ncsnet/dns.h>

void dns_util_getip6(const char* dst, int srcport, char* dnsbuf, size_t buflen)
{
  struct in6_addr addr;
  int sock, res;
  char host[NI_MAXHOST];
  struct timeval timeout;
  struct sockaddr_in6 sa;

  memset(&sa, 0, sizeof(sa));
  sa.sin6_family = AF_INET6;

  timeout.tv_sec = 600;
  timeout.tv_usec = 0;

  if (inet_pton(AF_INET6, dst, &addr) != 1)
    goto fail;

  sa.sin6_addr = addr;
  sa.sin6_port = htons(srcport);

  sock = socket(AF_INET6, SOCK_STREAM, 0);
  if (sock == -1)
    goto fail;

  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD);
  close(sock);
  if (res == -1)
    goto fail;
  if (strlen(host) >= buflen)
    goto fail;

  strncpy(dnsbuf, host, buflen);
  dnsbuf[buflen - 1] = '\0';

  return;
fail:
  strncpy(dnsbuf, "n/a", buflen);
  return;
}
