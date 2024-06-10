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

#include <ncsnet/http.h>
#include "ncsnet/socket.h"
#include <unistd.h>

int httpreq_qprc_pkt(const char *dst, u16 dstport, const char *path,
		      long long timeoutns, struct http_response *r, u8 *buf,
		      ssize_t buflen)
{
  struct http_request req;
  u8 temp[4096];
  int fd, a = -1;

  http_init_req(&req, "GET", "", "", 0, path, 0, 0);
  http_add_hdr(&req, "Host", dst);
  http_add_hdr(&req, "User-Agent", "oldteam");
  http_add_hdr(&req, "Connection", "close");

  fd = sock_session(dst, dstport, timeoutns, temp, sizeof(temp));
  if (fd == -1)
    return a;
  a = http_send_pkt(fd, &req);
  http_free_req(&req);
  if (a == -1) {
    close(fd);
    return a;
  }
  a = http_recv_pkt(fd, r, buf, buflen);

  close(fd);
  return a;
}
