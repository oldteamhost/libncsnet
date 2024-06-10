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

#define RECV_MAX_PACKET_LEN_HTTP 655355
bool http_basicauth(int fd, const char *dst, const char *path, const char *user,
		    const char *pass)
{
  u8 packet[RECV_MAX_PACKET_LEN_HTTP];
  struct http_response response;
  struct http_request request;
  int temp = 0;

  http_init_req(&request, "GET", "", "", 0, path, 0, 0);
  http_add_hdr(&request, "Host", dst);
  http_add_hdr(&request, "User-Agent", "oldteam");
  http_add_hdr(&request, "Accept", "*/*");
  http_add_hdr(&request, "Connection", "close");
  http_add_hdr(&request, user, pass);

  temp = http_send_pkt(fd, &request);
  http_free_req(&request);
  if (temp == -1)
    return false;

  temp = http_recv_pkt(fd, &response, packet, RECV_MAX_PACKET_LEN_HTTP);
  if (temp == -1)
    return false;

  if (response.code == 200)
    return true;
  return false;
}
