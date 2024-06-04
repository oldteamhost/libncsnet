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

#include <stdnoreturn.h>
#include "../ncsnet/http.h"
#include "../ncsnet/socket.h"

noreturn void usage(char** argv)
{
  printf("Usage: %s [ip] [port] [user-agent]\n", argv[0]);
  exit(0);
}

int main(int argc, char** argv)
{
  struct http_response res;
  u8 response[CMD_BUFFER];
  struct http_request r;
  int fd;

  if (argc < 3 + 1)
    usage(argv);

  http_init_req(&r, "GET", "", "", 0, "/", 0, 0);
  http_add_hdr(&r, "Connection", "close");
  http_add_hdr(&r, "Host", argv[1]);
  http_add_hdr(&r, "User-Agent", argv[3]);

  fd = session(argv[1], atoi(argv[2]), 2000000000, NULL, 0); /* timeout 2s */
  if (fd == -1)
    return -1;

  http_send_pkt(fd, &r);
  http_recv_pkt(fd, &res, response, CMD_BUFFER);
  printf("%s\n", response);

  http_free_req(&r);
  close(fd);
}

