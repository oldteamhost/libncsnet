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
#include "ncsnet/utils.h"

int session_run(const char* dest_ip, int port, long long timeoutns, int verbose)
{
  struct sockaddr_in server_addr;
  char response_buffer[CMD_BUFFER];
  int sockfd = -1, r;

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (ncs_inet_pton(AF_INET, dest_ip, &server_addr.sin_addr) <= 0)
    goto fail;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
    return -1;

  if (!(socket_util_timeoutns(sockfd, timeoutns, true, true)))
    goto fail;
  if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
    goto fail;

  r = recv(sockfd, response_buffer, CMD_BUFFER - 1, 0);
  if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
    goto fail;

  if (verbose) {
    response_buffer[r] = '\0';
    printf("VERBOSE  %s", response_buffer);
  }

  return sockfd;
  
fail:
  close(sockfd);
  return -1;
}

int session(const char* dst, u16 port, long long timeoutns, u8* packet, size_t len)
{
  struct sockaddr_in server_addr;
  int sockfd, r;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
    return -1;

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  ncs_inet_pton(AF_INET, dst, &server_addr.sin_addr);

  if (!(socket_util_timeoutns(sockfd, timeoutns, true, true)))
    goto fail;
  if (connect(sockfd,(struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
    goto fail;

  if (packet) {
    r = recv(sockfd, packet, len - 1, 0);
    if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
      goto fail;
    packet[r] = '\0';
  }
  
  return sockfd;

fail:
  close(sockfd);
  return -1;
}

ssize_t session_packet(int fd, u8* packet, ssize_t len, const char* message)
{
  ssize_t s, r;

  s = send(fd, message, strlen(message), MSG_NOSIGNAL);
  if (s == -1)
    return -1;
  r = recv(fd, packet, len - 1, MSG_NOSIGNAL);
  if (r == -1)
    return -1;
  else
    packet[r] = '\0';
  
  return r;
}

u8 *sendproto_command(int fd, const char* command)
{
  char sendbuf[CMD_BUFFER];
  u8 *packet;

  snprintf(sendbuf, CMD_BUFFER, "%s", command);
  packet = (u8*)malloc(CMD_BUFFER);
  if (!packet)
    return NULL;

  return packet;
}

bool socket_util_timeoutns(int fd, long long timeoutns, bool send, bool recv)
{
  struct timeval tv;
  tv = timevalns(timeoutns);
  
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 && recv)
    return false;
  if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0 && send)
    return false;

  return true;
}
