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

u8 *http_build_pkt(struct http_request *request, const char *data,
		     ssize_t datalen, ssize_t *pktlen)
{
  struct _http_header *curhdr = NULL;
  ssize_t offset = 0;
  u8 *packet = NULL;

  packet = (u8 *)malloc(MAX_PACKET_SIZE);
  if (!packet)
    return NULL;
  if (request->uri.scheme && request->uri.scheme[0] != '\0')
    offset = snprintf((char *)packet, MAX_PACKET_SIZE,
      "%s %s://", request->method, request->uri.scheme);
  else
    offset = snprintf((char *)packet, MAX_PACKET_SIZE,
      "%s ", request->method);
  if (request->uri.host && request->uri.host[0] != '\0')
    offset += snprintf((char *)packet + offset, MAX_PACKET_SIZE - offset,
      "%s", request->uri.host);
  if (request->uri.port != 0 &&
    !(request->uri.scheme != NULL && strcmp(request->uri.scheme, "http") == 0 && request->uri.port == 80) &&
    !(request->uri.scheme != NULL && strcmp(request->uri.scheme, "https") == 0 && request->uri.port == 443)) {
    offset += snprintf((char *)packet + offset, MAX_PACKET_SIZE - offset, ":%d", request->uri.port);
  }
  if (request->uri.path)
    offset += snprintf((char *)packet + offset, MAX_PACKET_SIZE - offset,
      "%s HTTP/1.1\r\n", request->uri.path);
  else
    offset += snprintf((char *)packet + offset, MAX_PACKET_SIZE - offset,
      " HTTP/1.1\r\n");
  curhdr = request->hdr;
  while (curhdr) {
    offset += snprintf((char *)packet + offset, MAX_PACKET_SIZE - offset,
      "%s: %s\r\n", curhdr->field, curhdr->value);
    curhdr = curhdr->nxt;
  }
  if (datalen)
    offset += snprintf((char *)packet + offset, MAX_PACKET_SIZE - offset, "Content-Length: %zd\r\n", datalen);
  offset += snprintf((char *)packet + offset, MAX_PACKET_SIZE - offset, "\r\n");
  if (data && datalen) {
    memcpy(packet + offset, data, datalen);
    offset += datalen;
  }

  *pktlen = offset;
  return packet;
}
