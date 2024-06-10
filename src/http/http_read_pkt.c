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

struct http_response http_read_pkt(u8 *response)
{
  u8* packet = NULL;
  struct http_response res;
  struct _http_header *hdr = NULL;
  char *statusline = NULL, *headerline = NULL,
       *value = NULL, *colon = NULL;

  res.hdr = NULL;
  res.code = 0;
  res.contentlen = 0;
  res.phrase = NULL;

  packet = http_remove_html(response);
  if (!packet)
    return res;

  statusline = strtok((char *)packet, "\r\n");
  sscanf(statusline, "HTTP/1.1 %d %ms", &res.code, &res.phrase);

  headerline = strtok(NULL, "\r\n");
  while (headerline && headerline[0] != '\0') {
    if (headerline[0] == '\r' || headerline[0] == '\n')
      break;
    colon = strchr(headerline, ':');
    if (colon) {
      *colon = '\0';
      value = colon + 1;
      while (*value == ' ' || *value == '\t')
        value++;
      struct _http_header *newhdr = (struct _http_header *)malloc(sizeof(struct _http_header));
      newhdr->field = strdup(headerline);
      newhdr->value = strdup(value);
      newhdr->nxt = res.hdr;
      res.hdr = newhdr;
    }
    headerline = strtok(NULL, "\r\n");
  }
  res.contentlen = 0;
  hdr = res.hdr;
  while (hdr) {
    if (strcmp(hdr->field, "Content-Length") == 0) {
      sscanf(hdr->value, "%lu", &res.contentlen);
      break;
    }
    hdr = hdr->nxt;
  }

  if (packet)
    free(packet);
  return res;
}
