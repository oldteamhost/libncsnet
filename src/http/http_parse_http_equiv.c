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
#include "ncsnet/utils.h"

char *http_parse_http_equiv(const char *buf)
{
  char* url_prefixes[] = {"0;url=", "1;url=", "2;url=", "0.0;url=", "12;url="};
  char* htmll = strdup(buf);
  char* meta_str = "<meta";
  char* http_equiv_str = "http-equiv=\"refresh\"";
  char* content_str = "content=\"";
  char* end_str = "\"";
  char* url = NULL;
  char* meta_it = NULL;
  char* http_equiv_it = NULL;
  char* content_it = NULL;
  char* end_it = NULL;
  int len = 0;
  char* src = NULL;
  char* dest= NULL;

  for (int i = 0; htmll[i]; i++)
    htmll[i] = tolower(htmll[i]);
  meta_it = strstr(htmll, meta_str);
  if (meta_it) {
    http_equiv_it = strstr(meta_it, http_equiv_str);
    if (http_equiv_it) {
      content_it = strstr(http_equiv_it, content_str);
      if (content_it) {
        content_it += strlen(content_str);
        end_it = strstr(content_it, end_str);
        if (end_it) {
          len = end_it - content_it;
          url = (char*)malloc(len + 1);
          if (url) {
            strncpy(url, content_it, len);
            url[len] = '\0';
            src = url;
            dest = url;
            while (*src) {
              if (!isspace((unsigned char)*src)) {
                *dest = *src;
                dest++;
              }
              src++;
            }
            *dest = '\0';
            for (int i = 0; i < sizeof(url_prefixes) / sizeof(url_prefixes[0]); i++) {
              if (strncmp(url, url_prefixes[i], strlen(url_prefixes[i])) == 0) {
                memmove(url, url + strlen(url_prefixes[i]), strlen(url) - strlen(url_prefixes[i]) + 1);
              }
            }
          }
        }
      }
    }
  }

  free(htmll);
  return url;
}
