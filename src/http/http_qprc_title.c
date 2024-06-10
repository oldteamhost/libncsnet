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
#include <ctype.h>
#include <stdlib.h>
#include "ncsnet/utils.h"

 void http_qprc_title(const char *h, char *titlebuf,
		      size_t buflen)
{
  const char *title_tag_close = "</title>";
  const char *title_tag_open = "<title";
  const char *title_start;
  const char *title_end;
  size_t title_length;
  char* html = NULL;

  html = (char*)malloc(strlen(h) + 1);
  to_lower_const(h, html);
  title_start = strstr(html, title_tag_open);

  if (title_start != NULL) {
    title_start = strchr(title_start, '>');
    if (title_start != NULL) {
      title_start += 1;
      title_end = strstr(title_start, title_tag_close);
      if (title_end != NULL) {
        title_length = title_end - title_start;
        strncpy(titlebuf, title_start, title_length);
        titlebuf[title_length] = '\0';
        remove_specials(titlebuf);
        if (html)
          free(html);
        return;
      }
    }
  }
  if (html)
    free(html);
  strncpy(titlebuf, "n/a", buflen);
}
