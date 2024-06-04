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

#include "ncsnet/http.h"

char *http_parse_parent_location(const char *buf)
{
  const char* search_str = "parent.location=\"";
  const char* search_str2 = "parent.location='";
  const char* end_str = "\"";
  const char* end_str2 = "\'";
  char* result = NULL;
  const char *start_pos = NULL;
  const char *end_pos = NULL;
  size_t length = 0;

  start_pos = strstr(buf, search_str);
  if (!start_pos)
    start_pos = strstr(buf, search_str2);
  if (start_pos) {
    start_pos += strlen(search_str);
    end_pos = strstr(start_pos, end_str);
    if (!end_pos)
      end_pos = strstr(start_pos, end_str2);
    if (end_pos) {
      length = end_pos - start_pos;
      result = (char*)malloc(length + 1);
      if (result) {
        strncpy(result, start_pos, length);
        result[length] = '\0';
      }
    }
  }

  return result;
}

