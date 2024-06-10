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

#include <ncsnet/utils.h>

long long delayconv(const char *txt)
{
  char unit[3] = {0};
  long long res;
  char* endptr;
  size_t len;
  
  if (txt == NULL || *txt == '\0')
    return -1;
  if (strcmp(txt, "0") == 0)
    return 1;
  
  res = strtoll(txt, &endptr, 10);
  if (*endptr == '\0')
    return res;
  
  len = strlen(endptr);
  if (len > 2)
    return -1;
  
  strncpy(unit, endptr, 2);
  if (res == 0)
    return 1;
  
  if (strcmp(unit, "ms") == 0)
    return res * 1000000LL;
  else if (strcmp(unit, "s") == 0)
    return res * 1000000000LL;
  else if (strcmp(unit, "m") == 0)
    return res * 60000000000LL;
  else if (strcmp(unit, "h") == 0)
    return res * 3600000000000LL;
  
  return -1;
}
