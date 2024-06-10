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

#include <ncsnet/tcp.h>

struct tcp_flags tcp_util_str_setflags(const char *flags)
{
  struct tcp_flags res;
  int i;
  
  memset(&res, 0, sizeof(struct tcp_flags));
  for (i = 0; flags[i] != '\0'; ++i) {
    switch (flags[i])
    {
      case 's':
      case 'S':
        res.syn = 1;
        break;
      case 'a':
      case 'A':
        res.ack = 1;
        break;
      case 'r':
      case 'R':
        res.rst = 1;
        break;
      case 'f':
      case 'F':
        res.fin = 1;
        break;
      case 'p':
      case 'P':
        res.psh = 1;
        break;
      case 'u':
      case 'U':
        res.urg = 1;
        break;
      case 'c':
      case 'C':
        res.cwr = 1;
        break;
      case 'e':
      case 'E':
        res.ece = 1;
        break;
    }
  }
  return res;
}
