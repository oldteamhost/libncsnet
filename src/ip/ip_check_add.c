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

#include <ncsnet/ip.h>

int ip_check_add(const void *buf, size_t len, int check)
{
  u16 *sp = (u16*)buf;
  int n, sn;

  sn = len / 2;
  n = (sn + 15) / 16;

  switch (sn % 16) {
  case 0: do {
    check += *sp++;
  case 15:
    check += *sp++;
  case 14:
    check += *sp++;
  case 13:
    check += *sp++;
  case 12:
    check += *sp++;
  case 11:
    check += *sp++;
  case 10:
    check += *sp++;
  case 9:
    check += *sp++;
  case 8:
    check += *sp++;
  case 7:
    check += *sp++;
  case 6:
    check += *sp++;
  case 5:
    check += *sp++;
  case 4:
    check += *sp++;
  case 3:
    check += *sp++;
  case 2:
    check += *sp++;
  case 1:
    check += *sp++;
    } while (--n > 0);
  }

  if (len & 1)
    check += htons(*(u_char *)sp << 8);

  return check;
}
