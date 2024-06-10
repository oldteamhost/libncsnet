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

void parse_tcpopts(u8 *optp, int len, char *result,
    int bufsize)
{
  assert(optp);
  assert(result);
  char *p, ch;
  u8 *q;
  int opcode;
  u16 tmpshort;
  u32 tmpword1, tmpword2;
  u32 i = 0;

  p = result;
  *p = '\0';
  q = optp;
  ch = '<';

  while (len > 0 && bufsize > 2) {
    snprintf(p, bufsize, "%c", ch);
    bufsize--;
    p++;
    opcode = *q++;
    if (!opcode) { /* End of List */
      snprintf(p, bufsize, "eol");
      bufsize -= strlen(p);
      p += strlen(p);
      len--;
    }
    else if (opcode == 1) { /* No Op */
      snprintf(p, bufsize, "nop");
      bufsize -= strlen(p);
      p += strlen(p);

      len--;
    }
    else if (opcode == 2) { /* MSS */
      if (len < 4)
        break; /* MSS has 4 bytes */

      q++;
      memcpy(&tmpshort, q, 2);

      snprintf(p, bufsize, "mss %hu", (u16) ntohs(tmpshort));
      bufsize -= strlen(p);
      p += strlen(p);

      q += 2;
      len -= 4;
    }
    else if (opcode == 3) { /* Window Scale */
      if (len < 3)
        break; /* Window Scale option has 3 bytes */

      q++;

      snprintf(p, bufsize, "wscale %u", *q);
      bufsize -= strlen(p);
      p += strlen(p);

      q++;
      len -= 3;
    }
    else if (opcode == 4) { /* SACK permitted */
      if (len < 2)
        break; /* SACK permitted option has 2 bytes */

      snprintf(p, bufsize, "sackOK");
      bufsize -= strlen(p);
      p += strlen(p);

      q++;
      len -= 2;
    }
    else if (opcode == 5) { /* SACK */
      unsigned sackoptlen = *q;
      if ((unsigned) len < sackoptlen)
        break;

      /* This would break parsing, so it's best to just give up */
      if (sackoptlen < 2)
        break;

      q++;

      if ((sackoptlen - 2) == 0 || ((sackoptlen - 2) % 8 != 0)) {
        snprintf(p, bufsize, "malformed sack");
        bufsize -= strlen(p);
        p += strlen(p);
      }
      else {
        snprintf(p, bufsize, "sack %d ", (sackoptlen - 2) / 8);
        bufsize -= strlen(p);
        p += strlen(p);
        for (i = 0; i < sackoptlen - 2; i += 8) {
          memcpy(&tmpword1, q + i, 4);
          memcpy(&tmpword2, q + i + 4, 4);
          snprintf(p, bufsize, "{%u:%u}", tmpword1, tmpword2);
          bufsize -= strlen(p);
          p += strlen(p);
        }
      }

      q += sackoptlen - 2;
      len -= sackoptlen;
    }
    else if (opcode == 8) { /* Timestamp */
      if (len < 10)
        break;
      q++;
      memcpy(&tmpword1, q, 4);
      memcpy(&tmpword2, q + 4, 4);

      snprintf(p, bufsize, "timestamp %lu %lu", (unsigned long) ntohl(tmpword1),
               (unsigned long) ntohl(tmpword2));
      bufsize -= strlen(p);
      p += strlen(p);

      q += 8;
      len -= 10;
    }
    ch = ',';
  }

  if (len > 0) {
    *result = '\0';
    return;
  }
  snprintf(p, bufsize, ">");
}
