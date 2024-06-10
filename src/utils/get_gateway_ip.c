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

#define ROUTE_FILE "/proc/net/route"
#define BUF_SIZE 512
int get_gateway_ip(char* buf, size_t len)
{
  FILE *file;
  char line[BUF_SIZE];
  char iface[BUF_SIZE], dest[BUF_SIZE], gw[BUF_SIZE];
  u32 gw_addr;

  file = fopen(ROUTE_FILE, "r");
  if (!file)
    return -1;

  fgets(line, BUF_SIZE, file);
  while (fgets(line, BUF_SIZE, file)) {
    if (sscanf(line, "%s %s %s", iface, dest, gw) == 3) {
      if (strcmp(dest, "00000000") == 0 && strcmp(gw, "00000000") != 0) {
        sscanf(gw, "%X", &gw_addr);
        snprintf(buf, len, "%d.%d.%d.%d",
            gw_addr & 0xFF, (gw_addr >> 8) & 0xFF,
            (gw_addr >> 16) & 0xFF, (gw_addr >> 24) & 0xFF);
        fclose(file);
        return 0;
      }
    }
  }

  fclose(file);
  return -1;
}
