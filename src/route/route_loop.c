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

#include <ncsnet/route.h>

int route_loop(route_t *r, route_handler callback, void *arg)
{
  char        s[33], d[8][5], n[8][5];
  char        buf[BUFSIZ];
  int         ret=0;
  FILE       *fp;
  int         i, iflags, refcnt, use, metric, mss, win, irtt;
  u32         mask;
  u32         slen, dlen;
  route_entry entry;

  if (!(fp = fopen(PROC_ROUTE_FILE, "r")))
    return ret;

  while (fgets(buf, sizeof(buf), fp)) {
    u32 tmp, tmp1;
    i=sscanf(buf, "%16s %X %X %X %d %d %d %X %d %d %d\n",
      entry.dev, &tmp, &tmp1, &iflags, &refcnt, &use,
      &metric, &mask, &mss, &win, &irtt);
    u32_ip4t(tmp, &entry.route_dst.addr_ip4);
    u32_ip4t(tmp1, &entry.route_gw.addr_ip4);
    if (i<10||!(iflags&RTF_UP))
      continue;
    if (ip4t_u32(&entry.route_gw.addr_ip4)==IP4_ADDR_ANY)
      continue;
    entry.route_dst.type=entry.route_gw.type=ADDR_TYPE_IP;
    if (addr_mtob(&mask, IP4_ADDR_LEN, &entry.route_dst.bits)<0)
        continue;
    entry.route_gw.bits=IP4_ADDR_BITS;
    if ((ret = callback(&entry, arg)) != 0)
      break;
  }
  fclose(fp);

  if (ret!=0||(!(fp=fopen(PROC_IPV6_ROUTE_FILE, "r"))))
    return ret;

  while (fgets(buf, sizeof(buf), fp)) {
    sscanf(buf, "%04s%04s%04s%04s%04s%04s%04s%04s %02x "
      "%32s %02x %04s%04s%04s%04s%04s%04s%04s%04s ",
      d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
      &dlen, s, &slen,
      n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]);

    snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s:%s:%s/%d",
      d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
      dlen);
    addr_aton(buf, &entry.route_dst);
    snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s:%s:%s/%d",
      n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], IP6_ADDR_BITS);
    addr_aton(buf, &entry.route_gw);
    if ((ret=callback(&entry, arg))!=0)
      break;
  }
  fclose(fp);

  return ret;
}

