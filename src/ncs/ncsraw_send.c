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

#include <ncsnet/nescanet.h>

static void tmpdelay(long long ns)
{
  struct timespec ts;
  ts.tv_sec = ns / 1000000000;
  ts.tv_nsec = ns % 1000000000;
  nanosleep(&ts, NULL);
}

ssize_t ncsraw_send(ncsraw_t *n)
{
  size_t res = 0;
  if (n->no.randomfd) {
    if (n->fd != -1)
      close(n->fd);
    n->fd = socket(n->dst_in.ss_family, SOCK_RAW, IPPROTO_RAW);
    if (n->fd == -1)
      return -1;
  }
  else {
    if (n->fd == -1) {
      n->fd = socket(n->dst_in.ss_family, SOCK_RAW, IPPROTO_RAW);
      if (n->fd == -1)
	return -1;
    }
  }
  tmpdelay(n->no.delay);

  res = ip_send(NULL, n->fd, &n->dst_in, n->mtu, n->pkt, n->pktlen);
  if (n->no.trace > 0)
    read_util_tracepkt(TRACE_PKT_SENT, n->pkt, n->pktlen, 0, n->no.trace);
  return res;
}
