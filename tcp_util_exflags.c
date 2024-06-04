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

#include "ncsnet/tcp.h"

struct tcp_flags tcp_util_exflags(u8 type)
{
  struct tcp_flags tpf;
  memset(&tpf, 0, sizeof(struct tcp_flags));

  tpf.rst = 0;
  tpf.ack = 0;
  switch (type) {
    case TCP_SYN_PACKET:
      tpf.syn = 1;
      tpf.fin = 0;
      tpf.psh = 0;
      tpf.urg = 0;
      break;
    case TCP_XMAS_PACKET:
      tpf.syn = 0;
      tpf.fin = 1;
      tpf.psh = 1;
      tpf.urg = 1;
      break;
    case TCP_FIN_PACKET:
      tpf.syn = 0;
      tpf.fin = 1;
      tpf.psh = 0;
      tpf.urg = 0;
      break;
    case TCP_NULL_PACKET:
      tpf.syn = 0;
      tpf.fin = 0;
      tpf.psh = 0;
      tpf.urg = 0;
      break;
    case TCP_WINDOW_PACKET:
    case TCP_ACK_PACKET:
      tpf.syn = 0;
      tpf.fin = 0;
      tpf.psh = 0;
      tpf.urg = 0;
      tpf.ack = 1;
      break;
    case TCP_MAIMON_PACKET:
      tpf.syn = 0;
      tpf.fin = 1;
      tpf.psh = 0;
      tpf.urg = 0;
      tpf.ack = 1;
      break;
    case TCP_PSH_PACKET:
      tpf.syn = 0;
      tpf.fin = 0;
      tpf.psh = 1;
      tpf.urg = 0;
      tpf.ack = 0;
      break;
  }
  return tpf;
}
