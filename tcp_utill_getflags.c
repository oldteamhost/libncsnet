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

struct tcp_flags tcp_util_getflags(u8 flags)
{
  struct tcp_flags tf;
  
  tf.syn = (flags & TCP_FLAG_SYN) ? 1 : 0;
  tf.ack = (flags & TCP_FLAG_ACK) ? 1 : 0;
  tf.fin = (flags & TCP_FLAG_FIN) ? 1 : 0;
  tf.rst = (flags & TCP_FLAG_RST) ? 1 : 0;
  tf.urg = (flags & TCP_FLAG_URG) ? 1 : 0;
  tf.psh = (flags & TCP_FLAG_PSH) ? 1 : 0;
  tf.cwr = (flags & TCP_FLAG_CWR) ? 1 : 0;
  tf.ece = (flags & TCP_FLAG_ECE) ? 1 : 0;
  
  return tf;
}
