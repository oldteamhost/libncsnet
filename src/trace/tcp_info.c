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

//#include <ncsnet/trace.h>
#include "../../ncsnet/trace.h"

const char *tcp_info(const u8 *tcp, size_t tcplen, int detail)
{
  static char tcpinfo[TRACE_PROTO_MAX_LEN]="";
  char tcpoptinfo[256] = "";
  tcph_t *tcph=NULL;
  char tflags[10];
  char *p=NULL;

  if (tcplen<TCP_HDR_LEN||!tcp)
    return "tcp (incorrect)";
  tcph=(tcph_t*)tcp;
  
  p=tflags;
  if (tcph->th_flags&TCP_FLAG_SYN)
    *p++='S';
  if (tcph->th_flags& TCP_FLAG_FIN)
    *p++='F';
  if (tcph->th_flags&TCP_FLAG_RST)
    *p++='R';
  if (tcph->th_flags&TCP_FLAG_PSH)
    *p++='P';
  if (tcph->th_flags&TCP_FLAG_ACK)
    *p++='A';
  if (tcph->th_flags&TCP_FLAG_URG)
    *p++='U';
  if (tcph->th_flags&TCP_FLAG_ECE)
    *p++='E';
  if (tcph->th_flags&TCP_FLAG_CWR)
    *p++='C';
  *p++ = '\0';

  if ((u32)tcph->th_off*4>sizeof(tcph_t)) {
    if (tcplen<(u32)tcph->th_off*4)
      snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");
    else
      read_util_tcpoptinfo((u8*)tcp+sizeof(tcph_t), tcph->th_off*4-sizeof(tcph_t),
        tcpoptinfo, sizeof(tcpoptinfo));
  }

  if (detail == LOW_DETAIL)
    snprintf(tcpinfo, sizeof(tcpinfo), "tcp src=%hu dst=%hu flags=%s seq=%lu win=%hu %s",
      (u16)ntohs(tcph->th_sport), (u16)ntohs(tcph->th_dport), tflags,
      (unsigned long)ntohl(tcph->th_seq), (u16)ntohs(tcph->th_win),
      tcpoptinfo);
  else if (detail == MEDIUM_DETAIL)
    snprintf(tcpinfo, sizeof(tcpinfo), "tcp src=%hu dst=%hu flags=%s seq=%lu win=%hu csum=0x%04X%s%s",
      (u16)ntohs(tcph->th_sport), (u16)ntohs(tcph->th_dport), tflags,
      (unsigned long)ntohl(tcph->th_seq), (u16)ntohs(tcph->th_win),
      (u16)ntohs(tcph->th_sum), (tcpoptinfo[0]!='\0')?" ":"", tcpoptinfo);
  else if (detail == HIGH_DETAIL)
    snprintf(tcpinfo, sizeof(tcpinfo), "tcp src=%hu dst=%hu flags=%s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%hu%s%s",
      (u16)ntohs(tcph->th_sport), (u16)ntohs(tcph->th_dport), tflags,
      (unsigned long)ntohl(tcph->th_seq), (unsigned long)ntohl(tcph->th_ack),
      (u8)tcph->th_off, (u8)tcph->th_x2, (u16)ntohs(tcph->th_win),
      ntohs(tcph->th_sum), (u16)ntohs(tcph->th_urp), (tcpoptinfo[0]!='\0')?" ":"", tcpoptinfo);
  
  return tcpinfo;
}
