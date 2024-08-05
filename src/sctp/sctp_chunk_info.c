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

#include <ncsnet/sctp.h>

const char *sctp_chunktypestr(u8 type)
{
  static char chunktypestr[512] = "";
  
  switch(type) {
  case SCTP_DATA: snprintf(chunktypestr, sizeof(chunktypestr), "data"); break;
  case SCTP_INIT: snprintf(chunktypestr, sizeof(chunktypestr), "init"); break;
  case SCTP_INIT_ACK: snprintf(chunktypestr, sizeof(chunktypestr), "init-ack"); break;
  case SCTP_SACK: snprintf(chunktypestr, sizeof(chunktypestr), "sack"); break;
  case SCTP_HEARTBEAT: snprintf(chunktypestr, sizeof(chunktypestr), "heartbeat"); break;
  case SCTP_HEARTBEAT_ACK: snprintf(chunktypestr, sizeof(chunktypestr), "heartbeat-ack"); break;
  case SCTP_ABORT: snprintf(chunktypestr, sizeof(chunktypestr), "abort"); break;
  case SCTP_SHUTDOWN: snprintf(chunktypestr, sizeof(chunktypestr), "shutdown"); break;
  case SCTP_SHUTDOWN_ACK: snprintf(chunktypestr, sizeof(chunktypestr), "shutdown-ack"); break;
  case SCTP_SHUTDOWN_COMPLETE: snprintf(chunktypestr, sizeof(chunktypestr), "shutdown-complete"); break;
  case SCTP_ERROR: snprintf(chunktypestr, sizeof(chunktypestr), "error"); break;
  case SCTP_COOKIE_ECHO: snprintf(chunktypestr, sizeof(chunktypestr), "cookie-echo"); break;
  case SCTP_COOKIE_ACK: snprintf(chunktypestr, sizeof(chunktypestr), "cookie-ack"); break;
  case SCTP_ECNE: snprintf(chunktypestr, sizeof(chunktypestr), "ecne"); break;
  case SCTP_CWR: snprintf(chunktypestr, sizeof(chunktypestr), "cwr"); break;
  case SCTP_AUTH: snprintf(chunktypestr, sizeof(chunktypestr), "auth"); break;
  case SCTP_ASCONF: snprintf(chunktypestr, sizeof(chunktypestr), "asconf"); break;
  case SCTP_ASCONF_ACK: snprintf(chunktypestr, sizeof(chunktypestr), "asconf-ack"); break;
  case SCTP_PKTDROP: snprintf(chunktypestr, sizeof(chunktypestr), "pktdrop"); break;
  case SCTP_PAD: snprintf(chunktypestr, sizeof(chunktypestr), "pad"); break;
  case SCTP_FORWARD_TSN: snprintf(chunktypestr, sizeof(chunktypestr), "forward-tsn"); break;
  default: snprintf(chunktypestr, sizeof(chunktypestr), "%hhu", type); break;
  }
  
  return chunktypestr;
}

const char *sctp_chunk_info(const u8 *chunk)
{
  static char chunkhdrinfo[512] = "";
  static char chunkinfo[1024] = "";
  sctp_chunk *chunkhdr=NULL;

  chunkhdr=(sctp_chunk*)chunk;
  if (!chunkhdr)
    return NULL;

  snprintf(chunkhdrinfo, sizeof(chunkhdrinfo), "chunk=%s flags=%hhu len=%hu",
    sctp_chunktypestr(chunkhdr->type), chunkhdr->flags, (u16)ntohs(chunkhdr->len));
  
  switch(chunkhdr->type) {
  case SCTP_DATA: {
    sctp_chunk_data *data=(sctp_chunk_data*)chunk;
    u8 *realdata=(u8*)((chunk)+sizeof(sctp_chunk_data));
    size_t realdatalen=(u16)ntohs(chunkhdr->len)-sizeof(sctp_chunk_data), i=0;
    char realdatahex[realdatalen*2+1];
    if (realdatalen>0) {
      for (;i<realdatalen;i++)
	snprintf(&realdatahex[i*2], 3, "%02x", realdata[i]);
      snprintf(chunkinfo, sizeof(chunkinfo), "%s tsn=%u stream=%hu n=%hu protoload=%u data=%s datalen=%lu",
        chunkhdrinfo, (u32)ntohl(data->tsn), (u16)ntohs(data->s), (u16)ntohs(data->n),
        (u32)ntohl(data->protoload), realdatahex, realdatalen);
    }
    else
      snprintf(chunkinfo, sizeof(chunkinfo), "%s tsn=%u stream=%hu n=%hu protoload=%u data=empty",
        chunkhdrinfo, (u32)ntohl(data->tsn), (u16)ntohs(data->s), (u16)ntohs(data->n),
        (u32)ntohl(data->protoload));
    break;
  }
  case SCTP_COOKIE_ECHO: {
    u8 *cookie=(u8*)((chunk)+sizeof(sctp_chunk));
    size_t cookielen=(u16)ntohs(chunkhdr->len)-sizeof(sctp_chunk), i=0;
    char cookiehex[cookielen*2+1];
    if (cookielen>0) {    
      for (;i<cookielen;i++)
	snprintf(&cookiehex[i*2], 3, "%02x", cookie[i]);
      snprintf(chunkinfo, sizeof(chunkinfo), "%s cookie=%s cookielen=%lu",
        chunkhdrinfo, cookiehex, cookielen);
    }
    else
      snprintf(chunkinfo, sizeof(chunkinfo), "%s cookie=empty", chunkhdrinfo);
    break;
  }
  case SCTP_INIT_ACK:
  case SCTP_INIT: {
    sctp_chunk_init *init=(sctp_chunk_init*)chunk;
    snprintf(chunkinfo, sizeof(chunkinfo), "%s itag=%u arwnd=%u nos=%hu nis=%hu itsn=%hu",
      chunkhdrinfo, (u32)ntohl(init->itag), (u32)ntohl(init->arwnd), (u16)ntohs(init->nos),
      (u16)ntohs(init->nis), (u32)ntohl(init->itsn));
    break;
  }
  case SCTP_SHUTDOWN: {
    u32 *tsnack=(u32*)(chunk+sizeof(sctp_chunk));
    snprintf(chunkinfo, sizeof(chunkinfo), "%s tsnack=%u",
      chunkhdrinfo, ntohl(*tsnack));
    break;
  }
  case SCTP_HEARTBEAT_ACK:
  case SCTP_HEARTBEAT: {
    sctp_chunk_heartbeat_info *info=(sctp_chunk_heartbeat_info*)(chunk+sizeof(sctp_chunk));
    size_t realinfolen=((u16)ntohs(info->infolen)-sizeof(sctp_chunk_heartbeat_info)), i=0;
    u8 *realinfo=(u8*)((chunk)+sizeof(sctp_chunk_heartbeat));
    char realinfohex[realinfolen*2+1];
    if (realinfolen>0) {    
      for (;i<realinfolen;i++)
	snprintf(&realinfohex[i*2], 3, "%02x", realinfo[i]);
      snprintf(chunkinfo, sizeof(chunkinfo), "%s type=%hu info=%s infolen=%lu",
        chunkhdrinfo, (u16)ntohs(info->type), realinfohex, realinfolen);      
    }
    else
      snprintf(chunkinfo, sizeof(chunkinfo), "%s type=%hu info=empty",
        chunkhdrinfo, (u16)ntohs(info->type));
    break;
  }
  case SCTP_ERROR: {
    sctp_error_cause_op *cause=(sctp_error_cause_op*)(chunk+sizeof(sctp_chunk));
    size_t errorlen=((u16)ntohs(cause->len)-sizeof(sctp_error_cause_op)), i=0;
    u8 *error=(u8*)((chunk)+sizeof(sctp_chunk_error));
    char errorhex[errorlen*2+1];
    if (errorlen>0) {    
      for (;i<errorlen;i++)
	snprintf(&errorhex[i*2], 3, "%02x", error[i]);
      snprintf(chunkinfo, sizeof(chunkinfo), "%s code=%hu info=%s infolen=%lu",
        chunkhdrinfo, (u16)ntohs(cause->code), errorhex, errorlen);      
    }
    else
      snprintf(chunkinfo, sizeof(chunkinfo), "%s code=%hu info=empty",
        chunkhdrinfo, (u16)ntohs(cause->code));      
    break;
  }
  case SCTP_ABORT: {
    size_t errorlen=(u16)ntohs(chunkhdr->len)-sizeof(sctp_chunk);
    snprintf(chunkinfo, sizeof(chunkinfo), "%s errorlen=%lu", chunkhdrinfo, errorlen);    
    break;
  }
  case SCTP_SHUTDOWN_COMPLETE:
  case SCTP_SHUTDOWN_ACK:
  case SCTP_COOKIE_ACK:
  default:
    snprintf(chunkinfo, sizeof(chunkinfo), "%s", chunkhdrinfo);
    break;
  }

  return chunkinfo;
}
