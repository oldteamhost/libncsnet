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

#define writebuf(note) \
  strncat(traceinfo, note, sizeof(traceinfo)-strlen(traceinfo)-1);

const char *frminfo(const u8 *frame, size_t frmlen, int detail, u32 flags)
{
  /*
   * This is where the information will be recorded when you return it.
   */
  static char  info[TRACE_MAX_TOTAL_LEN]="";


  /*
   * Flags proccessing
   */
  bool skipeth=0;
  if (flags&FLAG_SKIPETH)
    skipeth=1;
  if (flags&FLAG_UDP)
    return udp_info(frame, frmlen, detail);
  if (flags&FLAG_ICMP4)
    return icmp4_info(frame, frmlen, detail);
  if (flags&FLAG_SCTP)
    return sctp_info(frame, frmlen, detail);
  if (flags&FLAG_IP)
    return ip_info(frame, frmlen, detail, NULL);
  if (flags&FLAG_ETH)
    return eth_info(frame, frmlen, detail);
  if (flags&FLAG_FRAME)
    return frm_info(frame, frmlen, NULL);
  if (flags&FLAG_TCP)
    return tcp_info(frame, frmlen, detail);
  if (flags&FLAG_ARP)
    return arp_info(frame, frmlen, detail);


  /*
   * ETHERNET FRAME
   * Gets the HEX and ASCII internet of the frame if high detail is
   * desired. Writes general information about the frame to frminfo,
   * and checks the frame size, if the check fails, it returns only
   * the information written above.
   */
  const char  *frminfo=NULL;
  char         asciinew[TRACE_MAX_DATA_LEN];
  char        *ascii=NULL;
  bool         valideth=0;

  if (detail==HIGH_DETAIL) {
    ascii=read_hexdump(frame, frmlen);
    if (ascii) {
      snprintf(asciinew, sizeof(asciinew), "\n\n%s", ascii);
      free(ascii);
    }
    else asciinew[0]='\0';
  }
  frminfo=frm_info(frame, frmlen, &valideth);
  if (!valideth) {
  onlyfrminfo:
    snprintf(info, sizeof(info), "%s\n%s", frminfo, asciinew);
    return info;
  }


  /*
   * HEADER MAC
   * Gathers information about MAC header, if skipeth is skip this stage,
   * otherwise, if there is only MAC header in the packet, it records
   * it and returns information, if not, it gets payload type in
   * ethtypeptr and ethtype, and increases skip according to MAC header
   * size, records eth protocol in traceinfo;
   */
  char         ethinfo[TRACE_PROTO_MAX_LEN];
  u16         *ethtypeptr=NULL, ethtype=0;
  char         traceinfo[TRACE_PROTO_MAX_LEN]="";
  size_t       skip=0;

  ethinfo[0]='\0';
  if (frmlen==ETH_HDR_LEN) {
    if (skipeth)
      goto onlyfrminfo;
    writebuf("eth;");
    snprintf(ethinfo, sizeof(ethinfo), "\n%s", eth_info(frame, frmlen, detail));
    snprintf(info, sizeof(info), "%s %s%s%s", traceinfo, frminfo, ethinfo, asciinew);
    return info;
  }
  if (!skipeth) {
    snprintf(ethinfo, sizeof(ethinfo), "\n%s", eth_info(frame, frmlen, detail));
    ethtypeptr=(u16*)(frame+MAC_ADDR_LEN*2);
    ethtype=(u16)ntohs(*ethtypeptr);
    skip+=ETH_HDR_LEN;
    writebuf("eth;");
  }
  else goto ipinfo; /* skip eth and goto at ipinfo*/


  /*
   * PAYLOAD TYPE IP4 and IP6
   */
  const char  *ipinfo=NULL;
  const char  *protoinfo=NULL;
  struct abstract_iphdr ipa;

  if (ethtype==ETH_TYPE_IPV4||ethtype==ETH_TYPE_IPV6) {
  ipinfo:
     writebuf("ip;");
     ipinfo=ip_info(frame+skip, frmlen-skip, detail, &ipa);
     if (((ethtype==ETH_TYPE_IPV4||ipa.version==4)&&frmlen<=skip+sizeof(ip4h_t))
       ||((ethtype==ETH_TYPE_IPV6||ipa.version==6)&&frmlen<=skip+sizeof(ip6h_t))) {
      snprintf(info, sizeof(info), "%s %s%s\n%s%s", traceinfo, frminfo, ethinfo, ipinfo, asciinew);
      return info;
    }
    if (ipa.version==4) skip+=sizeof(ip4h_t);
    else skip+=sizeof(ip6h_t);

    switch (ipa.proto) {
    case IPPROTO_ICMP:
      protoinfo=icmp4_info(frame+skip, frmlen-skip, detail);
      writebuf("icmp;");
      break;
    case IPPROTO_UDP:
      protoinfo=udp_info(frame+skip, frmlen-skip, detail);
      writebuf("udp;");
      break;
    case IPPROTO_SCTP:
      protoinfo=sctp_info(frame+skip, frmlen-skip, detail);
      writebuf("sctp;");
      break;
    case IPPROTO_TCP:
      protoinfo=tcp_info(frame+skip, frmlen-skip, detail);
      writebuf("tcp;");
      break;
    }

    snprintf(info, sizeof(info), "%s %s%s\n%s\n%s%s", traceinfo, frminfo, ethinfo, ipinfo, protoinfo, asciinew);
    return info;
  }


  /*
   * PAYLOAD TYPE ARP
   */
  else if (ethtype==ETH_TYPE_ARP) {
    writebuf("arp;");
    protoinfo=arp_info(frame+skip, frmlen-skip, detail);
    snprintf(info, sizeof(info), "%s %s%s\n%s%s", traceinfo, frminfo, ethinfo, protoinfo, asciinew);
    return info;
  }

  
  
  return NULL;
}
#undef writebuf
