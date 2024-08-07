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
#include <ncsnet/readpkt.h>

const char *ip_info(const u8 *frame, size_t frmlen, int detail)
{
  int more_fragments=0, dont_fragment=0, reserved_flag=0, frag_off=0;
  char srchost[INET6_ADDRSTRLEN] = "";
  char dsthost[INET6_ADDRSTRLEN] = "";
  u32 flow, ip6_fl, ip6_tc, datalen;  
  const struct sockaddr_in6 *sin6;
  static char ipinfo[1024] = "";
  const struct sockaddr_in *sin;
  const struct ip6_hdr *ip6;
  struct abstract_iphdr hdr;
  char fragnfo[64] = "";
  const ip4h_t *ip;
  const u8 *data;

  datalen = frmlen;
  data = (u8*)read_util_ip4getdata_any(frame, &datalen, &hdr);
  if (!data)
    return NULL;
  if (hdr.version==4)
    goto ip4;
  goto ip6;

 ip4:
  ip=(ip4h_t*)frame;
  sin=(struct sockaddr_in*)&hdr.src;
  ncs_inet_ntop(AF_INET, (void*)&sin->sin_addr.s_addr, srchost, sizeof(srchost));
  sin=(struct sockaddr_in*) &hdr.dst;
  ncs_inet_ntop(AF_INET, (void*)&sin->sin_addr.s_addr, dsthost, sizeof(dsthost));
  
  frag_off=8*(ntohs(ip->off)&8191);
  more_fragments=ntohs(ip->off)&IP4_MF;
  dont_fragment=ntohs(ip->off)&IP4_DF;
  reserved_flag=ntohs(ip->off)&IP4_RF;
  
  if (frag_off||more_fragments)
    snprintf(fragnfo, sizeof(fragnfo), " frag offset=%d%s", frag_off, more_fragments ? "+" : "");
  if (detail==LOW_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "IP: %s > %s ttl=%d id=%hu iplen=%hu%s %s%s%s",
      srchost, dsthost, ip->ttl, (u16)ntohs(ip->id), (u16)ntohs(ip->totlen), fragnfo,
      ip->ihl==5?"":"ipopts={",
      ip->ihl==5?"":read_util_fmtipopt((u8*)ip+sizeof(ip4h_t), MIN((u32)(ip->ihl-5)*4, frmlen-sizeof(ip4h_t))),
      ip->ihl==5?"":"}");
  else if (detail==MEDIUM_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "IP: %s > %s ttl=%d id=%hu proto=%d csum=0x%04x iplen=%hu%s %s%s%s",
      srchost, dsthost, ip->ttl, (u16)ntohs(ip->id),
      ip->proto, ntohs(ip->check),
      (u16) ntohs(ip->totlen), fragnfo,
      ip->ihl==5?"":"ipopts={",
      ip->ihl==5?"":read_util_fmtipopt((u8*)ip+sizeof(struct ip4_hdr), MIN((u32)(ip->ihl-5)*4,frmlen-sizeof(struct ip4_hdr))),
      ip->ihl==5?"":"}");
  else if (detail==HIGH_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "IP: %s > %s ver=%d ihl=%d tos=0x%02x iplen=%hu id=%hu%s%s%s%s foff=%d%s ttl=%d proto=%d csum=0x%04x%s%s%s",
      srchost, dsthost, ip->version, ip->ihl,
      ip->tos, (u16)ntohs(ip->totlen),
      (u16)ntohs(ip->id),
      (reserved_flag||dont_fragment||more_fragments) ? " flg=" : "",
      (reserved_flag)? "x" : "",
      (dont_fragment)? "D" : "",
      (more_fragments)? "M": "",
      frag_off, (more_fragments) ? "+" : "",
      ip->ttl, ip->proto,
      ntohs(ip->check),
      ip->ihl==5?"":" ipopts={",
      ip->ihl==5?"":read_util_fmtipopt((u8*)ip+sizeof(struct ip4_hdr), MIN((u32)(ip->ihl-5)*4, frmlen-sizeof(struct ip4_hdr))),
      ip->ihl==5?"":"}");
  goto ok;
  
 ip6:
  ip6=(struct ip6_hdr*)frame;
  sin6=(struct sockaddr_in6*)&hdr.src;
  ncs_inet_ntop(AF_INET6, (void*)sin6->sin6_addr.s6_addr, srchost, sizeof(srchost));
  sin6=(struct sockaddr_in6*)&hdr.dst;
  ncs_inet_ntop(AF_INET6, (void*)sin6->sin6_addr.s6_addr, dsthost, sizeof(dsthost));
  
  flow=ntohl(ip6->IP6_FLOW);
  ip6_fl=flow & 0x000fffff;
  ip6_tc=(flow & 0x0ff00000) >> 20;
  
  if (detail==LOW_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "IP: %s > %s hopl=%d flow=%x payloadlen=%hu",
      srchost, dsthost, ip6->IP6_HLIM, ip6_fl, (u16)ntohs(ip6->IP6_PKTLEN));
  else if (detail==MEDIUM_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "IP: %s > %s hopl=%d tclass=%d flow=%x payloadlen=%hu",
      srchost, dsthost, ip6->IP6_HLIM, ip6_tc, ip6_fl, (u16)ntohs(ip6->IP6_PKTLEN));
  else if (detail==HIGH_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "IP: %s > %s ver=6, tclass=%x flow=%x payloadlen=%hu nh=%s hopl=%d ",
      srchost, dsthost, ip6_tc, ip6_fl, (u16)ntohs(ip6->IP6_PKTLEN),
      read_util_nexthdrtoa(ip6->IP6_NXT, 1), ip6->IP6_HLIM);
 ok:  
  return ipinfo;
}
