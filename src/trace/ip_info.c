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

#include <ncsnet/trace.h>

const char *ip_info(const u8 *ip, size_t iplen, int detail, struct abstract_iphdr *info)
{
  int more_fragments=0, dont_fragment=0, reserved_flag=0, frag_off=0;
  char srchost[INET6_ADDRSTRLEN]="";
  char dsthost[INET6_ADDRSTRLEN]="";
  static char ipinfo[1024]="";
  u32 ip6_fl, ip6_tc, datalen;  
  const struct ip6_hdr *ip6;
  struct abstract_iphdr hdr;
  char fragnfo[64]="";
  const ip4h_t *iph;
  const u8 *data;

  datalen=iplen;
  data=(u8*)read_util_ip4getdata_any(ip, &datalen, &hdr);
  if (!data)
    return "ip (incorrect)";
  if (info)
    *info=hdr;
  if (hdr.version==4)
    goto ip4;
  goto ip6;

 ip4:
  iph=(ip4h_t*)ip;
  ip4t_ntop(&iph->src, srchost, sizeof(srchost));
  ip4t_ntop(&iph->dst, dsthost, sizeof(dsthost));

  frag_off=8*(ntohs(iph->off)&8191);
  more_fragments=ntohs(iph->off)&IP4_MF;
  dont_fragment=ntohs(iph->off)&IP4_DF;
  reserved_flag=ntohs(iph->off)&IP4_RF;

  if (frag_off||more_fragments)
    snprintf(fragnfo, sizeof(fragnfo), " frag offset=%d%s", frag_off, more_fragments ? "+" : "");
  if (detail==LOW_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "ip %s -> %s ttl=%d id=%hu iplen=%hu%s %s%s%s",
      srchost, dsthost, iph->ttl, (u16)ntohs(iph->id), (u16)ntohs(iph->totlen), fragnfo,
      iph->ihl==5?"":"ipopts={",
      iph->ihl==5?"":read_util_fmtipopt((u8*)iph+sizeof(ip4h_t), MIN((u32)(iph->ihl-5)*4, iplen-sizeof(ip4h_t))),
      iph->ihl==5?"":"}");
  else if (detail==MEDIUM_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "ip %s -> %s ttl=%d id=%hu proto=%d csum=0x%04x iplen=%hu%s %s%s%s",
      srchost, dsthost, iph->ttl, (u16)ntohs(iph->id),
      iph->proto, ntohs(iph->check),
      (u16) ntohs(iph->totlen), fragnfo,
      iph->ihl==5?"":"ipopts={",
      iph->ihl==5?"":read_util_fmtipopt((u8*)iph+sizeof(ip4h_t), MIN((u32)(iph->ihl-5)*4, iplen-sizeof(ip4h_t))),
      iph->ihl==5?"":"}");
  else if (detail==HIGH_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "ip %s -> %s ver=%d ihl=%d(%d) tos=0x%02x iplen=%hu id=%hu%s%s%s%s foff=%d%s ttl=%d proto=%d csum=0x%04x%s%s%s",
      srchost, dsthost, iph->version, iph->ihl, iph->ihl*4,
      iph->tos, (u16)ntohs(iph->totlen),
      (u16)ntohs(iph->id),
      (reserved_flag||dont_fragment||more_fragments) ? " flg=" : "",
      (reserved_flag)? "x" : "",
      (dont_fragment)? "D" : "",
      (more_fragments)? "M": "",
      frag_off, (more_fragments) ? "+" : "",
      iph->ttl, iph->proto,
      ntohs(iph->check),
      iph->ihl==5?"":" ipopts={",
      iph->ihl==5?"":read_util_fmtipopt((u8*)iph+sizeof(ip4h_t), MIN((u32)(iph->ihl-5)*4, iplen-sizeof(ip4h_t))),
      iph->ihl==5?"":"}");
  goto ok;

 ip6:
  ip6=(ip6h_t*)ip;
  ip6t_ntop(&ip6->src, srchost, sizeof(srchost));
  ip6t_ntop(&ip6->dst, dsthost, sizeof(dsthost));

  ip6_fl=((ip6->flags[1]&0x0F)<<16|(ip6->flags[2]<<8)|ip6->flags[3]);
  ip6_tc=((ip6->flags[0]&0x0F)<<4)|((ip6->flags[1]>>4)&0x0F);

  if (detail==LOW_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "ip %s -> %s hopl=%d flow=%x payloadlen=%hu",
      srchost, dsthost, ip6->hoplimit, ip6_fl, (u16)ntohs(ip6->totlen));
  else if (detail==MEDIUM_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "ip %s -> %s hopl=%d tclass=%hhu(0x%02x) flow=%x payloadlen=%hu",
      srchost, dsthost, ip6->hoplimit, ip6_tc, ip6_tc, ip6_fl, (u16)ntohs(ip6->totlen));
  else if (detail==HIGH_DETAIL)
    snprintf(ipinfo, sizeof(ipinfo), "ip %s -> %s ver=6, tclass=%hhu(0x%02x) flow=%x payloadlen=%hu nh=%s hopl=%d ",
      srchost, dsthost, ip6_tc, ip6_tc, ip6_fl, (u16)ntohs(ip6->totlen),
      read_util_nexthdrtoa(ip6->nxt, 1), ip6->hoplimit);
 ok:
  return ipinfo;
}
