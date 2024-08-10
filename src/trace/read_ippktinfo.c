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

const char *read_ippktinfo(const u8 *pkt, u32 len, int detail)
{
  struct abstract_iphdr hdr;
  const u8 *data;
  u32 datalen;

  struct tcp_hdr *tcp = NULL;
  struct udp_hdr *udp = NULL;
  struct sctp_hdr *sctp = NULL;
  static char protoinfo[1024] = "";
  char ipinfo[512] = "";
  char icmpinfo[512] = "";
  char icmptype[128] = "";
  char icmpfields[256] = "";
  char fragnfo[64] = "";
  char srchost[INET6_ADDRSTRLEN] = "";
  char dsthost[INET6_ADDRSTRLEN] = "";
  char *p = NULL;
  int frag_off = 0;
  int more_fragments = 0;
  int dont_fragment = 0;
  int reserved_flag = 0;

  datalen = len;
  data = (u8*)read_util_ip4getdata_any(pkt, &datalen, &hdr);
  if (data == NULL)
    return "BOGUS! Can't parse supposed IP packet";
  
  if (detail != LOW_DETAIL && detail != MEDIUM_DETAIL && detail != HIGH_DETAIL)
    detail = LOW_DETAIL;
  
  if (hdr.version == 4) {
    const struct ip4_hdr *ip;
    const struct sockaddr_in *sin;
    
    ip = (struct ip4_hdr*)pkt;
    sin = (struct sockaddr_in *) &hdr.src;
    ncs_inet_ntop(AF_INET, (void *)&sin->sin_addr.s_addr, srchost, sizeof(srchost));
    sin = (struct sockaddr_in *) &hdr.dst;
    ncs_inet_ntop(AF_INET, (void *)&sin->sin_addr.s_addr, dsthost, sizeof(dsthost));
	
    frag_off = 8 * (ntohs(ip->off) & 8191);
    more_fragments = ntohs(ip->off) & IP4_MF;
    dont_fragment = ntohs(ip->off) & IP4_DF;
    reserved_flag = ntohs(ip->off) & IP4_RF;
    
    if (frag_off || more_fragments)
      snprintf(fragnfo, sizeof(fragnfo), " frag offset=%d%s", frag_off, more_fragments ? "+" : "");
    
    if (detail == LOW_DETAIL)
      snprintf(ipinfo, sizeof(ipinfo), "ttl=%d id=%hu iplen=%hu%s %s%s%s",
	       ip->ttl, (u16)ntohs(ip->id), (u16)ntohs(ip->totlen), fragnfo,
	       ip->ihl==5?"":"ipopts={",
	       ip->ihl==5?"":read_util_fmtipopt((u8*) ip + sizeof(struct ip4_hdr), MIN((unsigned)(ip->ihl-5)*4,len-sizeof(struct ip4_hdr))),
	       ip->ihl==5?"":"}");
    else if (detail == MEDIUM_DETAIL)
      snprintf(ipinfo, sizeof(ipinfo), "ttl=%d id=%hu proto=%d csum=0x%04x iplen=%hu%s %s%s%s",
	       ip->ttl, (u16)ntohs(ip->id),
	       ip->proto, ntohs(ip->check),
	       (u16) ntohs(ip->totlen), fragnfo,
	       ip->ihl==5?"":"ipopts={",
	       ip->ihl==5?"":read_util_fmtipopt((u8*) ip + sizeof(struct ip4_hdr), MIN((unsigned)(ip->ihl-5)*4,len-sizeof(struct ip4_hdr))),
	       ip->ihl==5?"":"}");
    else if (detail == HIGH_DETAIL)
      snprintf(ipinfo, sizeof(ipinfo), "ver=%d ihl=%d tos=0x%02x iplen=%hu id=%hu%s%s%s%s foff=%d%s ttl=%d proto=%d csum=0x%04x%s%s%s",
	       ip->version, ip->ihl,
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
	       ip->ihl==5?"":read_util_fmtipopt((u8*) ip + sizeof(struct ip4_hdr), MIN((unsigned)(ip->ihl-5)*4,len-sizeof(struct ip4_hdr))),
               ip->ihl==5?"":"}");
  }
  else {
    const struct ip6_hdr *ip6;
    const struct sockaddr_in6 *sin6;

    ip6 = (struct ip6_hdr*)pkt;
    sin6 = (struct sockaddr_in6 *) &hdr.src;
    ncs_inet_ntop(AF_INET6, (void *)sin6->sin6_addr.s6_addr, srchost, sizeof(srchost));
    sin6 = (struct sockaddr_in6 *) &hdr.dst;
    ncs_inet_ntop(AF_INET6, (void *)sin6->sin6_addr.s6_addr, dsthost, sizeof(dsthost));

    u32 flow = ntohl(ip6->IP6_FLOW);
    u32 ip6_fl = flow & 0x000fffff;
    u32 ip6_tc = (flow & 0x0ff00000) >> 20;
    
    if (detail == LOW_DETAIL)
      snprintf(ipinfo, sizeof(ipinfo), "hopl=%d flow=%x payloadlen=%hu",
	       ip6->IP6_HLIM, ip6_fl, (u16)ntohs(ip6->IP6_PKTLEN));
    else if (detail == MEDIUM_DETAIL)
      snprintf(ipinfo, sizeof(ipinfo), "hopl=%d tclass=%d flow=%x payloadlen=%hu",
	       ip6->IP6_HLIM, ip6_tc, ip6_fl, (u16)ntohs(ip6->IP6_PKTLEN));
    else if (detail==HIGH_DETAIL)
      snprintf(ipinfo, sizeof(ipinfo), "ver=6, tclass=%x flow=%x payloadlen=%hu nh=%s hopl=%d ",
	       ip6_tc, ip6_fl, (u16)ntohs(ip6->IP6_PKTLEN),
	       read_util_nexthdrtoa(ip6->IP6_NXT, 1), ip6->IP6_HLIM);
  }

  if (hdr.proto == IPPROTO_TCP) {
    char tflags[10];
    char tcpinfo[64] = "";
    char buf[32];
    char tcpoptinfo[256] = "";
    tcp = (struct tcp_hdr*)data;

    if (frag_off > 8 || datalen < 8)
      snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? ?? %s (incomplete)",
	       srchost, dsthost, ipinfo);
    else if (frag_off > 0) {
      assert(frag_off == 8);
      tcp = (struct tcp_hdr*)((u8*)tcp - frag_off);

      p = tflags;
      if (tcp->th_flags & TCP_FLAG_SYN)
        *p++ = 'S';
      if (tcp->th_flags & TCP_FLAG_FIN)
        *p++ = 'F';
      if (tcp->th_flags & TCP_FLAG_RST)
        *p++ = 'R';
      if (tcp->th_flags & TCP_FLAG_PSH)
        *p++ = 'P';
      if (tcp->th_flags & TCP_FLAG_ACK) {
        *p++ = 'A';
	snprintf(tcpinfo, sizeof(tcpinfo), " ack=%lu", (unsigned long)ntohl(tcp->th_ack));
      }
      if (tcp->th_flags & TCP_FLAG_URG)
        *p++ = 'U';
      if (tcp->th_flags & TCP_FLAG_ECE)
        *p++ = 'E';
      if (tcp->th_flags & TCP_FLAG_CWR)
        *p++ = 'C';
      *p++ = '\0';

      if ((u32) tcp->th_off * 4 > sizeof(struct tcp_hdr)) {
	if (datalen < (u32) tcp->th_off * 4 - frag_off)
	  snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");
	else
	  read_util_tcpoptinfo((u8*) tcp + sizeof(struct tcp_hdr), tcp->th_off*4 - sizeof(struct tcp_hdr), tcpoptinfo, sizeof(tcpoptinfo));
      }
      
      if (detail == LOW_DETAIL)
	snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s %s %s %s",
		 srchost, dsthost, tflags, ipinfo, tcpinfo, tcpoptinfo);
      else if (detail == MEDIUM_DETAIL)
	snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s ack=%lu win=%hu %s IP [%s]",
		 srchost, dsthost, tflags,
		 (unsigned long)ntohl(tcp->th_ack), (u16)ntohs(tcp->th_win),
		 tcpoptinfo, ipinfo);
      else if (detail == HIGH_DETAIL) {
	if (datalen >= 12)
	  snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:?? > %s:?? %s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%hu%s%s] IP [%s]",
		   srchost, dsthost, tflags,
		   (unsigned long)ntohl(tcp->th_seq),
		   (unsigned long)ntohl(tcp->th_ack),
		   (u8)tcp->th_off, (u8)tcp->th_x2, (u16)ntohs(tcp->th_win),
		   ntohs(tcp->th_sum), (u16)ntohs(tcp->th_urp),
		   (tcpoptinfo[0]!='\0') ? " " : "",
		   tcpoptinfo, ipinfo);
	else
	  snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s ack=%lu win=%hu %s IP [%s]",
		   srchost, dsthost, tflags,
		   (unsigned long)ntohl(tcp->th_ack), (u16)ntohs(tcp->th_win),
		   tcpoptinfo, ipinfo);
      }
    }
    else if (datalen < 20) {
      if (datalen < 12)
        snprintf(tcpinfo, sizeof(tcpinfo), "TCP %s:%hu > %s:%hu ?? seq=%lu (incomplete) %s",
		 srchost, (u16)ntohs(tcp->th_sport), dsthost,
		 (u16)ntohs(tcp->th_dport), (unsigned long)ntohl(tcp->th_seq), ipinfo);
      
      else if (datalen < 16) {
	if (detail == LOW_DETAIL)
	  snprintf(tcpinfo, sizeof(tcpinfo), "TCP %s:%hu > %s:%hu seq=%lu (incomplete), %s",
		   srchost, (u16)ntohs(tcp->th_sport), dsthost,
		   (u16)ntohs(tcp->th_dport), (unsigned long) ntohl(tcp->th_seq), ipinfo);
	else
	  snprintf(tcpinfo, sizeof(tcpinfo), "TCP [%s:%hu > %s:%hu seq=%lu ack=%lu (incomplete)] IP [%s]",
		   srchost, (u16)ntohs(tcp->th_sport), dsthost,
		   (u16)ntohs(tcp->th_dport), (unsigned long) ntohl(tcp->th_seq),
		   (unsigned long) ntohl(tcp->th_ack), ipinfo);
      }
      else {
	p = tflags;
	if (tcp->th_flags & TCP_FLAG_SYN)
	  *p++ = 'S';
	if (tcp->th_flags & TCP_FLAG_FIN)
	  *p++ = 'F';
	if (tcp->th_flags & TCP_FLAG_RST)
	  *p++ = 'R';
	if (tcp->th_flags & TCP_FLAG_PSH)
	  *p++ = 'P';
	if (tcp->th_flags & TCP_FLAG_ACK) {
	  *p++ = 'A';
	  snprintf(buf, sizeof(buf), " ack=%lu",
		   (unsigned long)ntohl(tcp->th_ack));
	  strncat(tcpinfo, buf, sizeof(tcpinfo) - strlen(tcpinfo) - 1);
	}
	if (tcp->th_flags & TCP_FLAG_URG)
	  *p++ = 'U';
	if (tcp->th_flags & TCP_FLAG_ECE)
	  *p++ = 'E';
	if (tcp->th_flags & TCP_FLAG_CWR)
	  *p++ = 'C';
	*p++ = '\0';
	
	if (detail == LOW_DETAIL)
	  snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%hu > %s:%hu %s %s seq=%lu win=%hu (incomplete)",
		   srchost, (u16)ntohs(tcp->th_sport), dsthost, (u16)ntohs(tcp->th_dport),
		   tflags, ipinfo, (unsigned long) ntohl(tcp->th_seq),
		   (u16)ntohs(tcp->th_win));
	else if (detail == MEDIUM_DETAIL)
	  snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu ack=%lu win=%hu (incomplete)] IP [%s]",
		   srchost, (u16)ntohs(tcp->th_sport), dsthost, (u16)ntohs(tcp->th_dport),
		   tflags,  (unsigned long) ntohl(tcp->th_seq),
		   (unsigned long) ntohl(tcp->th_ack),
		   (u16)ntohs(tcp->th_win), ipinfo);
	else if (detail == HIGH_DETAIL)
	  snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu ack=%lu off=%d res=%d win=%hu (incomplete)] IP [%s]",
		   srchost, (u16)ntohs(tcp->th_sport),
		   dsthost, (u16)ntohs(tcp->th_dport),
		   tflags, (unsigned long) ntohl(tcp->th_seq),
		   (unsigned long) ntohl(tcp->th_ack),
		   (u8)tcp->th_off, (u8)tcp->th_x2, (u16)ntohs(tcp->th_win),
		   ipinfo);
      }
    }
    else {












      
      p = tflags;
      if (tcp->th_flags & TCP_FLAG_SYN)
        *p++ = 'S';
      if (tcp->th_flags & TCP_FLAG_FIN)
        *p++ = 'F';
      if (tcp->th_flags & TCP_FLAG_RST)
        *p++ = 'R';
      if (tcp->th_flags & TCP_FLAG_PSH)
        *p++ = 'P';
      if (tcp->th_flags & TCP_FLAG_ACK) {
        *p++ = 'A';
	snprintf(buf, sizeof(buf), " ack=%lu",
		 (unsigned long)ntohl(tcp->th_ack));
        strncat(tcpinfo, buf, sizeof(tcpinfo) - strlen(tcpinfo) - 1);
      }
      if (tcp->th_flags & TCP_FLAG_URG)
        *p++ = 'U';
      if (tcp->th_flags & TCP_FLAG_ECE)
        *p++ = 'E';
      if (tcp->th_flags & TCP_FLAG_CWR)
        *p++ = 'C';
      *p++ = '\0';
      
      if ((u32)tcp->th_off * 4 > sizeof(struct tcp_hdr)) {
        if (datalen < (u32)tcp->th_off * 4) {
          snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");
	} else {
          read_util_tcpoptinfo((u8*) tcp + sizeof(struct tcp_hdr),
			       tcp->th_off*4 - sizeof(struct tcp_hdr),
			       tcpoptinfo, sizeof(tcpoptinfo));
        }
      }
      if (detail == LOW_DETAIL)
        snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%hu > %s:%hu %s %s seq=%lu win=%hu %s",
		 srchost, (u16)ntohs(tcp->th_sport), dsthost, (u16)ntohs(tcp->th_dport),
		 tflags, ipinfo, (unsigned long)ntohl(tcp->th_seq),
		 (u16)ntohs(tcp->th_win), tcpoptinfo);
      else if (detail == MEDIUM_DETAIL)
        snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu win=%hu csum=0x%04X%s%s] IP [%s]",
		 srchost, (u16)ntohs(tcp->th_sport), dsthost, (u16)ntohs(tcp->th_dport),
		 tflags, (unsigned long)ntohl(tcp->th_seq),
		 (u16)ntohs(tcp->th_win), (u16)ntohs(tcp->th_sum),
		 (tcpoptinfo[0]!='\0') ? " " : "",
		 tcpoptinfo, ipinfo);
      else if (detail == HIGH_DETAIL)
        snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%hu%s%s] IP [%s]",
		 srchost, (u16)ntohs(tcp->th_sport),
		 dsthost, (u16)ntohs(tcp->th_dport),
		 tflags, (unsigned long)ntohl(tcp->th_seq),
		 (unsigned long)ntohl(tcp->th_ack),
		 (u8)tcp->th_off, (u8)tcp->th_x2, (u16)ntohs(tcp->th_win),
		 ntohs(tcp->th_sum), (u16)ntohs(tcp->th_urp),
		 (tcpoptinfo[0]!='\0') ? " " : "",
		 tcpoptinfo, ipinfo);
    }
  }
  else if (hdr.proto == IPPROTO_UDP && frag_off) {
    snprintf(protoinfo, sizeof(protoinfo), "UDP %s:?? > %s:?? fragment %s (incomplete)",
	     srchost, dsthost, ipinfo);
  }
  else if (hdr.proto == IPPROTO_UDP) {
    udp = (struct udp_hdr*)data;
    if (detail == LOW_DETAIL)
      snprintf(protoinfo, sizeof(protoinfo), "UDP %s:%hu > %s:%hu %s",
	       srchost, (u16)ntohs(udp->srcport), dsthost, (u16)ntohs(udp->dstport),
	       ipinfo);
    else if (detail == MEDIUM_DETAIL)
      snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%hu > %s:%hu csum=0x%04X] IP [%s]",
	       srchost, (u16)ntohs(udp->srcport), dsthost, (u16)ntohs(udp->dstport), ntohs(udp->check),
	       ipinfo);
    else if (detail == HIGH_DETAIL)
      snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%hu > %s:%hu len=%hu csum=0x%04X] IP [%s]",
	       srchost, (u16)ntohs(udp->srcport), dsthost, (u16)ntohs(udp->dstport),
	       (u16)ntohs(udp->len), ntohs(udp->check),
	       ipinfo);
  }
  else if (hdr.proto == IPPROTO_SCTP && frag_off) {
    snprintf(protoinfo, sizeof(protoinfo), "SCTP %s:?? > %s:?? fragment %s (incomplete)",
	     srchost, dsthost, ipinfo);
  }
  else if (hdr.proto == IPPROTO_SCTP) {
    sctp = (struct sctp_hdr*)data;
    if (detail == LOW_DETAIL)
      snprintf(protoinfo, sizeof(protoinfo), "SCTP %s:%hu > %s:%hu %s",
	       srchost, (u16)ntohs(sctp->srcport), dsthost, (u16)ntohs(sctp->dstport),
	       ipinfo);
    else if (detail == MEDIUM_DETAIL)
      snprintf(protoinfo, sizeof(protoinfo), "SCTP [%s:%hu > %s:%hu csum=0x%08x] IP [%s]",
	       srchost, (u16)ntohs(sctp->srcport), dsthost, (u16)ntohs(sctp->dstport), ntohl(sctp->check),
	       ipinfo);
    else if (detail == HIGH_DETAIL)
      snprintf(protoinfo, sizeof(protoinfo), "SCTP [%s:%hu > %s:%hu vtag=%lu csum=0x%08x] IP [%s]",
	       srchost, (u16)ntohs(sctp->srcport), dsthost, (u16)ntohs(sctp->dstport),
	       (unsigned long) ntohl(sctp->vtag), ntohl(sctp->check),
	       ipinfo);
  }
  else if (hdr.proto == IPPROTO_ICMP && frag_off) {
    snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s fragment %s (incomplete)",
	     srchost, dsthost, ipinfo);
  }
  else if (hdr.proto == IPPROTO_ICMP) {
    struct ip4_hdr *ip2;
    char *ip2dst;
    char auxbuff[128];
    struct icmp_packet{
      u8 type;
      u8 code;
      u16 checksum;
      u8 data[128];
    }*icmppkt;
    struct ppkt {
      u8 type;
      u8 code;
      u16 checksum;
      u16 id;
      u16 seq;
    } *ping = NULL;
    struct icmp_redir{
      u8 type;
      u8 code;
      u16 checksum;
      u32 addr;
    } *icmpredir = NULL;
    struct icmp_router{
      u8 type;
      u8 code;
      u16 checksum;
      u8 addrs;
      u8 addrlen;
      u16 lifetime;
    } *icmprouter = NULL;
    struct icmp_param{
      u8 type;
      u8 code;
      u16 checksum;
      u8 pnt;
      u8 unused;
      u16 unused2;
    } *icmpparam = NULL;
    struct icmp_tstamp{
      u8 type;
      u8 code;
      u16 checksum;
      u16 id;
      u16 seq;
      u32 orig;
      u32 recv;
      u32 trans;
    } *icmptstamp = NULL;
    struct icmp_amask{
      u8 type;
      u8 code;
      u16 checksum;
      u16 id;
      u16 seq;
      u32 mask;
    } *icmpmask = NULL;

    unsigned pktlen = 8;
    if (pktlen > datalen)
      goto icmpbad;

    ping = (struct ppkt*)data;
    icmppkt = (struct icmp_packet*)data;

    switch(icmppkt->type) {
      case 0:
        strcpy(icmptype, "Echo reply");
        snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (unsigned short) ntohs(ping->id), (unsigned short) ntohs(ping->seq));
        break;
      case 3:
        ip2 = (struct ip4_hdr *) (data + 8);
        pktlen += MAX( (ip2->ihl * 4), 20);
        if (pktlen > datalen) {
          if (datalen == 8) {
            snprintf(icmptype, sizeof icmptype, "Destination unreachable%s",
              (detail!=LOW_DETAIL)? " (original datagram missing)" : "");
          }else {
            snprintf(icmptype, sizeof icmptype, "Destination unreachable%s",
              (detail!=LOW_DETAIL)? " (part of original datagram missing)" : "");
          }
          goto icmpbad;
        }
        if ((ip2->version != 4) || ((ip2->ihl * 4) < 20) || ((ip2->ihl * 4) > 60)) {
          snprintf(icmptype, sizeof icmptype, "Destination unreachable (bogus original datagram)");
          goto icmpbad;
        }else {
          if (pktlen + 8 < datalen) {
            tcp = (struct tcp_hdr *) ((char *) ip2 + (ip2->ihl * 4));
            udp = (struct udp_hdr *) ((char *) ip2 + (ip2->ihl * 4));
            sctp = (struct sctp_hdr *) ((char *) ip2 + (ip2->ihl * 4));
          }
        }
	struct in_addr addr;
	addr.s_addr = htonl(ip2->dst);
        ip2dst = ncs_inet_ntoa(addr);
        switch (icmppkt->code) {
	  case 0:
            snprintf(icmptype, sizeof icmptype, "Network %s unreachable", ip2dst);
            break;
          case 1:
            snprintf(icmptype, sizeof icmptype, "Host %s unreachable", ip2dst);
            break;
          case 2:
            snprintf(icmptype, sizeof icmptype, "Protocol %u unreachable", ip2->proto);
            break;
          case 3:
            if (pktlen + 8 < datalen) {
              if (ip2->proto == IPPROTO_UDP && udp)
                snprintf(icmptype, sizeof icmptype, "Port %hu unreachable", (u16)ntohs(udp->dstport));
              else if (ip2->proto == IPPROTO_TCP && tcp)
                snprintf(icmptype, sizeof icmptype, "Port %hu unreachable", (u16)ntohs(tcp->th_dport));
              else if (ip2->proto == IPPROTO_SCTP && sctp)
                snprintf(icmptype, sizeof icmptype, "Port %hu unreachable", (unsigned short) ntohs(sctp->dstport));
              else
                snprintf(icmptype, sizeof icmptype, "Port unreachable (unknown protocol %u)", ip2->proto);
            }
            else
              strcpy(icmptype, "Port unreachable");
            break;
          case 4:
            strcpy(icmptype, "Fragmentation required");
            snprintf(icmpfields, sizeof(icmpfields), "Next-Hop-MTU=%d", icmppkt->data[2]<<8 | icmppkt->data[3]);
            break;
          case 5:
            strcpy(icmptype, "Source route failed");
            break;
          case 6:
            snprintf(icmptype, sizeof icmptype, "Destination network %s unknown", ip2dst);
            break;
          case 7:
            snprintf(icmptype, sizeof icmptype, "Destination host %s unknown", ip2dst);
            break;
          case 8:
            strcpy(icmptype, "Source host isolated");
            break;
          case 9:
            snprintf(icmptype, sizeof icmptype, "Destination network %s administratively prohibited", ip2dst);
            break;
          case 10:
            snprintf(icmptype, sizeof icmptype, "Destination host %s administratively prohibited", ip2dst);
            break;
          case 11:
            snprintf(icmptype, sizeof icmptype, "Network %s unreachable for TOS", ip2dst);
            break;
          case 12:
            snprintf(icmptype, sizeof icmptype, "Host %s unreachable for TOS", ip2dst);
            break;
          case 13:
            strcpy(icmptype, "Communication administratively prohibited by filtering");
            break;
          case 14:
            strcpy(icmptype, "Host precedence violation");
            break;
          case 15:
            strcpy(icmptype, "Precedence cutoff in effect");
            break;
          default:
            strcpy(icmptype, "Destination unreachable (unknown code)");
            break;
        }
        break;
      case 4:
        strcpy(icmptype, "Source quench");
        break;
      case 5:
        if (ping->code == 0)
          strcpy(icmptype, "Network redirect");
        else if (ping->code == 1)
          strcpy(icmptype, "Host redirect");
        else
          strcpy(icmptype, "Redirect (unknown code)");
        icmpredir = (struct icmp_redir *) icmppkt;
        ncs_inet_ntop(AF_INET, &icmpredir->addr, auxbuff, sizeof(auxbuff));
        snprintf(icmpfields, sizeof(icmpfields), "addr=%s", auxbuff);
        break;
      case 8:
        strcpy(icmptype, "Echo request");
        snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (u16)ntohs(ping->id), (u16)ntohs(ping->seq));
        break;
      case 9:
        if (icmppkt->code == 16)
          strcpy(icmptype, "Router advertisement (Mobile Agent Only)");
        else
          strcpy(icmptype, "Router advertisement");
        icmprouter = (struct icmp_router *) icmppkt;
        snprintf(icmpfields, sizeof(icmpfields), "addrs=%u addrlen=%u lifetime=%hu",
		 icmprouter->addrs,
		 icmprouter->addrlen,
		 (u16)ntohs(icmprouter->lifetime));
        break;
      case 10:
        strcpy(icmptype, "Router solicitation");
        break;
      case 11:
        if (icmppkt->code == 0)
          strcpy(icmptype, "TTL=0 during transit");
        else if (icmppkt->code == 1)
          strcpy(icmptype, "TTL=0 during reassembly");
        else
          strcpy(icmptype, "TTL exceeded (unknown code)");
        break;
      case 12:
        if (ping->code == 0)
          strcpy(icmptype, "Parameter problem (pointer indicates error)");
        else if (ping->code == 1)
          strcpy(icmptype, "Parameter problem (option missing)");
        else if (ping->code == 2)
          strcpy(icmptype, "Parameter problem (bad length)");
        else
          strcpy(icmptype, "Parameter problem (unknown code)");
        icmpparam = (struct icmp_param *) icmppkt;
        snprintf(icmpfields, sizeof(icmpfields), "pointer=%d", icmpparam->pnt);
        break;
      case 13:
      case 14:
        snprintf(icmptype, sizeof(icmptype), "Timestamp %s", (icmppkt->type == 13)? "request" : "reply");
        icmptstamp = (struct icmp_tstamp *) icmppkt;
        snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu orig=%lu recv=%lu trans=%lu",
          (u16)ntohs(icmptstamp->id), (u16)ntohs(icmptstamp->seq),
          (unsigned long) ntohl(icmptstamp->orig),
          (unsigned long) ntohl(icmptstamp->recv),
          (unsigned long) ntohl(icmptstamp->trans));
        break;
      case 15:
        strcpy(icmptype, "Information request");
        snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (u16)ntohs(ping->id), (u16)ntohs(ping->seq));
        break;
      case 16:
        strcpy(icmptype, "Information reply");
        snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (u16)ntohs(ping->id), (u16)ntohs(ping->seq));
        break;
      case 17:
      case 18:
        snprintf(icmptype, sizeof(icmptype), "Address mask %s", (icmppkt->type == 17)? "request" : "reply");
        icmpmask = (struct icmp_amask *) icmppkt;
        ncs_inet_ntop(AF_INET, &icmpmask->mask, auxbuff, sizeof(auxbuff));
        snprintf(icmpfields, sizeof(icmpfields), "id=%u seq=%u mask=%s",
            (u16)ntohs(ping->id), (u16)ntohs(ping->seq), auxbuff);
        break;
      case 30:
        strcpy(icmptype, "Traceroute");
        break;
      case 37:
        strcpy(icmptype, "Domain name request");
        break;
      case 38:
        strcpy(icmptype, "Domain name reply");
        break;
      case 40:
        strcpy(icmptype, "Security failures");
        break;
      default:
        strcpy(icmptype, "Unknown type"); break;
        break;
    }
    if (pktlen > datalen) {
icmpbad:
      if (ping) {
	snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s %s (type=%d/code=%d) %s",
		 srchost, dsthost, icmptype, ping->type, ping->code, ipinfo);
      }
      else {
	snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s [??] %s",
		 srchost, dsthost, ipinfo);
      }
    }
    else {
      if (ping)
	sprintf(icmpinfo,"type=%d/code=%d", ping->type, ping->code);
      else
	strncpy(icmpinfo,"type=?/code=?", sizeof(icmpinfo));
      
      snprintf(protoinfo, sizeof(protoinfo), "ICMP [%s > %s %s (%s) %s] IP [%s]",
	       srchost, dsthost, icmptype, icmpinfo, icmpfields, ipinfo);
    }
  }
  else if (hdr.proto == IPPROTO_ICMPV6) {
    if (datalen > sizeof(icmp6h_t)) {
      const icmp6h_t *icmpv6;
      icmpv6 = (icmp6h_t*) data;
      snprintf(protoinfo, sizeof(protoinfo), "ICMPv6 (%d) %s > %s (type=%d/code=%d) %s",
	       hdr.proto, srchost, dsthost,
	       icmpv6->type, icmpv6->code, ipinfo);
    }
    else {
      snprintf(protoinfo, sizeof(protoinfo), "ICMPv6 (%d) %s > %s (type=?/code=?) %s",
	       hdr.proto, srchost, dsthost, ipinfo);
    }
  }
  else {
    const char *hdrstr;
    hdrstr = read_util_nexthdrtoa(hdr.proto, 1);
    if (hdrstr == NULL || *hdrstr == '\0')
      snprintf(protoinfo, sizeof(protoinfo), "Unknown protocol (%d) %s > %s: %s",
	       hdr.proto, srchost, dsthost, ipinfo);
    else
      snprintf(protoinfo, sizeof(protoinfo), "%s (%d) %s > %s: %s",
	       hdrstr, hdr.proto, srchost, dsthost, ipinfo);
  }
  
  return protoinfo;
}
