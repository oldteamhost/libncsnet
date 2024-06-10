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

typedef struct protospec
{
  bool ip4, tcp, icmp4,
    sctp, igmp, udp, ip6, icmp6;
} protocols;

typedef struct opthdr
{
  const char *key, *value;
} option;

typedef struct tmpip4_hdr
{
  const char *opt;
  int proto, ttl, ipid, tos;
  u32 src, dst;
  bool df, badsum;
  const char *data;
  int datalen;
} tmpip4;

typedef struct tmptcp_hdr
{
  int srcport, dstport, reserved, win, urp;
  size_t seq, acknum;
  const char *opt, *data;
  int datalen;
  u8 flags;
} tmptcp;

typedef struct tmpicmp4_hdr
{
  int code, type, icmpid, seq;
  const char *data;
  int datalen;
} tmpicmp4;

typedef struct tmpudp_hdr
{
  int srcport, dstport;
  const char *data;
  int datalen;
} tmpudp;

typedef struct tmpigmp_hdr
{
  int type, code;
  const char *data;
  int datalen;
} tmpigmp;

static void remove_token(char *proto, char *token)
{
  char *pos, *end;
  pos = strstr(proto, token);
  if (pos) {
    end = pos + strlen(token);
    if (*end == *NCSRAWBUILD_TOKEN_SPEC_DEL)
      end++;
    memmove(pos, end, strlen(end) + 1);
  }
}

static protocols ncsbuild_parseproto(char *proto, char *errbuf)
{
  char protobuf[NCSRAWBUILD_PROTOS_MAXLEN];
  bool advanced, addr;
  protocols res;
  char *token;

  advanced = addr = false;
  memset(&res, 0, sizeof(protocols));
  strncpy(protobuf, proto, sizeof(protobuf));
  protobuf[sizeof(protobuf) - 1] = '\0';

  token = strtok(protobuf, NCSRAWBUILD_TOKEN_SPEC_DEL);
  while(token) {
#define C(ident) (strcmp(token, (ident)) == 0)
#define CA(token) if (advanced) {					\
      snprintf(errbuf, NCSRAWBUILD_ERRBUF_MAXLEN,				\
          "error protocol, to the address protocol, only 1 can be an additional 1 (%s)", token); \
      return res;							\
    }									\
    else								\
      advanced = true;							\
    
    if (C(NCSRAWBUILD_TOKEN_IP4_IDENT) || C(NCSRAWBUILD_TOKEN_IP4_IDENT_1)) {
      res.ip4 = true;
      addr = true;
      remove_token(proto, token);
    }
    else if (C(NCSRAWBUILD_TOKEN_IP6_IDENT)) {
      if (res.ip4) {
	snprintf(errbuf, NCSRAWBUILD_ERRBUF_MAXLEN,
            "error protocol, you cannot address ip4 and ip6 in the same packet at the same time, (%s)", token);
	return res;
      }
      res.ip6 = true;
      addr = true;
      remove_token(proto, token);
    }
    else if (C(NCSRAWBUILD_TOKEN_TCP_IDENT)) {
      CA(token)
      res.tcp = true;
      remove_token(proto, token);
    }
    else if (C(NCSRAWBUILD_TOKEN_ICMP6_IDENT)) {
      CA(token)
      res.icmp6 = true;
      remove_token(proto, token);
    }    
    else if (C(NCSRAWBUILD_TOKEN_ICMP4_IDENT) || C(NCSRAWBUILD_TOKEN_ICMP4_IDENT_1)) {
      CA(token)
      res.icmp4 = true;
      remove_token(proto, token);
    }
    else if (C(NCSRAWBUILD_TOKEN_UDP_IDENT)) {
      CA(token)
      res.udp = true;
      remove_token(proto, token);
    }
    else if (C(NCSRAWBUILD_TOKEN_SCTP_IDENT)) {
      CA(token)
      res.sctp = true;
      remove_token(proto, token);
    }
    else if (C(NCSRAWBUILD_TOKEN_IGMP_IDENT)) {
      CA(token)
      res.igmp = true;
      remove_token(proto, token);
    }        
#undef C
#undef CA
    token = strtok(NULL, NCSRAWBUILD_TOKEN_SPEC_DEL);
  }
  if (!addr)
    snprintf(errbuf, NCSRAWBUILD_ERRBUF_MAXLEN,
      "error protocol, you didn't specify any address protocols");
  
  return res;
}

static size_t remove_spaces(char *str)
{
  char *i = str;
  char *j = str;
  size_t count = 0;
  while (*j != '\0') {
    if (*j != ' ') {*i = *j; i++;}
    else
      count++;
    j++;
  }
  *i = '\0';
  return count;
}

static option ncsbuild_parseoption(char *str, char *errbuf)
{
  option res = {NULL, NULL};
  char *delimiter = strchr(str, NCSRAWBUILD_TOKEN_OPT_DEL);
  if (delimiter) {
    *delimiter = '\0';
    res.key = str;
    res.value = delimiter + 1;
  }
  else
    snprintf(errbuf, NCSRAWBUILD_ERRBUF_MAXLEN,
	     "error opts, not found (%s)", str);
  return res;
}

static bool ncsbuild_protocheck(const char *key, int proto)
{
#define C(ident) (strcmp(key, (ident)) == 0)

  switch (proto) {
  case NCSRAWBUILD_PROTO_IP4: {
    if (C(NCSRAWBUILD_IP4HDR_DF)    ||
	C(NCSRAWBUILD_IP4HDR_SRC)   ||
	C(NCSRAWBUILD_IP4HDR_DST)   ||
	C(NCSRAWBUILD_IP4HDR_PROTO) ||
	C(NCSRAWBUILD_IP4HDR_TTL)   ||
	C(NCSRAWBUILD_IP4HDR_ID)    ||
	C(NCSRAWBUILD_IP4HDR_TOS)   ||
	C(NCSRAWBUILD_HDR_BADSUM)   ||	
	C(NCSRAWBUILD_IP4HDR_OPT))
      return true;
    break;
  }
  case NCSRAWBUILD_PROTO_TCP: {
    if (C(NCSRAWBUILD_TCPHDR_SRCPORT)  ||
      C(NCSRAWBUILD_TCPHDR_DSTPORT)    ||
      C(NCSRAWBUILD_TCPHDR_SEQ)        ||
      C(NCSRAWBUILD_TCPHDR_ACK)        ||
      C(NCSRAWBUILD_TCPHDR_RESERVED)   ||
      C(NCSRAWBUILD_TCPHDR_WINDOW)     ||
      C(NCSRAWBUILD_TCPHDR_URP)        ||
      C(NCSRAWBUILD_TCPHDR_OPT)        ||
      C(NCSRAWBUILD_TCPHDR_FLAGS)      ||	
      C(NCSRAWBUILD_TCPHDR_DATA))
      return true;
    break;
  }
  case NCSRAWBUILD_PROTO_UDP: {
    if (C(NCSRAWBUILD_UDPHDR_SRCPORT) ||
	C(NCSRAWBUILD_UDPHDR_DSTPORT) ||
	C(NCSRAWBUILD_UDPHDR_DATA))
      return true;
    break;
  }
  case NCSRAWBUILD_PROTO_ICMP4: {
    if (C(NCSRAWBUILD_ICMP4HDR_TYPE)  ||
	C(NCSRAWBUILD_ICMP4HDR_CODE)  ||
	C(NCSRAWBUILD_ICMP4HDR_ID)    ||
	C(NCSRAWBUILD_ICMP4HDR_SEQ)   ||
	C(NCSRAWBUILD_ICMP4HDR_DATA))
      return true;
    break;
  }
  case NCSRAWBUILD_PROTO_IGMP: {
    if (C(NCSRAWBUILD_IGMPHDR_TYPE)    ||
	C(NCSRAWBUILD_IGMPHDR_CODE)    ||
	C(NCSRAWBUILD_IGMPHDR_DATA))
      return true;
    break;
  }
#undef C
  };

  return false;
}

static bool ncsbuild_checkrange(size_t current, size_t min, size_t max, const char *hdr, const char *opt, char *errbuf)
{
  if (current > max || current < min) {
    snprintf(errbuf, NCSRAWBUILD_ERRBUF_MAXLEN,
	     "error %s %s, its range (%ld-%ld) (current %ld)", hdr, opt, min, max, current);
    return false;
  }
  return true;
}

#define C(ident) (strcmp(opt.key, (ident)) == 0)
static void ncsbuild_updtip4(tmpip4 *ip4, option opt, char *errbuf)
{
  int tmp;
  if (C(NCSRAWBUILD_IP4HDR_TTL)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 1, UCHAR_MAX, "ip4hdr", NCSRAWBUILD_IP4HDR_TTL, errbuf))
      return;
    ip4->ttl = tmp;
    return;
  }
  if (C(NCSRAWBUILD_IP4HDR_PROTO)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, UCHAR_MAX, "ip4hdr", NCSRAWBUILD_IP4HDR_PROTO, errbuf))
      return;
    ip4->proto = tmp;
  }
  if (C(NCSRAWBUILD_HDR_BADSUM)) {
    tmp = atoi(opt.value);
    ip4->badsum = tmp;
  }  
  if (C(NCSRAWBUILD_IP4HDR_ID)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, USHRT_MAX, "ip4hdr", NCSRAWBUILD_IP4HDR_ID, errbuf))
      return;
    ip4->ipid = tmp;
  }
  if (C(NCSRAWBUILD_IP4HDR_TOS)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, UCHAR_MAX, "ip4hdr", NCSRAWBUILD_IP4HDR_TOS, errbuf))
      return;
    ip4->tos = tmp;
  }
  if (C(NCSRAWBUILD_IP4HDR_DF))
    ip4->df = atoi(opt.value);
  if (C(NCSRAWBUILD_IP4HDR_OPT))
    ip4->opt = opt.value;
  if (C(NCSRAWBUILD_IP4HDR_SRC)) {
    char tmp1[16];
    if (strcmp(NCSRAWBUILD_TOKEN_LOCALIP, opt.value) == 0 || strcmp(NCSRAWBUILD_TOKEN_LOCALIP_1, opt.value) == 0) {
      char *tmp2 = NULL;
      tmp2 = ip4_util_strsrc();
      if (!tmp2)
	return;
      strcpy(tmp1, tmp2);
      free(tmp2);
      ip4->src = ncs_inet_addr(tmp1);
    }
    else {
      if (getipv4(opt.value, tmp1, 16) == 0)
	ip4->src = ncs_inet_addr(tmp1);
      else {
	snprintf(errbuf, NCSRAWBUILD_ERRBUF_MAXLEN,
		 "error ip4hdr %s, failed resolv %s", NCSRAWBUILD_IP4HDR_SRC, opt.value);
	return;
      }
    }
  }
  if (C(NCSRAWBUILD_IP4HDR_DST)) {
    char tmp1[16];
    if (getipv4(opt.value, tmp1, 16) == 0)
      ip4->dst = ncs_inet_addr(tmp1);
    else {
      snprintf(errbuf, NCSRAWBUILD_ERRBUF_MAXLEN,
	       "error ip4hdr %s, failed resolv %s", NCSRAWBUILD_IP4HDR_DST, opt.value);
      return;
    }
  }
}

static void ncsbuild_updttcp(tmptcp *tcp, option opt, char *errbuf)
{
  size_t tmp;
  if (C(NCSRAWBUILD_TCPHDR_SRCPORT)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, USHRT_MAX, "tcphdr", NCSRAWBUILD_TCPHDR_SRCPORT, errbuf))
      return;
    tcp->srcport = tmp;
  }
  if (C(NCSRAWBUILD_TCPHDR_DSTPORT)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, USHRT_MAX, "tcphdr", NCSRAWBUILD_TCPHDR_DSTPORT, errbuf))
      return;
    tcp->dstport = tmp;
  }
  if (C(NCSRAWBUILD_TCPHDR_SEQ)) {
    sscanf(opt.value, "%zu", &tmp);
    if (!ncsbuild_checkrange(tmp, 0, UINT_MAX, "tcphdr", NCSRAWBUILD_TCPHDR_SEQ, errbuf))
      return;
    tcp->seq = tmp;
  }
  if (C(NCSRAWBUILD_TCPHDR_ACK)) {
    sscanf(opt.value, "%zu", &tmp);
    if (!ncsbuild_checkrange(tmp, 0, UINT_MAX, "tcphdr", NCSRAWBUILD_TCPHDR_ACK, errbuf))
      return;
    tcp->acknum = tmp;
  }
  if (C(NCSRAWBUILD_TCPHDR_RESERVED)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, UCHAR_MAX, "tcphdr", NCSRAWBUILD_TCPHDR_RESERVED, errbuf))
      return;
    tcp->reserved = tmp;
  }
  if (C(NCSRAWBUILD_TCPHDR_WINDOW)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, USHRT_MAX, "tcphdr", NCSRAWBUILD_TCPHDR_WINDOW, errbuf))
      return;
    tcp->win = tmp;
  }
  if (C(NCSRAWBUILD_TCPHDR_URP)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, USHRT_MAX, "tcphdr", NCSRAWBUILD_TCPHDR_URP, errbuf))
      return;
    tcp->urp = tmp;
  }
  if (C(NCSRAWBUILD_TCPHDR_DATA)) {
    tcp->data = opt.value;
    tcp->datalen = strlen(opt.value);
  }
  if (C(NCSRAWBUILD_TCPHDR_OPT))
    tcp->opt = opt.value;
  if (C(NCSRAWBUILD_TCPHDR_FLAGS)) {
    struct tcp_flags tf;
    memset(&tf, 0, sizeof(struct tcp_flags));
    tf = tcp_util_str_setflags(opt.value);
    tcp->flags = tcp_util_setflags(&tf);
  }
}

static void ncsbuild_updticmp4(tmpicmp4 *icmp4, option opt, char *errbuf)
{
  int tmp;

  if (C(NCSRAWBUILD_ICMP4HDR_CODE)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, UCHAR_MAX, "icmp4hdr", NCSRAWBUILD_ICMP4HDR_CODE, errbuf))
      return;
    icmp4->code = tmp;
  }
  if (C(NCSRAWBUILD_ICMP4HDR_TYPE)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, UCHAR_MAX, "icmp4hdr", NCSRAWBUILD_ICMP4HDR_TYPE, errbuf))
      return;
    icmp4->type = tmp;
  }
  if (C(NCSRAWBUILD_ICMP4HDR_ID)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, USHRT_MAX, "icmp4hdr", NCSRAWBUILD_ICMP4HDR_ID, errbuf))
      return;
    icmp4->icmpid = tmp;
  }
  if (C(NCSRAWBUILD_ICMP4HDR_SEQ)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, USHRT_MAX, "icmp4hdr", NCSRAWBUILD_ICMP4HDR_SEQ, errbuf))
      return;
    icmp4->seq = tmp;
  }    
  if (C(NCSRAWBUILD_ICMP4HDR_DATA)) {
    icmp4->data = opt.value;
    icmp4->datalen = strlen(opt.value);
  }
}

static void ncsbuild_updtudp(tmpudp *udp, option opt, char *errbuf)
{
  int tmp;
  if (C(NCSRAWBUILD_UDPHDR_SRCPORT)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, USHRT_MAX, "udphdr", NCSRAWBUILD_UDPHDR_SRCPORT, errbuf))
      return;
    udp->srcport = tmp;
  }
  if (C(NCSRAWBUILD_UDPHDR_DSTPORT)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, USHRT_MAX, "udphdr", NCSRAWBUILD_UDPHDR_DSTPORT, errbuf))
      return;
    udp->dstport = tmp;
  }  
  if (C(NCSRAWBUILD_UDPHDR_DATA)) {
    udp->data = opt.value;
    udp->datalen = strlen(opt.value);
  }
}

static void ncsbuild_updtigmp(tmpigmp *igmp, option opt, char *errbuf)
{
  int tmp;
  if (C(NCSRAWBUILD_IGMPHDR_CODE)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, UCHAR_MAX, "igmphdr", NCSRAWBUILD_IGMPHDR_CODE, errbuf))
      return;
    igmp->code = tmp;
  }
  if (C(NCSRAWBUILD_IGMPHDR_TYPE)) {
    tmp = atoi(opt.value);
    if (!ncsbuild_checkrange(tmp, 0, UCHAR_MAX, "igmphdr", NCSRAWBUILD_IGMPHDR_TYPE, errbuf))
      return;
    igmp->type = tmp;
  }
  if (C(NCSRAWBUILD_IGMPHDR_DATA)) {
    igmp->data = opt.value;
    igmp->datalen = strlen(opt.value);
  }
}

#undef C

static void to_uppercase(char *str)
{
  while (*str) {
    *str = toupper((unsigned char)*str);
    str++;
  }
}

void ncsraw_build(ncsraw_t *n, char *errbuf, const char *fmt, ...)
{
  char       buf[NCSRAWBUILD_FMT_MAXLEN];
  char      *token;
  tmpicmp4   icmp4;
  tmpigmp    igmp;
  option     tmp;
  tmptcp     tcp;
  tmpudp     udp;
  tmpip4     ip4;
  va_list    ap;
  protocols  p;
  
  memset(&ip4, 0, sizeof(tmpip4));
  memset(&tcp, 0, sizeof(tmptcp));
  memset(&icmp4, 0, sizeof(tmpicmp4));
  memset(&igmp, 0, sizeof(tmpigmp));  
  memset(&udp, 0, sizeof(tmpudp));      

  if (errbuf)
    *errbuf = '\0';
  else
    return;
  
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  to_lower(buf);
  remove_spaces(buf);
  p = ncsbuild_parseproto(buf, errbuf);
  if (*errbuf != '\0')
    return;
  if (*buf == '\0') {
    snprintf(errbuf, NCSRAWBUILD_ERRBUF_MAXLEN,
	     "error opts, they empty");
    return;
  }
  token = strtok(buf, NCSRAWBUILD_TOKEN_SPEC_DEL);
  while(token) {
    tmp = ncsbuild_parseoption(token, errbuf);
    if (*errbuf != '\0')
      return;
    if (!tmp.key || !tmp.value)
      goto next;
    if ((ncsbuild_protocheck(tmp.key, NCSRAWBUILD_PROTO_IP4)) && p.ip4) {
      if (*errbuf != '\0')
	return;
      else
	ncsbuild_updtip4(&ip4, tmp, errbuf);
      goto next;
    }
    if ((ncsbuild_protocheck(tmp.key, NCSRAWBUILD_PROTO_TCP)) && p.tcp) {
      if (*errbuf != '\0')
	return;
      else
	ncsbuild_updttcp(&tcp, tmp, errbuf);
      goto next;
    }
    if ((ncsbuild_protocheck(tmp.key, NCSRAWBUILD_PROTO_ICMP4)) && p.icmp4) {
      if (*errbuf != '\0')
	return;
      else
	ncsbuild_updticmp4(&icmp4, tmp, errbuf);
      goto next;
    }
    if ((ncsbuild_protocheck(tmp.key, NCSRAWBUILD_PROTO_UDP)) && p.udp) {
      if (*errbuf != '\0')
	return;
      else
	ncsbuild_updtudp(&udp, tmp, errbuf);
      goto next;
    }
    if ((ncsbuild_protocheck(tmp.key, NCSRAWBUILD_PROTO_IGMP)) && p.igmp) {
      if (*errbuf != '\0')
	return;
      else
	ncsbuild_updtigmp(&igmp, tmp, errbuf);
      goto next;
    }        
  next:
    token = strtok(NULL, NCSRAWBUILD_TOKEN_SPEC_DEL);
    continue;
  }

  if (p.ip4) {
    struct sockaddr_in *s = (struct sockaddr_in*)&n->dst_in;
    char *tmp;
    u8 ipopts[256];
    int ipoptslen, ipopts_first_hop_offset,
      ipopts_last_hop_offset;

    s->sin_family = AF_INET;
    s->sin_addr.s_addr = ip4.dst;
    memset(&ipopts, 0, sizeof(ipopts));
    
    if (ip4.opt){
      tmp = strdup(ip4.opt);
      if (tmp) {
	to_uppercase(tmp);
	ipoptslen = parse_ipopts(tmp, ipopts, sizeof(ipopts),
            &ipopts_first_hop_offset, &ipopts_last_hop_offset,
            errbuf, NCSRAWBUILD_ERRBUF_MAXLEN);
	free(tmp);
	if (*errbuf != '\0')
	  return;
      }
    }
    
    if (p.tcp) {
      n->pkt = tcp4_build_pkt(ip4.src, s->sin_addr.s_addr, ip4.ttl, ip4.ipid,
          ip4.tos, ip4.df, ipopts, ipoptslen, tcp.srcport, tcp.dstport, tcp.seq, tcp.acknum, tcp.reserved,
          tcp.flags, tcp.win, tcp.urp, NULL, 0, tcp.data, tcp.datalen, &n->pktlen, ip4.badsum);
      return;
    }
    else if (p.icmp4) {
      n->pkt = icmp4_build_pkt(ip4.src, s->sin_addr.s_addr, ip4.ttl, ip4.ipid,
          ip4.tos, ip4.df, ipopts, ipoptslen, icmp4.seq, icmp4.icmpid, icmp4.type, icmp4.code, icmp4.data,
          icmp4.datalen, &n->pktlen, ip4.badsum);
      return;
    }
    else if (p.udp) {
      n->pkt = udp4_build_pkt(ip4.src, s->sin_addr.s_addr, ip4.ttl, ip4.ipid, ip4.tos,
          ip4.df, ipopts, ipoptslen, udp.srcport, udp.dstport, udp.data, udp.datalen, &n->pktlen, ip4.badsum);
      return;
    }
    else if (p.igmp) {
      n->pkt = igmp4_build_pkt(ip4.src, s->sin_addr.s_addr, ip4.ttl, ip4.ipid, ip4.tos,
          ip4.df, ipopts, ipoptslen, igmp.type, igmp.code, igmp.data, igmp.datalen, &n->pktlen, ip4.badsum);
      return;
    }
    else {
      n->pkt = ip4_build(ip4.src, s->sin_addr.s_addr, ip4.proto, ip4.ttl, ip4.ipid, ip4.tos, ip4.df, ipopts,
			 ipoptslen, ip4.data, ip4.datalen, &n->pktlen);
    }
    
  }
  
}
