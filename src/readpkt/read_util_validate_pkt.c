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

#include <ncsnet/readpkt.h>

bool read_util_validate_tcp(const u8 *tcpc, unsigned len)
{
  const struct tcp_hdr *tcp = (struct tcp_hdr *) tcpc;
  unsigned hdrlen, optlen;

  hdrlen = tcp->th_off * 4;

  if (hdrlen > len || hdrlen < sizeof(struct tcp_hdr))
    return false;

  tcpc += sizeof(struct tcp_hdr);
  optlen = hdrlen - sizeof(struct tcp_hdr);

#define OPTLEN_IS(expected) do {					\
    if ((expected) == 0 || optlen < (expected) || hdrlen != (expected)) \
      return false;							\
    optlen -= (expected);						\
    tcpc += (expected);							\
  } while(0);
  while (optlen > 1) {
    hdrlen = *(tcpc + 1);
    switch (*tcpc) {
    case 0:
      return true;
    case 1:
      optlen--;
      tcpc++;
      break;
    case 2:
      OPTLEN_IS(4);
      break;
    case 3:
      OPTLEN_IS(3);
      break;
    case 4:
      OPTLEN_IS(2);
      break;
    case 5:
      if (!(hdrlen - 2) || ((hdrlen - 2) % 8))
        return false;
      OPTLEN_IS(hdrlen);
      break;
    case 8:
      OPTLEN_IS(10);
      break;
    case 14:
      OPTLEN_IS(3);
      break;
    default:
      OPTLEN_IS(hdrlen);
      break;
    }
  }

  if (optlen == 1)
    return (*tcpc == 0 || *tcpc == 1);
  assert(optlen == 0);
  return true;
#undef OPTLEN_IS
}

bool read_util_validate_pkt(const u8 *ipc, unsigned *len)
{
  const struct ip4_hdr *ip = (struct ip4_hdr*)ipc;
  const void *data;
  u32 datalen, iplen;
  u8 hdr;

  if (*len < 1)
    return false;

  if (ip->version == 4) {
    unsigned fragoff, iplen;

    datalen = *len;
    data = read_util_ip4getdata_up(ip, &datalen);
    if (!data)
      return false;

    iplen = ntohs(ip->totlen);

    fragoff = 8 * (ntohs(ip->off) & IP4_OFFMASK);
    if (fragoff)
      return false;

    if (*len > iplen)
      *len = iplen;
    hdr = ip->proto;
  }
  else if (ip->version == 6) {
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) ipc;
    
    datalen = *len;
    data = read_util_ip6getdata(ip6, &datalen, &hdr);
    if (data == NULL)
      return false;
    
    iplen = ntohs(ip6->IP6_PKTLEN);
    if (datalen > iplen)
      *len -= datalen - iplen;
  }
  else
    return false;

  switch (hdr) {
  case IPPROTO_TCP:
    if (datalen < sizeof(struct tcp_hdr))
      return false;
    if (!read_util_validate_tcp((u8 *)data, datalen))
      return false;
    break;
  case IPPROTO_UDP:
    if (datalen < sizeof(struct udp_hdr))
      return false;
    break;
  case IPPROTO_ICMP:
    if (datalen < ICMP4_LEN_MIN)
      return false;
    break    
  default:
    break;
  }
  
  return true;
}
