#include <stdio.h>

#include "../ncsnet/tcp.h"

int main(void)
{
  tcp_info_t src, dst;
  mac_t msrc, mdst;
  size_t ethlen;
  tcp_t *t;
  u8 *eth;

  src.port=random_srcport();
  dst.port=80;
  src.family=4;
  dst.family=4;
  ip4t_fill(&src.ip4, 192, 168, 1, 37);
  ip4t_fill(&dst.ip4, 142, 250, 74, 110);

  mact_fill(&mdst, 0x04, 0xbf, 0x6d, 0x0d, 0x3a, 0x50);
  mact_fill(&msrc, 0x40, 0xb0, 0x76, 0x47, 0x8f, 0x9a);
  eth=eth_build(msrc, mdst, ETH_TYPE_IPV4, NULL, 0, &ethlen);

  t=tcp_open("enp7s0", to_ns(1000));
  tcp_add_link(t, eth, ethlen);
  tcp_handshake(t, &src, &dst);
  tcp_close(t);

  return 0;
}
