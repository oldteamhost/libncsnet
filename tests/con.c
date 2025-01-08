#include <stdio.h>

#include "../ncsnet/tcp.h"

int main(void)
{
  tcp_info_t info;
  tcp_t *t;

  info.srcport=random_srcport();
  info.port=80;
  info.family=4;
  ip4t_fill(&info.srcip4, 192, 168, 1, 37);
  ip4t_fill(&info.ip4, 142, 250, 74, 110);
  mact_fill(&info.dst, 0x04, 0xbf, 0x6d, 0x0d, 0x3a, 0x50);
  mact_fill(&info.src, 0x40, 0xb0, 0x76, 0x47, 0x8f, 0x9a);

  t=tcp_open("enp7s0", to_ns(1000));
  tcp_bind(t, &info);
  tcp_handshake(t);
  tcp_close(t);

  return 0;
}
