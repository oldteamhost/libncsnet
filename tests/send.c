#include "../ncsnet/udp.h"

int main(void)
{
  int fd;
  size_t optlen;
  u8 *res;


  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  udp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.34"), ncs_inet_addr("173.194.222.138"), 121, random_u16(), NULL, 0, random_srcport(), 80, false, (u8*)"ka", 2, 0, false);


  res = tcp_opt_mss_build(16, &optlen);
  // res = tcp_opt_noop_build(&optlen);
  // res = tcp_opt_wscale_build(10, &optlen);
  // res = tcp_opt_sackpr_build(&optlen);
  // res = tcp_opt_tstamp_build(8, 8, &optlen);
  res = frmbuild_add(&optlen, res, NULL, "u8(1)");
  res = frmbuild_add(&optlen, res, NULL, "u8(1)");
  res = frmbuild_add(&optlen, res, NULL, "u8(2), u8(4), u16(%hu)", htons(230));
  

  close(fd);
  return 0;
}
