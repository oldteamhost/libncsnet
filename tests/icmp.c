#include <stdio.h>
#include "../ncsnet/icmp.h"

int main(void)
{
  u8 *icmp, *res, *msg;
  u32 pktlen = 0, len = 0;
  u16 msglen = 0;

  struct sockaddr_in d;
  d.sin_family = AF_INET;
  d.sin_addr.s_addr = ncs_inet_addr("173.194.222.138");

  /*

  msg = icmp4_msg_info_build(random_u16(), 1, &msglen);
  msg = icmp4_msg_tstamp_build(5555, 1, 324234, 3324, 4353, &msglen);
  msg = icmp4_msg_mask_build(123, 1, 98348, &msglen);
  msg = icmp4_msg_needfrag_build(123, NULL, 0, &msglen);
  */

  msg = icmp4_msg_echo_build(random_u16(), 1, "kek", 3, &msglen);
  icmp = icmp4_build(ICMP4_ECHO, 0, msg, msglen, &pktlen, false);
  printf("icmplen = %d\n", pktlen);

  
  res = ip4_build(ncs_inet_addr("192.168.1.38"), d.sin_addr.s_addr,
		  IPPROTO_ICMP, 121, random_u16(), 0, false, NULL, 0,
		  (char*)icmp, pktlen, &len);
  printf("iplen = %d\n", len);
  int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  printf("send= %d\n", ip4_send_raw(fd, &d, res, len));
  free(icmp);
  free(res);
  close(fd);

  
  return 0;
}
