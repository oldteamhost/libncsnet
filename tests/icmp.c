#include <stdio.h>
#include "../ncsnet/icmp.h"

int main(void)
{
  u16 msglen = 0;
  u8 *msg;
  int fd;

  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  
  msg = icmp4_msg_echo_build(random_u16(), 10, "kek", 3, &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.38"),
		 ncs_inet_addr("173.194.222.138"), 121, random_u16(),
		 0, false, NULL, 0, ICMP4_ECHO, 0, msg,
		 msglen, 0, false);

  msg = icmp4_msg_info_build(random_u16(), 1, &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.38"),
		 ncs_inet_addr("173.194.222.138"), 121, random_u16(),
		 0, false, NULL, 0, ICMP4_INFO, 0, msg,
		 msglen, 0, false);
  
  msg = icmp4_msg_tstamp_build(5555, 1, 324234, 3324, 4353, &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.38"),
		 ncs_inet_addr("173.194.222.138"), 121, random_u16(),
		 0, false, NULL, 0, ICMP4_TSTAMP, 0, msg,
		 msglen, 0, false);

  msg = icmp4_msg_needfrag_build(123, NULL, 0, &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.38"),
		 ncs_inet_addr("173.194.222.138"), 121, random_u16(),
		 0, false, NULL, 0, ICMP4_UNREACH, ICMP4_UNREACH_NEEDFRAG, msg,
		 msglen, 0, false);

  msg = icmp4_msg_mask_build(123, 1, 98348, &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.38"),
		 ncs_inet_addr("173.194.222.138"), 121, random_u16(),
		 0, false, NULL, 0, ICMP4_MASK, 0, msg,
		 msglen, 0, false);
  
  free(msg);
  close(fd);  
  return 0;
}
