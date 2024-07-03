#include <stdio.h>
#include "../ncsnet/icmp.h"
#include "../ncsnet/eth.h"
#include "../ncsnet/mac.h"
#include "../ncsnet/readpkt.h"
#include "../ncsnet/linuxread.h"

int main(void)
{
  size_t msglen = 0;
  u8 *msg;
  int fd;
  linuxread_t *lr;
  struct sockaddr_in src;
  
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  lr = linuxread_open(to_ns(1000));
  if (!lr)
    puts("Not support???");
  else
    puts("aeee");

  memset(&src, 0, sizeof(src));
  src.sin_family = AF_INET;
  src.sin_addr.s_addr = ncs_inet_addr("173.194.222.138");

  linuxread_filter(lr, IPPROTO_ICMP, (struct sockaddr_storage*)&src);
    
  msg = icmp4_msg_echo_build(random_u16(), 10, "kek", &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.36"),
		 src.sin_addr.s_addr, 121, random_u16(),
		 0, false, NULL, 0, ICMP4_ECHO, 0, msg,
		 msglen, 0, false);

  u8 *res;
  res = (u8*)calloc(4096, sizeof(u8));

  linuxread_live(lr, &res, 4096);
  linuxread_close(lr);
  free(res);
  
  /*
  msg = icmp4_msg_info_build(43, 1, &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.34"),
		 ncs_inet_addr("173.194.222.138"), 121, random_u16(),
		 0, false, NULL, 0, ICMP4_INFO, 0, msg,
		 msglen, 0, false);
  
  msg = icmp4_msg_tstamp_build(5555, 1, 324234, 3324, 4353, &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.34"),
		 ncs_inet_addr("173.194.222.138"), 121, random_u16(),
		 0, false, NULL, 0, ICMP4_TSTAMP, 0, msg,
		 msglen, 0, false);

  msg = icmp4_msg_needfrag_build(123, NULL, 0, &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.34"),
		 ncs_inet_addr("173.194.222.138"), 121, random_u16(),
		 0, false, NULL, 0, ICMP4_UNREACH, ICMP4_UNREACH_NEEDFRAG, msg,
		 msglen, 0, false);

  msg = icmp4_msg_mask_build(123, 1, ncs_inet_addr("192.168.1.38"), &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.34"),
		 ncs_inet_addr("173.194.222.138"), 121, random_u16(),
		 0, false, NULL, 0, ICMP4_MASK, 0, msg,
		 msglen, 0, false);
  */
  free(msg);
  close(fd);
  
  return 0;
}
