#include "../ncsnet/udp.h"
#include "../ncsnet/tcp.h"
#include "../ncsnet/igmp.h"

int main(void)
{
  int fd;
  
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  udp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.34"), ncs_inet_addr("173.194.222.138"), 121, random_u16(), NULL, 0, random_srcport(), 80, false, "ksjdf", 0, false);
  
  tcp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.34"), ncs_inet_addr("173.194.222.138"), 121, false, NULL, 0, random_srcport(), 80, random_u32(), 0, 0, TCP_FLAG_SYN,
		1024, 0, NULL, 0, "kek", 0, false);
  igmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.34"), ncs_inet_addr("173.194.222.138"), 121, false, NULL, 0, random_u16(),
		 0, IGMP_HOST_MEMBERSHIP_QUERY, 0, NULL, 0, 0, false);

  close(fd);
  return 0;
}
