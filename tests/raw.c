#include "../ncsnet/raw.h"
#include "../ncsnet/sctp.h"
#include "../ncsnet/icmp.h"

int main(void)
{
  char errbuf[ERRBUF_MAXLEN];
  size_t pktlen = 0;
  u8 *res;
  u8 *pkt;
  u32 pktlen_;

  res = build_frame(&pktlen, errbuf,
		    "u16(%hu), u16(%hu), str(kek)",
		    htons(random_u16()), htons(1));
  if (!res) {
    printf("errbuf = %s\n", errbuf);
    return -1;
  }

  pkt = icmp4_build_pkt(inet_addr("192.168.1.34"),
			inet_addr("173.194.222.138"),
			121, random_u16(), 0, false,
			NULL, 0, ICMP4_ECHO, 0, res,
			pktlen, &pktlen_, false);
  
  int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  struct sockaddr_in d;
  d.sin_family = AF_INET;
  d.sin_addr.s_addr = ncs_inet_addr("173.194.222.138");
  ip4_send_raw(fd, &d, pkt, pktlen_);

  free(pkt);    
  close(fd);
  
  free(res);
  
  return 0;
}
