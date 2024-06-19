#include "../ncsnet/raw.h"
#include "../ncsnet/sctp.h"
#include "../ncsnet/icmp.h"

int main(void)
{
  char errbuf[ERRBUF_MAXLEN];
  size_t pktlen = 0;
  u8 *res, *res1;
  u8 *pkt;
  u32 pktlen_;
  size_t res1len;

  /* ECHO MESSAGE */
  res = frmbuild(&pktlen, errbuf, "u16(%hu)", htons(random_u16())); /* add id */
  res = frmbuild_add(&pktlen, res, errbuf, "u16(%hu)", htons(1));   /* add seq */
  res1 = frmbuild(&res1len, errbuf, "str(kek)");
  res = frmbuild_addfrm(res1, &res1len, res, pktlen, errbuf);
  pktlen = res1len;
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
