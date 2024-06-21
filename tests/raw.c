#include "../ncsnet/raw.h"
#include "../ncsnet/sctp.h"
#include "../ncsnet/icmp.h"

static u8 *icmp4_msg(u16 id, u16 seq, const char *data, u16 datalen, size_t *msglen)
{
  u8 *res;
  res = frmbuild(msglen, NULL, "u16(%hu), u16(%hu))", htons(id), htons(seq));
  res = frmbuild_addfrm((u8*)data, (size_t)datalen, res, msglen, NULL);
  return res;
}

int main(void)
{
  size_t pktlen = 0;
  u8 *res;
  u8 *pkt;
  size_t pktlen_;

  //res = icmp4_msg(100, 1, NULL, 0, (size_t*)&pktlen);  
  res = icmp4_msg(100, 1, "123", 3, (size_t*)&pktlen);
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
