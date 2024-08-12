#include <stdio.h>
#include "../ncsnet/icmp.h"
#include "../ncsnet/eth.h"
#include "../ncsnet/mac.h"
#include "../ncsnet/linuxread.h"
#include "../ncsnet/trace.h"
struct sockaddr_in src;

#include <linux/if_ether.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

bool callback(u8 *frame, size_t frmlen)
{
  struct sockaddr_in dst;
  ip4h_t *ip;
  
  ip=(ip4h_t*)(frame + ETH_HDR_LEN);
  dst.sin_addr.s_addr=ip->src;
  if (dst.sin_addr.s_addr==src.sin_addr.s_addr)
    return true;
  return false;
}

static void tvsub(struct timeval *out, struct timeval *in)
{
  if ((out->tv_usec-=in->tv_usec)<0) {
    out->tv_sec--;
    out->tv_usec+=1000000;
  }
  out->tv_sec-=in->tv_sec;
}

int main(void)
{
  size_t frmlen=0, msglen=0, ethfrmlen=0;
  u8 *frame=NULL, *msg=NULL, *ethfrm=NULL;

  eth_t *eth;
  eth=eth_open("enp7s0");

  msg = icmp4_msg_echo_build(7, 1, NULL, &msglen);
  frame=icmp4_build_pkt(ncs_inet_addr("192.168.1.33"),ncs_inet_addr("108.177.14.102"), 64,
      33375, 0, 1, NULL, 0, 8, 0, msg, msglen, &frmlen, 0);

  mac_t src_, dst_;
  mac_aton(&src_, "40:B0:76:47:8F:9A");
  mac_aton(&dst_, "04:BF:6D:0D:3A:50");
  ethfrm=eth_build(src_, dst_, 0x800, frame, frmlen, &ethfrmlen);

  printf("%s\n", frminfo(ethfrm, ethfrmlen, 3, 0x00));
  eth_send(eth, ethfrm, ethfrmlen);

  free(msg);
  free(frame);
  free(ethfrm);
  eth_close(eth);

  return 0;

  int fd; 
  size_t reslen=0;
  u8 *pkt=NULL;
  lr_t *lr;

  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  lr = lr_open(to_ns(1000));
  if (!lr)
    puts("Not support???");

  memset(&src, 0, sizeof(src));
  src.sin_family = AF_INET;
  src.sin_addr.s_addr = ncs_inet_addr("173.194.222.138");

  //  msg=icmp4_msg_info_build(random_u16(), 100, &msglen);
  // msg=icmp4_msg_tstamp_build(random_u16(), 1, 100, 30, 344, &msglen);
  pkt=icmp4_build_pkt(ncs_inet_addr("192.168.1.33"), src.sin_addr.s_addr, 121,
		      12342, 0, 0, NULL, 0, ICMP4_ECHO, 0, msg, msglen, &reslen, false);
  //  printf("%s\n", frminfo(pkt, reslen, 3));
  ip4_send(NULL, fd, &src, 0, pkt, reslen);

  u8 *res = (u8*)calloc(65535, sizeof(u8));
  lr_callback(lr, callback);
  size_t len;
  len = lr_live(lr, &res, 65535);
  printf("%s\n", frminfo(res, len, 3,1));
  
  tvsub(&lr->tstamp_e, &lr->tstamp_s);
  size_t triptime=lr->tstamp_e.tv_sec*1000+(lr->tstamp_e.tv_usec/1000);
  printf("%ld\n", triptime);
  
  lr_close(lr);
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
