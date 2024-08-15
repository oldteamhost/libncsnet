#include <stdio.h>
#include <sys/socket.h>
#include "../ncsnet/icmp.h"
#include "../ncsnet/eth.h"
#include "../ncsnet/mac.h"
#include "../ncsnet/udplite.h"
#include "../ncsnet/utils.h"
#include "../ncsnet/eth.h"
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
  /*
  int status, valread, client_fd;
    struct sockaddr_in serv_addr;
    char* hello = "Hello from client";
    char buffer[1024] = { 0 };
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(80);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "142.250.74.110", &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }

    if ((status
         = connect(client_fd, (struct sockaddr*)&serv_addr,
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    send(client_fd, hello, strlen(hello), 0);
    printf("Hello message sent\n");
    valread = read(client_fd, buffer,
                   1024 - 1); // subtract 1 for the null
                              // terminator at the end
    printf("%s\n", buffer);

    // closing the connected socket
    close(client_fd);
    return 0;
*/


    u8 *opts, *sack, *tstamp, *nop, *wscale;
    size_t sacklen, tstamplen, noplen, wscalelen, optslen=0;

    opts=tcp_opt_mss_build(1460, &optslen);
    sack=tcp_opt_sackpr_build(&sacklen);
    tstamp=tcp_opt_tstamp_build(random_u32(), 0, &tstamplen);
    nop=tcp_opt_nop_build(&noplen);
    wscale=tcp_opt_wscale_build(7, &wscalelen);

    frmbuild_addfrm(sack, sacklen, opts, &optslen, NULL);
    frmbuild_addfrm(tstamp, tstamplen, opts, &optslen, NULL);
    frmbuild_addfrm(nop, noplen, opts, &optslen, NULL);
    frmbuild_addfrm(wscale, wscalelen, opts, &optslen, NULL);

    opts=frmbuild_hex(&optslen, NULL, "020405b40402080a04e1700d0000000001030307");
    struct ethtmp t;
    const char *tmpdev=getinterface();
    sprintf(t.devname, "%s",tmpdev);
    mac_aton(&t.dst, "04:bf:6d:0d:3a:50");
    mac_aton(&t.src, "40:b0:76:47:8f:9a");
    t.ethsd=eth_open(t.devname);

    tcp4_send_pkt(&t, 0, ncs_inet_addr("192.168.1.33"), ncs_inet_addr("142.250.74.110"), 121, 0, NULL, 0, random_srcport(), 80, random_u32(), 0, 0, TCP_FLAG_SYN,
      64240, 0, opts, optslen, NULL, 0, 0, 0);

    delayy(30);
    opts=frmbuild_hex(&optslen, NULL, "0101080a04e17024de31b6d2");
    tcp4_send_pkt(&t, 0, ncs_inet_addr("192.168.1.33"), ncs_inet_addr("142.250.74.110"), 121, 0, NULL, 0, random_srcport(), 80, random_u32(), 0, 0, TCP_FLAG_ACK,
      64240, 0, opts, optslen, NULL, 0, 0, 0);

    delayy(30);
    opts=frmbuild_hex(&optslen, NULL, "0101080a04e17024de31b6d2");
    tcp4_send_pkt(&t, 0, ncs_inet_addr("192.168.1.33"), ncs_inet_addr("142.250.74.110"), 121, 0, NULL, 0, random_srcport(), 80, random_u32(), 0, 0, TCP_FLAG_ACK|TCP_FLAG_PSH,
      64240, 0, opts, optslen, NULL, 0, 0, 0);



  return 0;

  u8 *op, *arp;
  ip4_t spa, tpa;
  mac_t sha, tha;
  size_t oplen, arplen;

  spa.octet[0] = 192;
  spa.octet[1] = 168;
  spa.octet[2] = 1;
  spa.octet[3] = 255;

  tpa.octet[0] = 192;
  tpa.octet[1] = 168;
  tpa.octet[2] = 1;
  tpa.octet[3] = 3;

  mac_aton(&sha, "40:b0:76:47:8f:9a");
  mac_aton(&tha, "40:b0:76:47:8f:9a");
  op=arp_op_request_build(6, 4, sha.octet, spa.octet, tha.octet, tpa.octet, &oplen);
  arp=arp_build(ARP_HDR_ETH, ARP_PRO_IP, 6, 4, ARP_OP_REQUEST, op, oplen, &arplen);

  printf("%s\n", frminfo(arp, arplen, 3, FLAG_ARP));

  return 4;
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
