#include <stdio.h>
#include <sys/socket.h>
#include "../ncsnet/icmp.h"
#include "../ncsnet/eth.h"
#include "../ncsnet/mac.h"
#include "../ncsnet/intf.h"
#include "../ncsnet/udplite.h"
#include "../ncsnet/utils.h"
#include "../ncsnet/eth.h"
#include "../ncsnet/linuxread.h"
#include "../ncsnet/trace.h"
#include "../ncsnet/ncsnet.h"

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
    const char *tmpdev=intf_getupintf();
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
*/

  //int fd;
  int id_rb=1;
  ncsnet_t *n;
  n=ncsopen();

try:
  u8 *msg, *opt, *preopt;
  size_t msglen;
  size_t optlen, preoptlen;
  size_t reslen=0;
  u8 *pkt=NULL;
  ip4_t iii;

  ncsopts(n, NCSOPT_RBUFLEN|NCSOPT_RTIMEOUT, 65535, to_ns(2000));
  ncsopts(n, NCSOPT_RINFO|NCSOPT_SINFO, 3, 3);

  ip4t_pton("77.88.55.88", &iii);
  ncsopts(n, NCSOPT_PROTO, PR_ICMP);

  msg=icmp4_msg_echo_build(random_u16(), id_rb, NULL, &msglen);
  pkt=icmp_build(ICMP4_ECHO, 0, msg, msglen, &reslen);
  icmp4_check(pkt, reslen, false);

  ncsbind(n, iii);
  ncssend(n, pkt, reslen, ncssend_getnip(iii));

  ncsrecv(n, NULL, id_rb);

  free(msg);
  free(pkt);

  id_rb++;
  if (id_rb==4) {
    printf("rtt: %lld\n", ncsrbuf_rtt(n, 1)/1000000LL);
    printf("rtt: %lld\n", ncsrbuf_rtt(n, 2)/1000000LL);
    printf("rtt: %lld\n", ncsrbuf_rtt(n, 3)/1000000LL);
    ncsclose(n);
    return 0;
  }
  goto try;

/*
  pkt=icmp4_build_pkt(ncs_inet_addr("192.168.1.33"), ip4t_u32(&iii), 121,
      12342, 0, 0, NULL, 0, ICMP4_ECHO, 0, msg, msglen, &reslen, false);
      */

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
  
  return 0;
}
