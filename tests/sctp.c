#include <stdio.h>
#include "../ncsnet/sctp.h"

int main(void)
{
  u8 *res, *chunk;
  size_t chunklen, pktlen;

  u8 cookie[2];
  cookie[0] = 0x11;
  cookie[1] = 0xbb;


  chunk = sctp_error_build(0, 0, cookie, 2, &chunklen);  
  /*
  chunk = sctp_init_build(SCTP_INIT, 0, random_u32(), 32768, 10, 2048, random_u32(), &chunklen);  
  chunk = sctp_shutdown_build(0, 343, &chunklen);  
  chunk = sctp_shutdown_ack_build(0, &chunklen);
  chunk = sctp_shutdown_complete_build(3, &chunklen);

  chunk = sctp_init_build(SCTP_INIT_ACK, 0, random_u32(), 32768, 10, 2048, random_u32(), &chunklen);

  chunk = sctp_heartbeat_build(SCTP_HEARTBEAT_ACK, 0, cookie, 2, &chunklen);

  chunk = sctp_data_build(0, 434, 4545, 343, 0, cookie, 2, &chunklen);
  chunk = sctp_cookie_build(SCTP_COOKIE_ECHO, 0, cookie, 2, &chunklen);  
  */

  //chunk = sctp_heartbeat_build(SCTP_HEARTBEAT, 0, cookie, 2, &chunklen);
  //  chunk = sctp_cookie_build(SCTP_COOKIE_ECHO, 0, cookie, 2, &chunklen);  
  //  chunk = sctp_abort_build(1, 1, cookie, 2, &chunklen);  

  res = sctp4_build_pkt(ncs_inet_addr("192.168.1.38"),
    ncs_inet_addr("173.194.222.138"),
    121, random_u16(), 0, false, NULL,
    0, 80, random_srcport(), random_u32(),
    chunk, chunklen, &pktlen, false, false);

  int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  struct sockaddr_in d;
  d.sin_family = AF_INET;
  d.sin_addr.s_addr = ncs_inet_addr("173.194.222.138");
  ip4_send_raw(fd, &d, res, pktlen);
  printf("%s\n", ip_info(res, pktlen, 3));

  free(chunk);  
  free(res);
  close(fd);

  
  return 0;
}
