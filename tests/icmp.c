#include <stdio.h>
#include "../ncsnet/icmp.h"
#include "../ncsnet/eth.h"
#include "../ncsnet/mac.h"
#include "../ncsnet/readpkt.h"
#include "../ncsnet/linuxread.h"

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
  dst.sin_addr.s_addr=ip->dst;
  if (dst.sin_addr.s_addr==src.sin_addr.s_addr)
    return true;
  return false;
}


long timeval_diff_ms(struct timeval *start, struct timeval *end)
{
  long seconds = end->tv_sec - start->tv_sec;
  long microseconds = end->tv_usec - start->tv_usec;
  long milliseconds = (seconds * 1000) + (microseconds / 1000);
  return milliseconds;
}

int main(void)
{
  size_t msglen = 0;
  u8 *msg;
  int fd;
  lr_t *lr;

  
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  lr = lr_open(to_ns(1000));
  if (!lr)
    puts("Not support???");
  else
    puts("aeee");

  memset(&src, 0, sizeof(src));
  src.sin_family = AF_INET;
  src.sin_addr.s_addr = ncs_inet_addr("173.194.222.138");

  msg = icmp4_msg_echo_build(random_u16(), 10, "kek", &msglen);
  icmp4_send_pkt(NULL, fd, ncs_inet_addr("192.168.1.36"),
		 src.sin_addr.s_addr, 121, random_u16(),
		 0, false, NULL, 0, ICMP4_ECHO, 0, msg,
		 msglen, 0, false);

  u8 *res;
  res = (u8*)calloc(4096, sizeof(u8));

  //  lr_callback(lr, callback);
  
  struct sock_filter bpf_code[] = {
    // Сначала убедимся, что это IPv4 пакет
    { 0x30, 0, 0, 0x0000000e }, // ldb [14] - загрузка 1 байта из смещения 14 (тип Ethernet)
    { 0x54, 0, 0, 0x000000f0 }, // and 0xf0
    { 0x15, 0, 6, 0x00000040 }, // jeq 0x40, L1 (если не IPv4, перейти к концу)
    
    // Переход к началу заголовка IPv4
    { 0x28, 0, 0, 0x0000001a }, // ldh [26] - загрузка 2 байтов из смещения 26 (начало заголовка IPv4)
    { 0x15, 0, 4, htons(ETH_P_IP) }, // jeq 0x0800, L1 (если не IP, перейти к концу)
    
    // Загрузка IP-адреса назначения (смещение 30)
    { 0x20, 0, 0, 0x0000001e }, // ldw [30] - загрузка 4 байтов из смещения 30 (IP-адрес назначения)
    
    // Сравнение IP-адреса назначения с заданным значением
    { 0x15, 0, 1, htonl(src.sin_addr.s_addr) }, // jeq <src_addr>, L2 (если совпадает, принять пакет)
    { 0x6, 0, 0, 0x00000000 },  // ret 0 (иначе отклонить пакет)
    
    // Принять пакет
    { 0x6, 0, 0, 0x00040000 },  // ret 262144
  };
  
  lr_bpf(lr, bpf_code,sizeof (bpf_code));
  
  lr_live(lr, &res, 4096);
  printf("%ld\n", timeval_diff_ms(&lr->tstamp_s, &lr->tstamp_e));
  
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
