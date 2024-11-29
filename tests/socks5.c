#include <stdio.h>
#include "../ncsnet/socks5.h"
#include "../ncsnet/utils.h"
#include "../ncsnet/tcp.h"
#include "../ncsnet/linuxread.h"
#include "../ncsnet/trace.h"

ip4_t ipdst,ipsrc;
mac_t dst,src;
u8 *tcp, *res, *buf;
size_t len;
eth_t *e;
lr_t *lr;
u32 seq, ack;

static bool c(u8 *frame, size_t frmlen, void *arg)
{
  if (frmlen<(14+20+sizeof(tcph_t)))
    return 0;
  ip4h_t *iphdr=(ip4h_t*)((frame)+14);
  if (!ip4t_compare(iphdr->src, ipdst))
    return 0;
  printf("ksjdfl\n");
  tcph_t *tcphdr=(tcph_t*)((frame)+(14+sizeof(ip4h_t)));
  if (tcphdr->th_flags!=(TCP_FLAG_SYN|TCP_FLAG_ACK))
    return 0;
  ack=ntohl(tcphdr->th_ack);
  printf("%u\n", ack);

  return 1;
}

int main(void)
{

  e=eth_open("enp7s0");
  lr=lr_open("enp7s0", to_ns(1000));
  ip4t_pton("142.250.74.110", &ipdst);
  ip4t_pton("192.168.1.37", &ipsrc);
  mact_pton("40:b0:76:47:8f:9a", &src);
  mact_pton("04:bf:6d:0d:3a:50", &dst);
  lr_callback(lr, c);

  /* SYN */
  seq=2;

  u8 *tmp, *k;
  u8 flags;
  size_t len, klen;
  ip4_t r[9];
  u32 tstamps[2];
  ip4t_pton("192.168.1.1", &r[0]);
  ip4t_pton("192.168.1.1", &r[1]);
  tstamps[0]=1;
  tstamps[1]=2;

  //tmp=ip4_opt_route(4, r, 1, &len);

  /* 0000 0011 */
  flags|=0;
  tmp=ip4_opt_tstamp(5, flags, r, tstamps, 2, &len);

  tcp=tcp4_build_pkt(ipsrc, ipdst, 112, random_u16(), 0, 0, tmp, len, random_srcport(), 80, seq,
      0, 0, TCP_FLAG_SYN, 1024, 0, NULL, 0, NULL, 0, &len, 0);
  res=eth_build(src, dst, ETH_TYPE_IPV4, tcp, len, &len);
  eth_send(e, res, len);
  free(tmp);
  free(res);
  free(tcp);

  eth_close(e);
  lr_close(lr);

  return 0;
}
