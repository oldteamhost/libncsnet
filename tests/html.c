#include "../ncsnet/html.h"

#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/param.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>


typedef unsigned char u8;
typedef unsigned short u16;

#define ARP_PRO_IP        0x0800

#define SRC_MAC   0x40,0xb0,0x76,0x47,0x8f,0x9a
#define SRC_IP4   192,168,1,33
#define ROUTE_IP4 192,168,1,1

int main(void)
{
  struct sockaddr_ll  sll;
  struct ifreq        ifr;
  int                 fd, n;
  char                device[] = "enp7s0";
  int                 proto    = 23043;
  size_t              pktlen;
  unsigned char       pkt[100];

  /* mac hdr*/
  u8 mac_dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  u8 mac_src[6] = {SRC_MAC};
  u16 mac_type  = htons(ETHERTYPE_ARP);

  /* arp hdr*/
  u16 arp_hdr = htons(ARPHRD_ETHER);
  u16 arp_pro = htons(ARP_PRO_IP);
  u8  arp_hln = 6;                    /* mac addr len */
  u8  arp_pln = 4;                    /* ipv4 addr len */
  u16 arp_op  = htons(ARPOP_REQUEST); /* operation */

  /* arp request hdr*/
  u8 sha[6] = {SRC_MAC};
  u8 spa[4] = {SRC_IP4};
  u8 tha[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  u8 tpa[4] = {192, 168, 1, 1};

  /* copy */
  memcpy(pkt, mac_dst, 6);
  memcpy(pkt+6, mac_src, 6);
  memcpy(pkt+6+6, &mac_type, 2);

  memcpy(pkt+14, &arp_hdr, 2);
  memcpy(pkt+14+2, &arp_pro, 2);
  memcpy(pkt+14+2+2, &arp_hln, 1);
  memcpy(pkt+14+2+2+1, &arp_pln, 1);
  memcpy(pkt+14+2+2+1+1, &arp_op, 2);
  memcpy(pkt+14+8, sha, 6);
  memcpy(pkt+14+8+6, spa, 4);
  memcpy(pkt+14+8+6+4, tha, 6);
  memcpy(pkt+14+8+6+4+6, tpa, 4);

  pktlen=14+8+20;

  fd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd<0)
    return -1;

  n=1;
  if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n))<0)
    goto fail;

  strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
    goto fail;

  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;

  sll.sll_protocol=proto;
  sendto(fd, pkt, pktlen, 0, (struct sockaddr*)&sll, sizeof(sll));

  close(fd);
  return 0;

fail:
  close(fd);
  return -1;


  return 0;
  char buf[HTML_BUFLEN];
  memset(&buf, 0, HTML_TAG_MAXLEN);

  html_text_fmt(buf, HTML_TXTSTYLE_BOLD, "kek");
  htmlnl(buf, HTML_TAG_MAXLEN);
  html_text_fmt(buf, HTML_TXTSTYLE_ITALIC, "kek");
  htmlnl(buf, HTML_TAG_MAXLEN);
  html_text_fmt(buf, HTML_TXTSTYLE_STRONG, "kek");    

  htmlnl(buf, HTML_TAG_MAXLEN);
  int kek = 1;
  html_tag_open(buf, "kek", "kdsf=%d class=dev1", kek);
  html_add(buf, HTML_TAG_MAXLEN, "kek");
  html_tag_close(buf, "kek");
  printf("%s\n", buf);
  return 0;
}
