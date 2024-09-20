#include "../ncsnet/utils.h"
#include "../ncsnet/log.h"
#include "../ncsnet/mac.h"
#include "../ncsnet/raw.h"
#include "../ncsnet/ip4addr.h"
#include "../ncsnet/ip6addr.h"


struct tmp{
   u8    ihl:4;     /* header length */
  u8    version:4; /* ip proto version */
   u8    tos;       /* type of service */
  u16   totlen;    /* total length */
  u16   id;        /* identificator */
  u16   off;       /* fragment offset */
  u8    ttl;       /* time to live */
  u8    proto;
  u16   check;     /* 16 bit checksum */
  ip4_t src, dst;  /* src and dst ip address */
} __attribute__((packed));

struct ttt {
  u8 kek1:4;
  u8 kek2:4;
  u8  kek3;

};


void print_mac(u8 *mac) {
  for (int i = 0; i < 6; i++) {
    printf("%02x", mac[i]);
    if (i < 5) printf(":");
  }
  printf("\n");
}


void print_buffer_bits(u8 *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            printf("%d", (buf[i] >> bit) & 1);
        }
        printf(" "); // Отделяем каждый байт пробелом для удобства
    }
    printf("\n");
}

int main() {
  /*
  ip4_t ip4addr = { .octet = { 224, 0, 0, 1 } };
  mac_t mac4, mac6;
  mact_ip4multicast(&mac4, &ip4addr);
  printf("IPv4 Multicast MAC: ");
  print_mac(mac4.octet);
  ip6_t ip6addr = { .octet = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
  mact_ip6multicast(&mac6, &ip6addr);
  printf("IPv6 Multicast MAC: ");
  print_mac(mac6.octet);
  */

  size_t tmp;
  char err[ERRBUF_MAXLEN];
  u8 *res=frmbuild(&tmp, err, "4(1), 4(2), 8(4)");
  if (!res)
    printf("err %s\n", err);
  printf("len %ld\n", tmp);

  struct ttt *t=(struct ttt*)res;
  printf("%u\n", t->kek1);
  printf("%u\n", t->kek2);
  printf("%u\n", t->kek3);
  printf("0x%02X", *(u8*)t);

  printf("%s\n", err);
  print_buffer_bits(res, tmp);
  free(res);


  return 0;
}
