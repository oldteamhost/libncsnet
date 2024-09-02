#include "../ncsnet/utils.h"
#include "../ncsnet/log.h"
#include "../ncsnet/mac.h"
#include "../ncsnet/ip4addr.h"
#include "../ncsnet/ip6addr.h"

void print_mac(u8 *mac) {
  for (int i = 0; i < 6; i++) {
    printf("%02x", mac[i]);
    if (i < 5) printf(":");
  }
  printf("\n");
}

int main() {
  ip4_t ip4addr = { .octet = { 224, 0, 0, 1 } };
  mac_t mac4, mac6;
  mact_ip4multicast(&mac4, &ip4addr);
  printf("IPv4 Multicast MAC: ");
  print_mac(mac4.octet);
  ip6_t ip6addr = { .octet = { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
  mact_ip6multicast(&mac6, &ip6addr);
  printf("IPv6 Multicast MAC: ");
  print_mac(mac6.octet);

  return 0;
}
