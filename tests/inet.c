#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#include "../ncsnet/inet.h"
#include "../ncsnet/ip.h"

void test_ncs_inet_aton(void)
{
  struct in_addr addr;
  int result = ncs_inet_aton("192.168.1.1", &addr);
  assert(result == 1);
  assert(addr.s_addr == htonl(0xC0A80101));
  printf("ncs_inet_aton passed\n");
}

void test_ncs_inet_addr(void)
{
  u32 result = ncs_inet_addr("192.168.1.1");
  assert(result == htonl(0xC0A80101));
  printf("ncs_inet_addr passed\n");
}

void test_ncs_inet_ntoa(void)
{
  struct in_addr addr;
  addr.s_addr = htonl(0xC0A80101);
  char *result = ncs_inet_ntoa(addr);
  assert(strcmp(result, "192.168.1.1") == 0);
  printf("ncs_inet_ntoa passed\n");
}

void test_ncs_inet_pton(void)
{
  struct in_addr addr;
  int result = ncs_inet_pton(AF_INET, "192.168.1.1", &addr);
  assert(result == 1);
  assert(addr.s_addr == htonl(0xC0A80101));
  printf("ncs_inet_pton passed\n");
}

void test_ncs_inet_ntop(void)
{
  struct in_addr addr;
  addr.s_addr = htonl(0xC0A80101);
  char buffer[INET_ADDRSTRLEN];
  const char *result = ncs_inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
  assert(strcmp(result, "192.168.1.1") == 0);
  printf("ncs_inet_ntop passed\n");
}

int main(void)
{
  test_ncs_inet_aton();
  test_ncs_inet_addr();
  test_ncs_inet_ntoa();
  test_ncs_inet_pton();
  test_ncs_inet_ntop();

  printf("All tests passed\n");
  return 0;
}
