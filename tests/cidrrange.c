#include "../ncsnet/eth.h"
#include "../ncsnet/ip.h"
#include "../ncsnet/utils.h"
#include "../ncsnet/log.h"
#include "../ncsnet/cidr.h"

int main(void)
{
  char buf[RANGE_CHAR_LEN_MAX];
  cidr_t *addr;

  addr = cidr_from_str("0.0.0.0/0");
  cidr_to_str_range(addr, buf, RANGE_CHAR_LEN_MAX);

  printf("(%s) hosts %lld\n", buf, (long long)cidr_get_numhost(addr));
  cidr_free(addr);
}
