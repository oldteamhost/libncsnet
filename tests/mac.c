#include "../ncsnet/eth.h"
#include "../ncsnet/ip.h"
#include "../ncsnet/utils.h"
#include "../ncsnet/log.h"
#include "../ncsnet/mac.h"

int main(void)
{
  char buf[MAC_ADDR_STRING_LEN];
  struct ethtmp et;
  
  memset(&et, 0, sizeof(struct ethtmp));
  mac_aton(&et.src, "40:b0:76:47:8f:9a");
  mac_aton(&et.dst, "50:b0:76:47:8f:9a");
  
  mac_copy(&et.src, &et.dst);
  mac_copy(&et.dst, &et.src);
  
  mac_ntoa(&et.src, buf);
  printf("%s\n", buf);
  
  return 0;
}
