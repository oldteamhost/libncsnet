#include <stdio.h>
#include "../ncsnet/socks5.h"
#include "../ncsnet/utils.h"

int main(void)
{
  socks5_t *s;
  
  s = socks5_open((to_ns(5000)), "72.195.101.99", 4145, NULL, NULL);
  printf("bind %d\n",  socks5_bind(s, "yandex.ru", 80));
  if (s) {
    socks5_close(s);
  }
  
  return 0;
}
