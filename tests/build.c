#include <stdio.h>
#include "../ncsnet/nescanet.h"

int main(void)
{
  char errbuf[NCSRAWBUILD_ERRBUF_MAXLEN];
  ncsraw_t *n;

  n = ncsraw_init();
  
  ncsraw_option(n, NCSRAW_OPT_SEND_TRACE, 1);
  ncsraw_option(n, NCSRAW_OPT_SEND_RANDOM_FD, 1);
  /* ncsraw_option(n, NCSRAW_OPT_FRAGMENT, 16); */
  ncsraw_option(n, NCSRAW_OPT_SEND_DELAY, "100ms");
  ncsraw_option(n, NCSRAW_OPT_SEND_CUSTOM_FD, socket(AF_INET, SOCK_RAW, IPPROTO_RAW));
  
  //  ncsraw_build(n, errbuf,
  //       "ip4, icmp4, src=local, dst=yandex.ru, ttl=121, ipid=%df, tos=0, df=0, type=%d, code=0, seq=%x, payload=sdjfklsdjf", random_u16(), ICMP4_ECHO);

  ncsraw_build(n, errbuf, "ip4, src=local, dst=yandex.ru, ttl=121, ipid=%df, tos=0, df=0,", random_u16());
  ncsraw_send(n);
  if (*errbuf != '\0')
    printf("err: %s\n", errbuf);
  
  ncsraw_free(n);
  return 0;
}

  /*
  ncsraw_build(n, errbuf, "[ip4;tcp] src=local, dst=173.194.222.139, ttl=121, ipid=%d, tos=0, df=0, dstport=80, srcport=%d, flags=S, \
                           seq=%x, acknum=0, reserved=0, win=1024, urp=0", random_u16(), random_srcport(), random_u32()); 
  ncsraw_send(n);
    

  ncsraw_send(n);
  

  */
