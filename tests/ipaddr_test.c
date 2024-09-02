/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "../ncsnet/ip4addr.h"
#include "../ncsnet/inet.h"
int main(void)
{
  ip4_t addr, addr2;
  ip4t_fill(&addr, 192, 168, 1, 1);
  printf(IP4_ADDR_STRING_FMT, addr.octet[0], addr.octet[1], addr.octet[2], addr.octet[3]);
  putchar('\n');
  printf("id 0 is %hhu\n", ip4t_getid(&addr, 0));
  ip4t_setid(&addr, 0, 111);
  printf("id 0 is %hhu\n", ip4t_getid(&addr, 0));
  ip4t_copy(&addr2, &addr);
  printf(IP4_ADDR_STRING_FMT, addr2.octet[0], addr2.octet[1], addr2.octet[2], addr2.octet[3]);
  putchar('\n');
  ip4t_clear(&addr);
  printf(IP4_ADDR_STRING_FMT, addr.octet[0], addr.octet[1], addr.octet[2], addr.octet[3]);
  putchar('\n');
  if (!ip4t_compare(addr, addr2))
    printf("not compare\n");
  else
    printf("yes compare\n");
  ip4t_clear(&addr2);
  if (!ip4t_compare(addr, addr2))
    printf("not compare\n");
  else
    printf("yes compare\n");
  u32 kek=ncs_inet_addr("192.168.1.255");
  u32_ip4t(kek, &addr);
  printf(IP4_ADDR_STRING_FMT, addr.octet[0], addr.octet[1], addr.octet[2], addr.octet[3]);
  putchar('\n');
  ip4t_pton("192.168.255.233", &addr2);
  char tmp[IP4_ADDR_STRING_LEN];
  ip4t_ntop(&addr2, tmp, IP4_ADDR_STRING_LEN);
  printf("%s\n",tmp);
  printf("%s\n",ip4t_ntop_c(&addr2));
  ip4t_fill(&addr, 192, 252, 33, 88);
  u32_ip4t(ip4t_u32(&addr), &addr);
  printf(IP4_ADDR_STRING_FMT, addr.octet[0], addr.octet[1], addr.octet[2], addr.octet[3]);
  putchar('\n');

  ip6_t addr6, addr62;
  ip6t_fill(&addr6, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34);
  printf(IP6_ADDR_STRING_FMT, addr6.octet[0], addr6.octet[1], addr6.octet[2], addr6.octet[3],
         addr6.octet[4], addr6.octet[5], addr6.octet[6], addr6.octet[7],
         addr6.octet[8], addr6.octet[9], addr6.octet[10], addr6.octet[11],
         addr6.octet[12], addr6.octet[13], addr6.octet[14], addr6.octet[15]);
  putchar('\n');
  printf("octet 0 is %02x\n", ip6t_getid(&addr6, 0));
  ip6t_setid(&addr6, 0, 0x12);
  printf("octet 0 is %02x\n", ip6t_getid(&addr6, 0));
  ip6t_copy(&addr62, &addr6);
  printf(IP6_ADDR_STRING_FMT, addr62.octet[0], addr62.octet[1], addr62.octet[2], addr62.octet[3],
         addr62.octet[4], addr62.octet[5], addr62.octet[6], addr62.octet[7],
         addr62.octet[8], addr62.octet[9], addr62.octet[10], addr62.octet[11],
         addr62.octet[12], addr62.octet[13], addr62.octet[14], addr62.octet[15]);
  putchar('\n');
  ip6t_clear(&addr6);
  printf(IP6_ADDR_STRING_FMT, addr6.octet[0], addr6.octet[1], addr6.octet[2], addr6.octet[3],
         addr6.octet[4], addr6.octet[5], addr6.octet[6], addr6.octet[7],
         addr6.octet[8], addr6.octet[9], addr6.octet[10], addr6.octet[11],
         addr6.octet[12], addr6.octet[13], addr6.octet[14], addr6.octet[15]);
  putchar('\n');
  if (!ip6t_compare(addr6, addr62))
    printf("not compare\n");
  else
    printf("yes compare\n");
  ip6t_clear(&addr62);
  if (!ip6t_compare(addr6, addr62))
    printf("not compare\n");
  else
    printf("yes compare\n");

  /* XXX failed */
  ip6t_pton("2001:db8:85a3::8a2e:370:7334", &addr62);
  char _tmp[IP6_ADDR_STRING_LEN];
  ip6t_ntop(&addr62, _tmp, IP6_ADDR_STRING_LEN);
  printf("%s\n", _tmp);
  printf("%s\n", ip6t_ntop_c(&addr62));

  return 0;
}
