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

#include <ncsnet/utils.h>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

int get_local_mac(const char *dev, char *mac_address)
{
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_ll *sll;

  if (getifaddrs(&ifap) == -1)
    return -1;

  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_PACKET) {
      sll = (struct sockaddr_ll *)ifa->ifa_addr;
      if (strcmp(ifa->ifa_name, dev) == 0) {
      snprintf(mac_address, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	           sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
            sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
        freeifaddrs(ifap);
        return 0;
      }
    }
  }

  freeifaddrs(ifap);
  return -1;
}
