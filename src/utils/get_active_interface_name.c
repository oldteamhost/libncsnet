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

const char *getinterface(void)
{
  struct if_nameindex *if_nidxs, *intf;
  static char dev[1024];
  struct ifreq ifr;
  int fd;

  fd=socket(AF_INET, SOCK_DGRAM, 0);
  if (fd<0)
    return NULL;

  if_nidxs=if_nameindex();
  for (intf=if_nidxs;intf->if_name;intf++) {
     strncpy(ifr.ifr_name, intf->if_name, IFNAMSIZ-1);
     ifr.ifr_name[IFNAMSIZ-1]='\0';
     if (ioctl(fd, SIOCGIFFLAGS, &ifr)==0) {
       if ((ifr.ifr_flags&IFF_UP)&&!(ifr.ifr_flags&IFF_LOOPBACK)) {
         strncpy(dev, intf->if_name, sizeof(dev)-1);
         dev[sizeof(dev)-1]='\0';
         if_freenameindex(if_nidxs);
         close(fd);
         return dev;
       }
     }
  }

  if_freenameindex(if_nidxs);
  close(fd);
  return NULL;
}
