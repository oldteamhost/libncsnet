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

#ifndef NCSNETHDRSHDR
#define NCSNETHDRSHDR
#include "../../ncsnet-config.h"
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/cdefs.h>
#include <netdb.h>
#include <errno.h>
#include <net/if.h>
#if defined(IS_BSD)
  #include <sys/sysctl.h>
  #include <net/route.h>
  #include <net/if_dl.h>
  #include <net/bpf.h>
  #include <net/if_var.h>
  #include <net/if_types.h>
#elif defined(IS_LINUX)
  #include <net/if.h>
  #if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
    #include <netpacket/packet.h>
    #include <net/ethernet.h>
  #else
    #include <asm/types.h>
    #include <linux/if_packet.h>
    #include <linux/if_ether.h>
  #endif
#endif
#include "dlt.h"
#endif
