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

#ifndef NESCANETHDR
#define NESCANETHDR

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "utils.h"
#include "ip.h"
#include "tcp.h"
#include "icmp.h"
#include "udp.h"
#include "sctp.h"
#include "igmp.h"
#include "readpkt.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define NCSRAWBUILD_ERRBUF_MAXLEN     512
#define NCSRAWBUILD_FMT_MAXLEN        65535
#define NCSRAWBUILD_PROTOS_MAXLEN     512

#define NCSRAW_OPT_SEND_TRACE         0
#define NCSRAW_OPT_FRAGMENT           1
#define NCSRAW_OPT_SEND_DELAY         2
#define NCSRAW_OPT_SEND_CUSTOM_FD     3
#define NCSRAW_OPT_SEND_RANDOM_FD     4

struct nescanetraw_opts
{
  long long delay;
  bool randomfd;
  int trace;
};

struct nescanetraw
{
  struct sockaddr_storage dst_in;
  struct nescanetraw_opts no;
  int mtu;  
  u8 *pkt;
  u32 pktlen;
  int fd;
};

typedef struct nescanetraw ncsraw_t;

ncsraw_t *ncsraw_init(void);
void      ncsraw_build(ncsraw_t *n, char *errbuf, const char *fmt, ...);
#define   ncsraw_option(n, option, val)			      \
  _Generic((val),					      \
	   const char*: __opt_str,			      \
	   char*: __opt_str,				      \
	   default: __opt_num				      \
	   )(n, option, val)
ssize_t   ncsraw_send(ncsraw_t *n);
void      ncsraw_free(ncsraw_t *n);

void __opt_str(ncsraw_t *n, int option, const char *val);
void __opt_num(ncsraw_t *n, int option, size_t val);

#endif
