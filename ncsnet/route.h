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

#ifndef NCSROUTEHDR
#define NCSROUTEHDR

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/route.h>

#include "addr.h"

#include "../ncsnet-config.h"
#include "sys/types.h"
#include "sys/nethdrs.h"

#define PROC_ROUTE_FILE       "/proc/net/route"
#define PROC_IPV6_ROUTE_FILE  "/proc/net/ipv6_route"

#define ADDR_ISHOST(a) \
  (((a)->type == ADDR_TYPE_IP && \
  (a)->bits== IP4_ADDR_BITS) || \
  ((a)->type == ADDR_TYPE_IP6 && \
  (a)->bits == IP6_ADDR_BITS))

typedef struct route_entry_hdr {
  addr_t route_dst;
  addr_t route_gw;
  char dev[IFNAMSIZ+1];
} route_entry;

typedef struct route_handle {
  int fd, fd6, nlfd;
} route_t;

typedef int (*route_handler)(const route_entry *entry, void *arg);

__BEGIN_DECLS

route_t *route_open(void);
int      route_add(route_t *r, const route_entry *entry);
int      route_add_dev(route_t *r, const route_entry *entry, const char* dev);
int      route6_add(route_t *r, const route_entry *entry, int intf_index);
int      route_delete(route_t *r, const route_entry *entry);
int      route6_delete(route_t *r, const route_entry *entry, int intf_index);
int      route_get(route_t *r, route_entry *entry);
int      route_loop(route_t *r, route_handler callback, void *arg);
void     route_close(route_t *r);

__END_DECLS

#endif


