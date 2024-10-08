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

#ifndef NCSLINUXREADHDR
#define NCSLINUXREADHDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "socket.h"
#include "ip.h"
#include "eth.h"

#include "sys/nethdrs.h"
#include "sys/types.h"
#include "../ncsnet-config.h"

typedef bool (*lrcall_t)(u8 *, size_t, void *);
typedef struct linuxread_hdr
{
  struct timeval tstamp_s, tstamp_e;
  lrcall_t callback;
  long long ns;
  eth_t *fd;
} lr_t;

__BEGIN_DECLS

lr_t        *lr_open(const char *device, long long ns);
void         lr_ns(lr_t *lr, long long ns);
bool         lr_fd(lr_t *lr, eth_t *fd);
void         lr_callback(lr_t *lr, lrcall_t callback);
lrcall_t     lr_getcallback(lr_t *lr);
ssize_t      lr_live(lr_t *lr, u8 **buf, size_t buflen, void *arg);
void         lr_close(lr_t *lr);

bool lrcall_default(u8 *frame, size_t frmlen, void *arg);

__END_DECLS

#endif
