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

typedef struct linuxread_hdr
{
  int fd;
  int proto;
  struct sockaddr_storage *src;
  int ms;
} linuxread_t;

__BEGIN_DECLS

linuxread_t *linuxread_open(long long ns);
void         linuxread_filter(linuxread_t *lr, int proto, struct sockaddr_storage *src);
ssize_t      linuxread_live(linuxread_t *lr, u8 **buf, size_t buflen);
void         linuxread_close(linuxread_t *lr);

__END_DECLS

#endif
