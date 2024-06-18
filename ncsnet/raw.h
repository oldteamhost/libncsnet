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

#ifndef NCSRAWHDR
#define NCSRAWHDR

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>

#include "utils.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define FMTBUF_MAXLEN 65535
#define ERRBUF_MAXLEN 4096

__BEGIN_DECLS

/*
 * Creates an internet frame based on the formatting in fmt,
 * in case of error writes it errbuf and returns NULL, in case
 * of success returns a frame with allocated memory and writes
 * its size to pktlen;
 *
 * It is important to remember that the order of the fields
 * you specify will be taken into account.
 * 
 * [[<datatype>(<value>)], [<datatype>(<value>)], etc. (...,)]
 */
u8 *build_frame(size_t *frmlen, char *errbuf, const char *fmt, ...);

typedef struct __fmtopt {
# define TYPE_U8  0
# define TYPE_U16 1
# define TYPE_U32 2
# define TYPE_U64 3
# define TYPE_STR 4    
  int type;
  const char *val;
} fmtopt;

fmtopt __fmtoptparse(const char *txt, char *errbuf);
int    __fmtopttype(const char *type);

/*
 * Write the "pkt" internet frame passed to it to the specified file
 * descriptor "fd" whose size corresponds to "pktlen". In case of
 * error returns -1 and writes the error to errbuf, in case of success
 * the number is greater than 0. Uses the write system call.
 */
ssize_t write_frame(int fd, char *errbuf, u8 *frame, size_t frmlen);

/*
 * Reads an internet frame from the file descriptor specified in fd,
 * and writes to a buf whose size corresponds to buflen. In case of
 * error returns -1 and writes it to errbuf, in case of success returns
 * purely greater than 0.Uses the read system call.
 */
ssize_t read_frame(int fd, char *errbuf, u8 *buf, size_t buflen);

__END_DECLS

#endif
