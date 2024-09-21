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

#define FMTBUF_MAXLEN  65535
#define ERRBUF_MAXLEN  4096
#define FMTTYPE_MAXLEN 1024

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
 * [[<bits>(<value>)], [<bits>(<value>)], etc. (...,)]
 * ex: frmbuild (&len, NULL, "4(1), 4(2), 8(10), 16(%hhu)", htons(100));
 */
u8 *frmbuild(size_t *frmlen, char *errbuf, const char *fmt, ...);

/*
 * Adds the specified data to an existing internet frame and
 * returns a new one. The "fmtlen" is the current length of
 * the internet frame, which will then be replaced by a new one,
 * you can use the same variable that stores the old frame.
 */
u8 *frmbuild_add(size_t *frmlen, u8 *oldframe, char *errbuf, const char *fmt, ...);

/*
 * Adds one internet frame to another, the added frame is
 * specified in frame, its length in frmlen. The old frame is
 * specified in oldframe, its length in oldfrmlen, where, by the
 * way, the new length will be written after the addition.
 */
u8 *frmbuild_addfrm(u8 *frame, size_t frmlen, u8 *oldframe, size_t *oldfrmlen, char *errbuf);

/*
 * Takes a HEX sequence like this, 45002a00910b000079849bd6c0a801
 * 26adc2de8a0050c52f29498d23fa327b230900000a0000000611bb, and puts
 * it into a u8 pointer that returns.
 */
u8 *frmbuild_hex(size_t *frmlen, char *errbuf, const char *hex);

typedef struct __fmtopt {
# define TYPE_U   -4
# define TYPE_U8   0
# define TYPE_U16  1
# define TYPE_U32  2
# define TYPE_U64  3
# define TYPE_STR  4
  int    type;
  char  *val;
  size_t bits;
} fmtopt;

u8    *__frmbuild_generic(size_t *frmlen, char *errbuf, const char *fmt, va_list ap);
fmtopt __fmtoptparse(const char *txt, char *errbuf);
int    __fmtopttype(fmtopt *f, const char *type);

__END_DECLS

#endif
