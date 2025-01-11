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

#ifndef NCSHEXHDR
#define NCSHEXHDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define chex_htoa(hex)                                       \
  (((hex)<=0xF)?(((hex)<10)?(hex)+'0':(hex)-10+'a'):'?')

#define chex_atoh(ascii)                                     \
  (((ascii)>='0'&&(ascii)<='9')?((ascii)-'0'):               \
  (((ascii)>='A'&&(ascii)<='F')?((ascii)-'A'+10):            \
  (((ascii)>='a'&&(ascii)<='f')?((ascii)-'a'+10):'?')))

#define hexlen(asciilen) (asciilen*2+1)
#define asciilen(hexlen) (hexlen+1)

__BEGIN_DECLS

/* ascii to hex*/
void hex_atoh(const char *ascii, u8 *hex, size_t hexlen);

/* hex to ascii */
void hex_htoa(const u8 *hex, size_t hexlen, char *ascii);

/* asciihex to hex */
u8 *hex_ahtoh(char *txt, size_t *hexlen);

/*
 * print hexdump with your options
 *
 * 0000  04 bf 6d 0d 3a 50 40 b0 76 47 8f 9a 08 00 45 00  ..m.:P@.vG....E.
 * 0010  00 34 8e d2 40 00 40 06 0d 66 c0 a8 01 22 b0 64  .4..@.@..f...".d
 * 0020  2c 5d c5 f0 1e d7 31 31 46 84 89 af 67 ba 80 10  ,]....11F...g...
 * 0030  02 93                                            ..
 */
typedef struct __hexdump_opts
{
  size_t off, snum;
  bool offprint, asciiprint, infoprint;
  const char *hexprfx;
} hdopts;

void hexdump_pro(u8 *hex, size_t hexlen, hdopts *opts);

__END_DECLS

#endif
