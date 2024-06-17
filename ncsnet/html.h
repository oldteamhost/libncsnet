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

#ifndef NCSHTMLHDR
#define NCSHTMLHDR

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include "sys/nethdrs.h"
#include "sys/types.h"
#include "../ncsnet-config.h"

#define HTML_BUFLEN     65535
#define HTML_TAG_MAXLEN 4096

#define HTML_TAG_B      "b"
#define HTML_TAG_STRONG "strong"
#define HTML_TAG_I      "i"
#define HTML_TAG_EM     "em"
#define HTML_TAG_MARK   "mark"
#define HTML_TAG_SMALL  "small"
#define HTML_TAG_DEL    "del"
#define HTML_TAG_INS    "ins"
#define HTML_TAG_SUB    "sub"
#define HTML_TAG_SUP    "sup"

#define HTML_TXTSTYLE_BOLD   HTML_TAG_B
#define HTML_TXTSTYLE_STRONG HTML_TAG_STRONG
#define HTML_TXTSTYLE_ITALIC HTML_TAG_I
#define HTML_TXTSTYLE_MARKED HTML_TAG_MARK
#define HTML_TXTSTYLE_SMALL  HTML_TAG_SMALL
#define HTML_TXTSTYLE_SUB    HTML_TAG_SUB
#define HTML_TXTSTYLE_SUP    HTML_TAG_SUP
#define HTML_TXTSTYLE_EMPH   HTML_TAG_EM
#define HTML_TXTSTYLE_INSERT HTML_TAG_INS
#define HTML_TXTSTYLE_DEL    HTML_TAG_DEL

__BEGIN_DECLS

bool     html_tag_open(char *buf, const char *key, const char *fmt, ...);
bool     html_tag_close(char *buf, const char *key);
bool     html_add(char *buf, size_t buflen, const char *fmt, ...);
#define  htmlnl(buf, buflen) html_add(buf, buflen, "\n")
bool     html_text_fmt(char *buf, const char *style, const char *fmt, ...);

/* dev */
bool ___html_add(char *buf, size_t buflen, const char *fmt, va_list args);
int  descriptor_general(char *buf, size_t buflen, int fd,
			const char *openq, const char *closeq,
			bool close, const char *key,
			const char *fmt, va_list args);

__END_DECLS
#endif
