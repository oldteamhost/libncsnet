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

#ifndef NCSSMTPHDR
#define NCSSMTPHDR

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

/* SMTP Response codes */
#define SMTP_REPLY_READY           220
#define SMTP_REPLY_COMPLETED       250
#define SMTP_REPLY_STARTTLS        220
#define SMTP_REPLY_AUTH_REQUIRED   334
#define SMTP_REPLY_AUTH_SUCCESS    235
#define SMTP_REPLY_AUTH_FAILED     535
#define SMTP_REPLY_MAIL_OKAY       250
#define SMTP_REPLY_RCPT_OKAY       250
#define SMTP_REPLY_DATA_OKAY       354
#define SMTP_REPLY_QUIT_OKAY       221
#define SMTP_REPLY_SERVER_ERROR    421
#define SMTP_REPLY_COMMAND_ERROR   500
#define SMTP_REPLY_AUTH_DISABLE    503
#define SMTP_REPLY_PARAM_ERROR     501
#define SMTP_REPLY_AUTH_ERROR      535
#define SMTP_REPLY_TRANSACTION_FAILED 554

__BEGIN_DECLS

void smtp_qprc_version(const char* dst, u16 dstport, long long timeoutns,
    u8* verbuf, size_t buflen);

__END_DECLS

#endif
