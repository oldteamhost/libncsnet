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

#ifndef NCSTYPESHDR
#define NCSTYPESHDR

#include <stdint.h>
#include <sys/cdefs.h>

#define ncs_bswap16(x) (((x) >> 8) | ((x) << 8))
#define ncs_bswap32(x) ((((x) >> 24) & 0xFF) | (((x) >> 8) & 0xFF00)	\
		    | (((x) << 8) & 0xFF0000) | (((x) << 24) & 0xFF000000))
#define ncs_bswap64(x) ((((x) >> 56) & 0xFF) | (((x) >> 40) & 0xFF00)	\
		    | (((x) >> 24) & 0xFF0000) | (((x) >> 8) & 0xFF000000) \
		    | (((x) << 8) & 0xFF00000000) | (((x) << 24) & 0xFF0000000000) \
		    | (((x) << 40) & 0xFF000000000000) | (((x) << 56) & 0xFF00000000000000))

#if defined (HAVE_NETDB_HOST)
 #define htons(x) ncs_bswap16(x)
 #define htonl(x) ncs_bswap32(x)
 #define ntohs(x) ncs_bswap16(x)
 #define ntohl(x) ncs_bswap32(x)
#endif

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#endif
