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

#ifndef NCSCRCHDR
#define NCSCRCHDR

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define CRC_POLY_8       0x8C
#define CRC_POLY_16      0xA001
#define CRC_POLY_32      0xEDB88320ul
#define CRC_POLY_32C     0x1EDC6F41
#define CRC_POLY_64      0x42F0E1EBA9EA3693ull
#define CRC_POLY_CCITT   0x1021
#define CRC_POLY_DNP     0xA6BC
#define CRC_POLY_KERMIT  0x8408
#define CRC_POLY_SICK    0x8005

#define CRC_START_8           0x00
#define CRC_START_16          0x0000
#define CRC_START_MODBUS      0xFFFF
#define CRC_START_XMODEM      0x0000
#define CRC_START_CCITT_1D0F  0x1D0F
#define CRC_START_CCITT_FFFF  0xFFFF
#define CRC_START_KERMIT      0x0000
#define CRC_START_SICK        0x0000
#define CRC_START_DNP         0x0000
#define CRC_START_32          0xFFFFFFFFul
#define CRC_START_64_ECMA     0x0000000000000000ull
#define CRC_START_64_WE       0xFFFFFFFFFFFFFFFFull

__BEGIN_DECLS

u16 crc16(const u8 *buf, size_t len, const u16 *customtab);
u16 crc16modbus(const u8 *buf, size_t len, const u16 *customtab);
u16 crc16dnp(const u8 *buf, size_t len, const u16 *customtab);
u16 crc16kermit(const u8 *buf, size_t len, const u16 *customtab);
u16 crc16xmodem(const u8 *buf, size_t len, const u16 *customtab);
u16 crc16ccitt_1d0f(const u8 *buf, size_t len, const u16 *customtab);
u16 crc16ccitt_ffff(const u8 *buf, size_t len, const u16 *customtab);
u16 crc16ccitt(const u8 *buf, size_t len, u16 start, const u16 *customtab);
u64 crc64ecma(const u8 *buf, size_t len, const u64 *customtab);
u64 crc64we(const u8 *buf, size_t len, const u64 *customtab);
u8  crc8(const u8 *buf, size_t len, const u8 *customtab);
u32 crc32(const u8 *buf, size_t len, const u32 *customtab);
unsigned long crc32c(const u8 *buf, size_t len);
u16 crc16sick(const u8 *buf, size_t len);
u8  crc8updt(u8 crc, u8 val);
u32 crc32updt(u32 crc, u8 val);
u64 crc64updt(u64 crc, u8 val);
u16 crc16updt(u16 crc, u8 val);
u16 crc16sickupdt(u16 crc, u8 val, u8 prev);
u16 crc16ccittupdt(u16 crc, u8 val);
u16 crc16dnpupdt(u16 crc, u8 val);
u16 crc16kermitupdt(u16 crc, u8 val);

__END_DECLS

#endif
