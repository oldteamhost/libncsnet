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

#include <ncsnet/crc.h>

static bool crc_tab8_init = false;
static u8 crc_tab8[256];
static bool crc_tab16_init = false;
static u16 crc_tab16[256];
static bool crc_tabdnp_init = false;
static u16 crc_tabdnp[256];
static bool crc_tab_init = false;
static u16 crc_tab[256];
static bool crc_tabccitt_init = false;
static u16 crc_tabccitt[256];
static bool crc_tab32_init = false;
static u32 crc_tab32[256];
static bool crc_tab32c_init = false;
static u32 crc_tab32c[256];
static bool crc_tab64_init = false;
static u64 crc_tab64[256];

static void init_crc8_tab(const u8 *customtab)
{
  u16 i, j;
  u8 crc;

  if (customtab) {
    memcpy(crc_tab8, customtab, 256 * sizeof(u8));
    goto ok;
  }

  i = 0;
  for (; i < 256; i++) {
    crc = i;
    for (j = 0; j < 8; j++) {
      if (crc & 0x80)
	crc = (crc << 1) ^ CRC_POLY_8;
      else
	crc <<= 1;
    }
    crc_tab8[i] = crc;
  }
  
 ok:  
  crc_tab8_init = true;
}

u8 crc8(const u8 *buf, size_t len, const u8 *customtab)
{
  const u8 *ptr;
  size_t a;
  u8 res;

  if (!crc_tab8_init)
    init_crc8_tab(customtab);
  
  res = CRC_START_8;
  ptr = buf;
  a = 0;
  
  if (ptr)
    for (; a < len; a++)
      res = crc_tab8[(*ptr++) ^ res];
  
  return res;
}

u8 crc8updt(u8 crc, u8 val)
{
  if (!crc_tab8_init)
    init_crc8_tab(NULL);
  return (crc_tab8[val ^ crc]);
}

static void init_crc16_tab(const u16 *customtab)
{
  u16 i, j, c, crc;

  if (customtab) {
    memcpy(crc_tab16, customtab, 256 * sizeof(u16));
    goto ok;
  }

  i = 0;
  for (; i < 256; i++) {
    crc = 0;
    c = i;
    for (j = 0; j < 8; j++) {
      if ((crc ^ c) & 0x0001)
	crc = (crc >> 1) ^ CRC_POLY_16;
      else
	crc = crc >> 1;
      c = c >> 1;
    }
    crc_tab16[i] = crc;
  }
 ok:
  crc_tab16_init = true;
}

u16 crc16(const u8 *buf, size_t len, const u16 *customtab)
{
  const unsigned char *ptr;
  size_t a;
  u16 res;
  
  if (!crc_tab16_init)
    init_crc16_tab(customtab);
  
  res = CRC_START_16;
  ptr = buf;
  a = 0;
  
  if (ptr)
    for (; a < len; a++)
      res = (res >> 8) ^ crc_tab16[(res ^ (u16)*ptr++) & 0x00FF];
  
  return res;
}

u16 crc16modbus(const u8 *buf, size_t len, const u16 *customtab)
{
  const u8 *ptr;
  size_t a;
  u16 res;

  if (!crc_tab16_init)
    init_crc16_tab(customtab);
  
  res = CRC_START_MODBUS;
  ptr = buf;
  a = 0;
  
  if (ptr)
    for (; a < len; a++)
      res = (res >> 8) ^ crc_tab16[(res ^ (u16)*ptr++) & 0x00FF];

  return res;
}

u16 crc16updt(u16 crc, u8 val)
{
  if (!crc_tab16_init)
    init_crc16_tab(NULL);
  return ((crc >> 8) ^ crc_tab16[(crc ^ (u16)val) & 0x00FF]);
}

static void init_crcdnp_tab(const u16 *customtab)
{
  u16 crc, c, i, j;

  if (customtab) {
    memcpy(crc_tabdnp, customtab, 256 * sizeof(u16));
    goto ok;
  }
    
  i = 0;
  for (; i < 256; i++) {
    crc = 0;
    c = i;
    for (j = 0; j < 8; j++) {
      if ((crc ^ c) & 0x0001 )
	crc = (crc >> 1) ^ CRC_POLY_DNP;
      else
	crc = crc >> 1;
      c = c >> 1;
    }
    crc_tabdnp[i] = crc;
  }
 ok:
  crc_tabdnp_init = true;
}

u16 crc16dnp(const u8 *buf, size_t len, const u16 *customtab)
{
  u16 res, low, high;
  const u8 *ptr;
  size_t a;

  if (!crc_tabdnp_init)
    init_crcdnp_tab(customtab);
  
  res = CRC_START_DNP;
  ptr = buf;
  a = 0;
  
  if (ptr)
    for (; a < len; a++)
      res = (res >> 8) ^ crc_tabdnp[(res ^ (u16)*ptr++) & 0x00FF];

  res  = ~res;
  low  = (res & 0xff00) >> 8;
  high = (res & 0x00ff) << 8;
  res  = low | high;
  
  return res;
}

u16 crc16dnpupdt(u16 crc, u8 val)
{
  if (!crc_tabdnp_init)
    init_crcdnp_tab(NULL);
  return (crc >> 8) ^ crc_tabdnp[(crc ^ (u16)val) & 0x00FF];
}

u16 crc16sick(const u8 *buf, size_t len)
{
  u16 crc, low, high, c, p;
  const u8 *ptr;
  size_t a;
  
  crc = CRC_START_SICK;
  ptr = buf;
  p = a =  0;
  
  if (ptr)
    for (; a < len; a++) {
      c = 0x00FF & (u16)*ptr;
      if (crc & 0x8000)
	crc = (crc << 1) ^ CRC_POLY_SICK;
      else
	crc = crc << 1;
      crc ^= (c | p);
      p = c << 8;
      ptr++;
    }
  
  low = (crc & 0xFF00) >> 8;
  high = (crc & 0x00FF) << 8;
  crc = low | high;
  
  return crc;
}

u16 crc16sickupdt(u16 crc, u8 val, u8 prev)
{
  u16 c, p;
  
  c = 0x00FF & (u16)val;
  p = (0x00FF & (u16)prev) << 8;
  
  if (crc & 0x8000)
    crc = (crc << 1) ^ CRC_POLY_SICK;
  else
    crc = crc << 1;
  crc ^= (c | p);
  
  return crc;
}

static void init_crc_tab(const u16 *customtab)
{
  u16 i, j, crc, c;

  if (customtab) {
    memcpy(crc_tab, customtab, 256 * sizeof(u16));
    goto ok;
  }
    
  i = 0;
  for (; i<256; i++) {
    crc = 0;
    c = i;
    for (j = 0; j < 8; j++) {
      if ((crc ^ c) & 0x0001 )
	crc = (crc >> 1) ^ CRC_POLY_KERMIT;
      else
	crc = crc >> 1;
      c = c >> 1;
    }
    crc_tab[i] = crc;
  }
 ok:
  crc_tab_init = true;
} 

u16 crc16kermit(const u8 *buf, size_t len, const u16 *customtab)
{
  u16 res, low, high;
  const u8 *ptr;
  size_t a;

  if (!crc_tab_init)
    init_crc_tab(customtab);

  res = CRC_START_KERMIT;
  ptr = buf;
  a = 0;

  if (ptr)
    for (; a < len; a++)
      res = (res >> 8) ^ crc_tab[(res ^ (u16)*ptr++) & 0x00FF];

  low = (res & 0xff00) >> 8;
  high = (res & 0x00ff) << 8;
  res = low | high;

  return res;
}

u16 crc16kermitupdt(u16 crc, u8 val)
{
  if (!crc_tab_init)
    init_crc_tab(NULL);
  return ((crc >> 8) ^ crc_tab[(crc ^ (u16)val) & 0x00FF]);
}

static void init_crcccitt_tab(const u16 *customtab)
{
  u16 i, j, crc, c;

  if (customtab) {
    memcpy(crc_tabccitt, customtab, 256 * sizeof(u16));
    goto ok;
  }
  
  i = 0;
  for (; i < 256; i++) {
    crc = 0;
    c = i << 8;
    for (j = 0; j < 8; j++) {
      if ((crc ^ c) & 0x8000)
	crc = ( crc << 1 ) ^ CRC_POLY_CCITT;
      else
	crc = crc << 1;
      c = c << 1;
    }
    crc_tabccitt[i] = crc;
  }
 ok:
  crc_tabccitt_init = true;
}

static u16 crc_ccitt_generic(const u8 *buf, size_t len, u16 start, const u16 *customtab)
{
  const u8 *ptr;
  size_t a;
  u16 res;
  
  if (!crc_tabccitt_init)
    init_crcccitt_tab(customtab);
  
  res = start;
  ptr = buf;
  a = 0;
  
  if (ptr)
    for (; a < len; a++)
      res = (res << 8) ^ crc_tabccitt[((res >> 8) ^ (u16)*ptr++) & 0x00FF];
  
  return res;
}

u16 crc16ccitt(const u8 *buf, size_t len, u16 start, const u16 *customtab)
{
  return crc_ccitt_generic(buf, len, start, customtab);
}

u16 crc16xmodem(const u8 *buf, size_t len, const u16 *customtab)
{
  return crc_ccitt_generic(buf, len, CRC_START_XMODEM, customtab);
}

u16 crc16ccitt_1d0f(const u8 *buf, size_t len, const u16 *customtab)
{
  return crc_ccitt_generic(buf, len, CRC_START_CCITT_1D0F, customtab);
}

u16 crc16ccitt_ffff(const u8 *buf, size_t len, const u16 *customtab)
{
  return crc_ccitt_generic(buf, len, CRC_START_CCITT_FFFF, customtab);
}

u16 crc16ccittupdt(u16 crc, u8 val)
{
  if (!crc_tabccitt_init)
    init_crcccitt_tab(NULL);
  return (crc << 8) ^ crc_tabccitt[ ((crc >> 8) ^ (u16)val) & 0x00FF ];
}

static void init_crc32_tab(const u32 *customtab, bool c)
{
  u32 i, j, crc, cc;

  if (customtab) {
    if (c)
      memcpy(crc_tab32c, customtab, 256 * sizeof(u32));
    else
      memcpy(crc_tab32, customtab, 256 * sizeof(u32));
    goto ok;
  }

  if (c)
    cc = CRC_POLY_32C;
  else
    cc = CRC_POLY_32;
    
  i = 0;
  for (; i < 256; i++) {
    crc = i;
    for (j = 0; j < 8; j++) {
      if (crc & 0x00000001L)
	crc = (crc >> 1) ^ cc;
      else
	crc = crc >> 1;
    }
    if (c)
      crc_tab32c[i] = crc;
    else
      crc_tab32[i] = crc;
  }
 ok:
  if (c)
    crc_tab32c_init = true;
  else
    crc_tab32_init = true;
}

u32 crc32(const u8 *buf, size_t len, const u32 *customtab)
{
  const u8 *ptr;
  size_t a;
  u32 res;

  if (!crc_tab32_init)
    init_crc32_tab(customtab, false);
  
  res = CRC_START_32;
  ptr = buf;
  a = 0;
  
  if (ptr)
    for (; a < len; a++) 
      res = (res >> 8) ^ crc_tab32[(res ^ (u32)*ptr++) & 0x000000FFul];
  
  return (res ^ 0xFFFFFFFFul);
}

u32 crc32c(const u8 *buf, size_t len, const u32 *customtab)
{
  if (!crc_tab32c_init)
    init_crc32_tab(customtab, true);
  return (crc32(buf, len, crc_tab32c));
}

u32 crc32updt(u32 crc, u8 val)
{
  if (!crc_tab32_init)
    init_crc32_tab(NULL, false);
  return (crc >> 8) ^ crc_tab32[(crc ^ (u32)val) & 0x000000FFul];
}

static void init_crc64_tab(const u64 *customtab)
{
  u64 i, j, c, crc;
  
  if (customtab) {
    memcpy(crc_tab64, customtab, 256 * sizeof(u64));
    goto ok;
  }
    
  i = 0;
  for (; i < 256; i++) {
    crc = 0;
    c = i << 56;
    for (j = 0; j < 8; j++) {
      if ((crc ^ c ) & 0x8000000000000000ull)
	crc = (crc << 1) ^ CRC_POLY_64;
      else
	crc = crc << 1;
      c = c << 1;
    }
    crc_tab64[i] = crc;
  }
 ok:
  crc_tab64_init = true;
}

u64 crc64ecma(const u8 *buf, size_t len, const u64 *customtab)
{
  const u8 *ptr;
  size_t a;
  u64 res;

  if (!crc_tab64_init)
    init_crc64_tab(customtab);

  res = CRC_START_64_ECMA;
  ptr = buf;
  a = 0;

  if (ptr)
    for (; a < len; a++)
      res = (res << 8) ^ crc_tab64[((res >> 56) ^ (u64)*ptr++) & 0x00000000000000FFull];
  
  return res;
}

u64 crc64we(const u8 *buf, size_t len, const u64 *customtab)
{
  const u8 *ptr;
  size_t a;
  u64 res;

  if (!crc_tab64_init)
    init_crc64_tab(customtab);

  res = CRC_START_64_WE;
  ptr = buf;
  a = 0;

  if (ptr)
     for (; a < len; a++)
       res = (res << 8) ^ crc_tab64[((res >> 56) ^ (u64)*ptr++) & 0x00000000000000FFull];
  
  return (res ^ 0xFFFFFFFFFFFFFFFFull);
}

u64 crc64updt(u64 crc, u8 val)
{
  if (!crc_tab64_init)
    init_crc64_tab(NULL);
  return (crc << 8) ^ crc_tab64[((crc >> 56) ^ (u64)val) & 0x00000000000000FFull];
}
