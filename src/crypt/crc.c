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

  res=CRC_START_32;
  ptr=buf;
  a=0;

  if (ptr)
    for (; a < len; a++)
      res = (res >> 8) ^ crc_tab32[(res ^ (u32)*ptr++) & 0x000000FFul];

  return (res ^ 0xFFFFFFFFul);
}

#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])

static unsigned long crc_c[256] = {
0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L,
};

unsigned long crc32c(const u8 *buf, size_t len)
{
  unsigned long crc32 = 0xffffffffL;
  u8 byte0, byte1, byte2, byte3;
  unsigned long result;
  int i;

  for (i=0;i<len; i++)
    CRC32C(crc32, buf[i]);

  result=~crc32;

  byte0=result&0xff;
  byte1=(result>>8)&0xff;
  byte2=(result>>16)&0xff;
  byte3=(result>>24)&0xff;
  crc32=((byte0<<24)|
    (byte1 << 16)|(byte2<<8)|byte3);

  return crc32;
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
