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

//#include <ncsnet/raw.h>
#include "../../ncsnet/raw.h"
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

u8 *frmbuild(size_t *frmlen, char *errbuf, const char *fmt, ...)
{
  char tmp[ERRBUF_MAXLEN];
  u8 *ret=NULL;
  va_list ap;

  if (!errbuf)
    errbuf=tmp;

  va_start(ap, fmt);
  ret=__frmbuild_generic(frmlen, errbuf, fmt, ap);
  va_end(ap);

  return ret;
}

u8 *frmbuild_add(size_t *frmlen, u8 *oldframe, char *errbuf, const char *fmt, ...)
{
  u8 *newframe=NULL, *res=NULL;
  char tmp[ERRBUF_MAXLEN];
  size_t newfrmlen=0;
  va_list ap;

  if (!errbuf)
    errbuf=tmp;
  if (!oldframe) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Old frame <oldframe> is NULL");
    return NULL;
  }

  va_start(ap, fmt);
  newframe=__frmbuild_generic(&newfrmlen, errbuf, fmt, ap);
  va_end(ap);
  if (!newframe) {
    free(oldframe);
    return NULL;
  }

  res=(u8*)calloc(1, (*frmlen+newfrmlen));
  if (!res) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Allocation failed");
    goto exit;
  }

  memcpy(res, oldframe, *frmlen);
  memcpy(res+*frmlen, newframe, newfrmlen);
  *frmlen+=newfrmlen;

exit:
  free(oldframe);
  free(newframe);
  return res;
}

u8 *frmbuild_addfrm(u8 *frame, size_t frmlen, u8 *oldframe, size_t *oldfrmlen, char *errbuf)
{
  char tmp[ERRBUF_MAXLEN];
  u8 *res=NULL;

  if (!errbuf)
    errbuf=tmp;

  if (!oldframe) {
    snprintf(errbuf, ERRBUF_MAXLEN, "Old frame is NULL");
    goto exit;
  }
  if (!frame) {
    snprintf(errbuf, ERRBUF_MAXLEN, "Frame is NULL");
    goto exit;
  }
  if (frmlen<0) {
    snprintf(errbuf, ERRBUF_MAXLEN, "Frame len <frmlen> is 0");
    goto exit;
  }
  if (*oldfrmlen==0) {
    snprintf(errbuf, ERRBUF_MAXLEN, "Old frame len <oldfrmlen> is 0");
    goto exit;
  }

  res=calloc(1, (frmlen+*oldfrmlen));
  if (!res) {
    snprintf(errbuf, ERRBUF_MAXLEN, "Allocation failed");
    goto exit;
  }

  memcpy(res, oldframe, *oldfrmlen);
  memcpy(res+*oldfrmlen, frame, frmlen);
  *oldfrmlen+=frmlen;

exit:
  free(oldframe);
  return res;
}

static u8 hexvalue(u8 c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  else if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return 0;
}

u8 *frmbuild_hex(size_t *frmlen, char *errbuf, const char *hex)
{
  size_t hexlen=0, i=0;
  u8 *res;

  if (!hex) {
    snprintf(errbuf, ERRBUF_MAXLEN, "Variable hex is (null)");
    return NULL;
  }
  hexlen=strlen(hex);
  if (hexlen%2!=0) {
    snprintf(errbuf, ERRBUF_MAXLEN, "The length (%ld) of the hex must be even!", hexlen);
    return NULL;
  }
  *frmlen=hexlen/2;
  res=(u8*)malloc(*frmlen);
  if (!res) {
    snprintf(errbuf, ERRBUF_MAXLEN, "Allocation failed");
    return NULL;
  }
  for (;i<*frmlen;++i)
    res[i]=(hexvalue(hex[2*i])<<4) | hexvalue(hex[2*i+1]);

  return res;
}


static size_t str_to_size_t(const char *str)
{
  unsigned long long res;
  char *endptr;
  errno=0;
  res=strtoull(str, &endptr, 10);
  if (errno!=0)
    return 0;
  if (*endptr!='\0')
    return 0;
  if (res>SIZE_MAX)
    return 0;
  return res;
}

static void __fmtopt_free(fmtopt *opt)
{
  if (opt)  {
    if (opt->val) {
      free(opt->val);
      opt->val=NULL;
    }
  }
}

static u8 *__frmbuild_alloc(size_t *frmlen, char *errbuf, char *buf)
{
  char      tmp[FMTBUF_MAXLEN]={0};
  size_t    tmplen=0;
  char     *tok=NULL;
  fmtopt    opt={};
  u8       *res=NULL;


  /*
   * First we need to get the length of our internet frame, for this
   * we can calculate the sizes of all data types from fmt. Also all
   * errors with formatting can be traced at this stage, it will be
   * advantageous because we will not have to do it further with
   * memory allocation.
   */
  strcpy(tmp, buf);
  tok=strtok(tmp, ",");
  while (tok) {
    opt=__fmtoptparse(tok, errbuf);
    if (*errbuf!='\0')
      return NULL;
    switch (opt.type) {
      case TYPE_U:    tmplen+=opt.bits;        break;
      case TYPE_U8:  *frmlen+=1;               break;
      case TYPE_U16: *frmlen+=2;               break;
      case TYPE_U32: *frmlen+=4;               break;
      case TYPE_U64: *frmlen+=8;               break;
      case TYPE_STR: *frmlen+=strlen(opt.val); break;
    }
    __fmtopt_free(&opt);
    tok=strtok(NULL, ",");
  }
  __fmtopt_free(&opt);


  /*
   * Convert bits to bytes, add 7 so that if the number is not a multiple
   * of 8, round it off.
   */
  *frmlen+=((tmplen+7)/8);
  if (*frmlen==0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Frame len <frmlen> is (0)");
    return NULL;
  }

  res=(u8*)calloc(1,(*frmlen));
  if (!res) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Allocated failed");
    return NULL;
  }

  return res;
}

static bool __frmbuild_add_bits_buf(u8 *buf, char *errbuf, u32 val, size_t bits, size_t *bit_pos)
{
  size_t byte_pos, bit_offset, i=0;
  byte_pos=*bit_pos/8;
  bit_offset=*bit_pos%8;
  for (;i<bits;i++) {
    if (val&(1<<(bits-i-1)))
      buf[byte_pos]|=(1<<(7-bit_offset));
    bit_offset++;
    if (bit_offset==8) {
      bit_offset=0;
      byte_pos++;
    }
  }
  *bit_pos+=bits;
  return true;
}

static bool __frmbuild_add_1_bytes_buf(u8 *buf, char *errbuf, size_t val, size_t *pos)
{
  u8 byte=0;
  if (val>UCHAR_MAX||val<0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Field \"%ld\" len error, valid range is, (0-%d)",
      val, UCHAR_MAX);
    return false;
  }
  byte=(u8)val;
  memcpy((buf+*pos), &byte, 1);
  *pos+=1;
  return true;
}

static bool __frmbuild_add_2_bytes_buf(u8 *buf, char *errbuf, size_t val, size_t *pos)
{
  u16 twobytes=0;
  if (val>USHRT_MAX||val<0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Field \"%ld\" len error, valid range is, (0-%d)",
      val, USHRT_MAX);
    return false;
  }
  twobytes=(u16)val;
  memcpy((buf+*pos), &twobytes, 2);
  *pos+=2;
  return true;
}

static bool __frmbuild_add_4_bytes_buf(u8 *buf, char *errbuf, size_t val, size_t *pos)
{
  u32 fourbytes=0;
  if (val>UINT_MAX||val<0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Field \"%ld\" len error, valid range is, (0-%d)",
      val, UINT_MAX);
    return false;
  }
  fourbytes=(u32)val;
  memcpy((buf+*pos), &fourbytes, 4);
  *pos+=4;
  return true;
}

static bool __frmbuild_add_8_bytes_buf(u8 *buf, char *errbuf, size_t val, size_t *pos)
{
  u64 eightbytes=0;
  if (val>ULONG_MAX||val<0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Field \"%ld\" len error, valid range is, (0-%ld)",
      val, ULONG_MAX);
    return false;
  }
  eightbytes=(u64)val;
  memcpy((buf+*pos), &eightbytes, 8);
  *pos+=8;
  return true;
}

static bool __frmbuild_add_str_buf(u8 *buf, const char *str, char *errbuf, size_t *pos)
{
  size_t strlen_t;
  strlen_t=strlen(str);
  memcpy((buf+*pos), (char*)str, strlen_t);
  *pos+=strlen_t;
  return true;
}

static bool __frmbuild_add_loop(u8 *frame, size_t *frmlen, char *errbuf, char *buf)
{
  size_t    check=0, pos=0, bitpos=0, i=0, j=0, bitstmp=0;
  char      tmp[FMTBUF_MAXLEN]={0};
  fmtopt    opts[1024]={};
  char     *tok=NULL;
  bool      try=0;

  strcpy(tmp, buf);
  tok=strtok(tmp, ",");
  while (tok) {
    opts[i++]=__fmtoptparse(tok, errbuf);
    tok=strtok(NULL, ",");
  }

  for (;j<i;j++) {
    check=str_to_size_t(opts[j].val);


    /*
     * We add bits to our Internet frame, if the number of bits is not a multiple of 8,
     * ie they do not stretch on one byte, then first check whether the next value is not
     * also a bit, and so on until the end until it is a multiple of 8. Or if the next
     * value is not a bit, we just fill the rest of the value with zeros until there are
     * no bytes.
     */
    if (opts[j].type==TYPE_U) {
      bitpos=pos*8;
      try=__frmbuild_add_bits_buf(frame, errbuf, (u32)check, opts[j].bits, &bitpos);
reply:
      pos=(bitpos/8);
      if (try) {
        if ((bitpos%8)!=0) {
          if (opts[j+1].type==TYPE_U) {
            __fmtopt_free(&opts[j]);
            j+=1;
            check=str_to_size_t(opts[j].val);
            try=__frmbuild_add_bits_buf(frame, errbuf, check, opts[j].bits, &bitpos);
            goto reply;
          }
          else {
            bitstmp=(8-(bitpos % 8)%8);
            try=__frmbuild_add_bits_buf(frame, errbuf, check, bitstmp, &bitpos);
          }
        }
      }
    }


    /*
     * Add other values, it is not difficult since they are multiples of 8.
     */
    else if (opts[j].type==TYPE_U8)
      try=__frmbuild_add_1_bytes_buf(frame, errbuf, check, &pos);
    else if (opts[j].type==TYPE_U16)
     try=__frmbuild_add_2_bytes_buf(frame, errbuf, check, &pos);
    else if (opts[j].type==TYPE_U32)
     try=__frmbuild_add_4_bytes_buf(frame, errbuf, check, &pos);
    else if (opts[j].type==TYPE_U64)
     try=__frmbuild_add_8_bytes_buf(frame, errbuf, check, &pos);
    else if (opts[j].type==TYPE_STR)
     try=__frmbuild_add_str_buf(frame, opts[j].val, errbuf,  &pos);

    __fmtopt_free(&opts[j]);
  }
  if (!try)
    return false;

  return true;
}

u8 *__frmbuild_generic(size_t *frmlen, char *errbuf, const char *fmt, va_list ap)
{
  char buf[FMTBUF_MAXLEN];
  u8 *res=NULL;

  if (errbuf) *errbuf='\0';
  else return NULL;
  *frmlen=0;

  vsnprintf(buf, FMTBUF_MAXLEN, fmt, ap);
  to_lower(buf);
  del_spaces(buf);

  if (!(res=__frmbuild_alloc(frmlen, errbuf, buf)))
    goto fail;


  /*
   * Now, in this allocated memory for our internet frame, the size of which we
   * obtained in the previous step, go through "fmt" again, sequentially
   * adding the specified values to our frame. At the same time, we keep
   * track of the size of the types.
   */
  if (!(__frmbuild_add_loop(res, frmlen, errbuf, buf)))
    goto fail;

  return res;
fail:
  if (res)
    free(res);
  return NULL;
}


int __fmtopttype(fmtopt *f, const char *type)
{
  size_t i_type=0;
#define C(x) (strcmp(type, x) == 0)
  if (C("u8")||C("8"))
    return f->type=TYPE_U8;
  else if (C("u16")||C("16"))
    return f->type=TYPE_U16;
  else if (C("u32")||C("32"))
    return f->type=TYPE_U32;
  else if (C("u64")||C("64"))
    return f->type=TYPE_U64;
  else if (C("str"))
    return f->type=TYPE_STR;
#undef C
  else {
    i_type=atoi(type);
    if (i_type<=0)
      return f->type=-1;
    f->type=TYPE_U;
    return f->bits=i_type;
  }
  return f->type=-1;;
}


fmtopt __fmtoptparse(const char *txt, char *errbuf)
{
  char type[FMTTYPE_MAXLEN];
  char val[FMTBUF_MAXLEN];
  const char *save;
  char *ptr, *ptr1;
  fmtopt res;
  int tmp;

  memset(&res, 0, sizeof(fmtopt));
  save=txt;
  if (errbuf)
    *errbuf = '\0';
  else
    return res;
  ptr=type;
  ptr1=val;

  while (*txt!='\0'&&*txt!='('&&(ptr-type)<(FMTTYPE_MAXLEN-1))
    *ptr++=*txt++;
  *ptr='\0';
  if (*txt=='\0') {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "There was a missing '(' in the option \"%s\"",
      save);
    return res;
  }
  if (*txt++=='(') {
    tmp=1;
    for (;*txt!='\0';txt++) {
      if (*txt==')') {
        tmp=0;
        break;
      }
      if (tmp&&(ptr1-val)<(FMTTYPE_MAXLEN-1))
        *ptr1++=*txt;
    }
    if (*txt=='\0') {
      snprintf(errbuf, ERRBUF_MAXLEN,
        "There was a missing ')' in the option \"%s\"",
        save);
      return res;
    }
  }
  *ptr1='\0';

  if (strlen(val)<=0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Empty value in the option \"%s\"",
      save);
    return res;
  }

  res.val=strdup(val);
  __fmtopttype(&res, type);

  if (res.type==-1)
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Not found type \"%s\" in the option \"%s\"",
      type, save);

  return res;
}
