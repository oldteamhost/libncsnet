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
  if (opt&&opt->val) {
    free(opt->val);
    opt->val=NULL;
  }
}

u8 *__frmbuild_generic(size_t *frmlen, char *errbuf, const char *fmt, va_list ap)
{
  char      buf[FMTBUF_MAXLEN];
  char      tmp[FMTBUF_MAXLEN];
  size_t    curlen, check;
  fmtopt    opt;
  char     *tok;
  u16       val16;
  u32       val32;
  u64       val64;
  u8        val8, *res, *cur;

  *frmlen=0;
  if (errbuf)
    *errbuf='\0';
  else
    return NULL;

  vsnprintf(buf, FMTBUF_MAXLEN, fmt, ap);
  to_lower(buf); /* XXX */
  del_spaces(buf);


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
      case TYPE_U8:  *frmlen+=sizeof(u8);      break;
      case TYPE_U16: *frmlen+=sizeof(u16);     break;
      case TYPE_U32: *frmlen+=sizeof(u32);     break;
      case TYPE_U64: *frmlen+=sizeof(u64);     break;
      case TYPE_STR: *frmlen+=strlen(opt.val); break;
    }
    __fmtopt_free(&opt);
    tok=strtok(NULL, ",");
  }
  __fmtopt_free(&opt);
  if (*frmlen==0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Frame len <frmlen> is (0)");
    return NULL;
  }


  /*
   * Now, allocate memory for our internet frame, the size of which we
   * obtained in the previous step, and go through "fmt" again, sequentially
   * adding the specified values to our frame. At the same time, we keep
   * track of the size of the types.
   */
  res=(u8*)calloc(1, (*frmlen));
  if (!res) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Allocated failed");
    return NULL;
  }
  cur=res;
  strcpy(tmp, buf);
  tok=strtok(tmp, ",");

  while (tok) {
    __fmtopt_free(&opt);
    opt=__fmtoptparse(tok, errbuf);
    val8=val16=val32=val64=check=0;
    check=str_to_size_t(opt.val);

    switch (opt.type) {
      case TYPE_U8: {
        if (check>UCHAR_MAX||check<0) {
          snprintf(errbuf, ERRBUF_MAXLEN,
            "Field \"%s\" len error, valid range is, (0-%d)",
            tok, UCHAR_MAX);
          goto fail;
        }
        val8=(u8)check;
        curlen=sizeof(u8);
        memcpy(cur, &val8, curlen);
        cur+=curlen; /* next */
        break;
      }
      case TYPE_U16: {
        if (check>USHRT_MAX||check < 0) {
          snprintf(errbuf, ERRBUF_MAXLEN,
            "Field \"%s\" len error, valid range is, (0-%d)",
            tok, USHRT_MAX);
          goto fail;
        }
        val16=(u16)check;
        curlen=sizeof(u16);
        memcpy(cur, &val16, curlen);
        cur+=curlen; /* next */
        break;
      }

      case TYPE_U32: {
        if (check>UINT_MAX||check < 0) {
          snprintf(errbuf, ERRBUF_MAXLEN,
            "Field \"%s\" len error, valid range is, (0-%u)",
             tok, UINT_MAX);
          goto fail;
        }
        val32=(u32)check;
        curlen=sizeof(u32);
        memcpy(cur, &val32, curlen);
        cur+=curlen; /* next */
        break;
      }

      case TYPE_U64: {
        if (check>ULONG_MAX||check < 0) {
          snprintf(errbuf, ERRBUF_MAXLEN,
            "Field \"%s\" len error, valid range is, (0-%ld)",
            tok, ULONG_MAX);
          goto fail;
        }
        val64=(u64)check;
        curlen=sizeof(u64);
        memcpy(cur, &val64, curlen);
        cur+=curlen; /* next */
        break;
      }

      case TYPE_STR: {
        curlen=strlen(opt.val);
        memcpy(cur, (char*)opt.val, curlen);
        cur+=curlen; /* next */
        break;
      }
    }
    tok=strtok(NULL, ",");
  }

  __fmtopt_free(&opt);
  return res;

fail:
  __fmtopt_free(&opt);
  free(res);
  return NULL;
}


int __fmtopttype(const char *type)
{
#define C(x) strcmp(type, x) == 0
  if (C("u8"))
    return TYPE_U8;
  if (C("u16"))
    return TYPE_U16;
  if (C("u32"))
    return TYPE_U32;
  if (C("u64"))
    return TYPE_U64;
  if (C("str"))
    return TYPE_STR;
#undef C
  return -1;
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
  if (*txt=='(') {
    txt++;
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
  res.type=__fmtopttype(type);

  if (res.type==-1)
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Not found type \"%s\" in the option \"%s\"",
      type, save);

  return res;
}
