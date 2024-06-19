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
  va_list ap;
  u8 *ret;

  va_start(ap, fmt);
  ret = __frmbuild_generic(frmlen, errbuf, fmt, ap);
  va_end(ap);

  return ret;
}

u8 *frmbuild_add(size_t *frmlen, u8 *oldframe, char *errbuf, const char *fmt, ...)
{
  u8 *newframe, *res;
  size_t newfrmlen;
  va_list ap;

  va_start(ap, fmt);
  newframe = __frmbuild_generic(&newfrmlen, errbuf, fmt, ap);
  va_end(ap);
  if (!newframe)
    return NULL;

  res = (u8*)malloc(*frmlen + newfrmlen);
  if (!res) {
    snprintf(errbuf, ERRBUF_MAXLEN, "Allocation failed");
    free(newframe);
    return NULL;
  }
  
  memcpy(res, oldframe, *frmlen);
  memcpy(res + *frmlen, newframe, newfrmlen);
  *frmlen += newfrmlen;
  
  free(newframe);
  return res;
}

u8 *frmbuild_addfrm(u8 *frame, size_t *frmlen, u8 *oldframe, size_t oldfrmlen, char *errbuf)
{
  u8 *res;
  
  res = (u8*)malloc(*frmlen + oldfrmlen);
  if (!res) {
    snprintf(errbuf, ERRBUF_MAXLEN, "Allocation failed");
    return NULL;
  }
  
  memcpy(res, oldframe, *frmlen);
  memcpy(res + *frmlen, frame, oldfrmlen);
  *frmlen += oldfrmlen;
  
  return res;
}

u8 *__frmbuild_generic(size_t *frmlen, char *errbuf, const char *fmt, va_list ap)
{
  char buf[FMTBUF_MAXLEN];
  char tmp[FMTBUF_MAXLEN];
  size_t curlen;
  fmtopt opt;
  char *tok;
  u8 *res, *cur;

  *frmlen = 0;
  if (errbuf)
    *errbuf = '\0';
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
  tok = strtok(tmp, ",");
  while (tok) {
    opt = __fmtoptparse(tok, errbuf);
    if (*errbuf != '\0')
      return NULL;
    switch (opt.type) {
      case TYPE_U8:
	*frmlen += sizeof(u8);      break;
      case TYPE_U16:
	*frmlen += sizeof(u16);     break;
      case TYPE_U32:
	*frmlen += sizeof(u32);     break;
      case TYPE_U64:
	*frmlen += sizeof(u64);     break;
      case TYPE_STR:
	*frmlen += strlen(opt.val); break;
    }
    tok = strtok(NULL, ",");
  }

  /*
   * Now, allocate memory for our internet frame, the size of which we
   * obtained in the previous step, and go through "fmt" again, sequentially
   * adding the specified values to our frame. At the same time, we keep
   * track of the size of the types.
   */
  res = (u8*)malloc(*frmlen);
  if (!res) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Allocated failed");
    return NULL;
  }
  memset(res, 0, *frmlen);
  cur = res;
  strcpy(tmp, buf);
  tok = strtok(tmp, ",");

  while (tok) {
    opt = __fmtoptparse(tok, errbuf);
    switch (opt.type) {
      case TYPE_U8: {
	int check;
	u8 tmp;
	check = atoi(opt.val);
	if (check > UCHAR_MAX || check < 0) {
	  snprintf(errbuf, ERRBUF_MAXLEN,
            "Field \"%s\" len error, valid range is, (0-%d)",
            tok, UCHAR_MAX);
	  return NULL;
	}
	tmp = (u8)check;
	curlen = sizeof(u8);
	memcpy(cur, &tmp, curlen);
	cur += curlen; /* next */
	break;
      }
      case TYPE_U16: {
	int check;
	u16 tmp;
	check = atoi(opt.val);
	if (check > USHRT_MAX || check < 0) {
	  snprintf(errbuf, ERRBUF_MAXLEN,
            "Field \"%s\" len error, valid range is, (0-%d)",
             tok, USHRT_MAX);
	  return NULL;
	}
	tmp = (u16)check;
	curlen = sizeof(u16);
	memcpy(cur, &tmp, curlen);
	cur += curlen; /* next */
	break;
      }
      case TYPE_U32: {
	size_t check;
	u32 tmp;
	check = atoi(opt.val);
	if (check > UINT_MAX || check < 0) {
	  snprintf(errbuf, ERRBUF_MAXLEN,
            "Field \"%s\" len error, valid range is, (0-%u)",
             tok, UINT_MAX);
	  return NULL;
	}
	tmp = (u32)check;
	curlen = sizeof(u32);
	memcpy(cur, &tmp, curlen);
	cur += curlen; /* next */
	break;
      }
      case TYPE_U64: {
	ssize_t check;
	u64 tmp;
	check = atoll(opt.val);
	if (check > (ssize_t)ULONG_MAX || check < 0) {
	  snprintf(errbuf, ERRBUF_MAXLEN,
            "Field \"%s\" len error, valid range is, (0-%ld)",
             tok, ULONG_MAX);
	  return NULL;
	}
	tmp = (u64)check;
	curlen = sizeof(u64);
	memcpy(cur, &tmp, curlen);
	cur += curlen; /* next */
	break;
      }
      case TYPE_STR: {
	curlen = strlen(opt.val) + 1;
	memcpy(cur, (char*)opt.val, curlen);
	cur += curlen; /* next */
	break;
      }
    }
    tok = strtok(NULL, ",");
  }
  
  return res;
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
  const char *save;
  char *ptr, *ptr1;
  char val[FMTBUF_MAXLEN];
  char type[FMTBUF_MAXLEN];
  fmtopt res;
  int tmp;

  save = txt;
  memset(&res, 0, sizeof(fmtopt));
  if (errbuf)
    *errbuf = '\0';
  else
    return res;
  ptr  = type;
  ptr1 = val;
  
  while (*txt != '\0' && *txt != '(')
    *ptr++ = *txt++;
  *ptr = '\0';
  if (*txt == '\0') {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "There was a missing '(' in the option \"%s\"",
      save);
    return res;
  }
  if (*txt == '(') {
    txt++;
    tmp = 1;
    for (; *txt != '\0'; txt++) {
      if (*txt == ')') {
	tmp = 0;
	break;
      }
      if (tmp)
	*ptr1++ = *txt;
    }
    if (*txt == '\0') {
      snprintf(errbuf, ERRBUF_MAXLEN,
        "There was a missing ')' in the option \"%s\"",
        save);
      return res;
    }
  }
  *ptr1 = '\0';

  if (strlen(val) <= 0) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Empty value in the option \"%s\"",
      save);
    return res;
  }
  
  res.val  = val;
  res.type = __fmtopttype(type);

  if (res.type == -1) {
    snprintf(errbuf, ERRBUF_MAXLEN,
      "Not found type \"%s\" in the option \"%s\"",
      type, save);
    return res;
  }
  
  return res;
}
