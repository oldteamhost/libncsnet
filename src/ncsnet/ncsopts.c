/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
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

//#include <ncsnet/ncsnet.h>
#include "../../ncsnet/ncsnet.h"

static int     _opts[NCSOPTSCOUNT];
static size_t  optscount=0;
int            ____opt_set(int code) { _opts[optscount++]=code; return code; }
static void    opts_clear(void) { memset(_opts, 0, NCSOPTSCOUNT+1); optscount=0;}

static bool ncsopt_rtimeout(ncsnet_t *n, ncstime_t val)
{
  if (val<0) {
    /* working only ncsopts(n, NCSOPT_RTIMEOUT, (ncstime_t) -(val)) */
    __ncsseterror("%s: rtimeout cannot be negative\n", __FUNCTION__);
    return 0;
  }
  n->sock.rtimeout=val;
  return 1;
}

static bool ncsopt_rbuflen(ncsnet_t *n, size_t val)
{
  void *new=NULL;
  if (val==0) {
    __ncsseterror("%s: rbuflen cannot be 0\n", __FUNCTION__);
    return 0;
  }

  /* realloc buffer*/
  new=calloc(1, val);
  if (!new) {
    __ncsseterror("%s: realloc failed\n", __FUNCTION__);
    return 0;
  }
  if (n->sock.recvfd.rbuf)
    free(n->sock.recvfd.rbuf);
  n->sock.rbuflen=val;
  n->sock.recvfd.rbuf=new;

  return 1;
}

static bool ncsopt_proto(ncsnet_t *n, int val)
{
  n->sock.proto=val;
  return 1;
}

static bool ncsopt_bindproto(ncsnet_t *n, int val)
{
  n->sock.bindproto=val;
  return 1;
}

static bool ncsopt_rinfo(ncsnet_t *n, int val)
{
  if (val>3||val<1) {
    __ncsseterror("%s: specify recv info level in range (1-3)\n", __FUNCTION__);
    return 0;
  }
  n->sock.rinfolvl=val;
  return 1;
}

static bool ncsopt_sinfo(ncsnet_t *n, int val)
{
  if (val>3||val<1) {
    __ncsseterror("%s: specify send info level in range (1-3)\n", __FUNCTION__);
    return 0;
  }
  n->sock.sinfolvl=val;
  return 1;
}

bool ncsopts(ncsnet_t *n, int opts, ...)
{
  va_list args;
  size_t i=0;
  bool ret=0;

  if (!n) {
    __ncsseterror("%s: (n) matches NULL\n", __FUNCTION__);
    return ret;
  }

  va_start(args, opts);
  for (;i<optscount;ret=0,i++) {
    if (_opts[i]==1) /* rtimeout */
      if (ncsopt_rtimeout(n, va_arg(args, ncstime_t)))
        ret=1;
    if (_opts[i]==2)  /* rbuflen */
      if (ncsopt_rbuflen(n, va_arg(args, size_t)))
        ret=1;
    if (_opts[i]==3)  /* proto */
      if (ncsopt_proto(n, va_arg(args, int)))
        ret=1;
    if (_opts[i]==4)  /* bindproto */
      if (ncsopt_bindproto(n, va_arg(args, int)))
        ret=1;
    if (_opts[i]==5)  /* rinfo */
      if (ncsopt_rinfo(n, va_arg(args, int)))
        ret=1;
    if (_opts[i]==6)  /* sinfo */
      if (ncsopt_sinfo(n, va_arg(args, int)))
        ret=1;
    if (ret==0)
      break;
  }
  va_end(args);

  opts_clear();
  return ret;
}
