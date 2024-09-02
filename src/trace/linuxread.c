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

#include <ncsnet/linuxread.h>

#if defined(IS_LINUX) && (HAVE_LINUX_READ == 1)
#include <linux/if_ether.h>
#include <linux/filter.h>
lr_t *lr_open(long long ns)
{
  lr_t *lr;

  lr=calloc(1, sizeof(lr_t));
  if (!lr)
    return NULL;
  lr->fd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (lr->fd==-1)
    goto fail;
  if (!(sock_util_timeoutns(lr->fd, ns, true, true)))
    goto fail;
  lr->ns=ns;
  memset(&lr->tstamp_s, 0, sizeof(struct timeval));
  memset(&lr->tstamp_e, 0, sizeof(struct timeval));
  lr->callback=NULL;
  lr->bpf=0;

  return lr;
 fail:
  free(lr);
  return NULL;
}

void lr_callback(lr_t *lr, lrcall_t callback)
{
  lr->callback=callback;
}

lrcall_t lr_getcallback(lr_t *lr)
{
  return lr->callback;
}

void lr_bpf(lr_t *lr, bpf_t *code, size_t codelen)
{
  struct sock_fprog bpf;
  bpf.len=codelen/sizeof(struct sock_filter);
  bpf.filter=code;
  lr->bpf=1;
  setsockopt(lr->fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
  perror("kek");
}

ssize_t lr_live(lr_t *lr, u8 **buf, size_t buflen)
{
  struct timespec start, current;
  long long elapsed;
  ssize_t res;
  u8 *tmpbuf;

  if (!lr->callback&&!lr->bpf)
    return -1;

  tmpbuf=*buf;
  clock_gettime(CLOCK_MONOTONIC, &start);
  gettimeofday(&lr->tstamp_s, NULL);

  if (lr->bpf) {
    res=recv(lr->fd, tmpbuf, buflen, 0);
    gettimeofday(&lr->tstamp_e, NULL);
    if (res==-1)
      return -1;
    else {
      *buf = tmpbuf;
      return res;
    }
  }

  for (;;) {
    res = recv(lr->fd, tmpbuf, buflen, 0);
    gettimeofday(&lr->tstamp_e, NULL);
    if (res == -1)
      return -1;
    if (!lr->callback(tmpbuf, res)) {
      clock_gettime(CLOCK_MONOTONIC, &current);
      elapsed=(current.tv_sec-start.tv_sec)*1000000000LL+(current.tv_nsec-start.tv_nsec);
       if (elapsed>=lr->ns)
         return -1;
      continue;
    }
    else {
      *buf = tmpbuf;
      return res;
    }
  }
  /* NOTREACHED */
}

void lr_close(lr_t *lr)
{
  close(lr->fd);
  free(lr);
}

bool lrcall_default(u8 *frame, size_t frmlen)
{
  /*
  char *src=NULL, *dst=NULL;
  ethh_t *eth;

  eth=(ethh_t*)frame;
  printf("FRAME ");
  if (dst && src)
    printf("%s > %s ", src, dst);
  printf("ptype=%hu ", ntohs(eth->type));
  printf("frmlen=%ld\n", frmlen);
  */
  
  return true;
}
#else
lr_t *lr_open(long long ns) { return NULL; }
void lr_callback(lr_t *lr, lrcall_t callback) { return; }
void lr_bpf(lr_t *lr, bpf_t *code, size_t codelen){ return; }
ssize_t lr_live(lr_t *lr, u8 **buf, size_t buflen) { return -1; }
bool lrcall_default(u8 *frame, size_t frmlen) { return false; }
void lr_close(lr_t *lr) { return; }
#endif
