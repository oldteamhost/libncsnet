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
lr_t *lr_open(const char *device, long long ns)
{
  lr_t *lr;

  lr=calloc(1, sizeof(lr_t));
  if (!lr)
    return NULL;
  lr->fd=NULL;
  lr->fd=eth_open(device);
  if (!lr->fd)
    goto fail;
  lr_ns(lr, ns);
  memset(&lr->tstamp_s, 0, sizeof(struct timeval));
  memset(&lr->tstamp_e, 0, sizeof(struct timeval));
  lr->callback=NULL;

  return lr;

 fail:
  if (lr->fd)
    eth_close(lr->fd);
  free(lr);
  return NULL;
}

bool lr_fd(lr_t *lr, eth_t *fd)
{
  if (!lr)
    return 0;
  if (!fd)
    return 0;
  eth_close(lr->fd);
  lr->fd=fd;
  if (!(sock_util_timeoutns(eth_fd(lr->fd), lr->ns, true, true)))
    return 0;
  return 1;
}

void lr_callback(lr_t *lr, lrcall_t callback)
{
  lr->callback=callback;
}

lrcall_t lr_getcallback(lr_t *lr)
{
  return lr->callback;
}

#include <poll.h>

ssize_t lr_live(lr_t *lr, u8 **buf, size_t buflen, void *arg)
{
  struct timespec start={0}, current={0};
  struct pollfd pfd={0};
  u8 *tmpbuf=NULL;
  ssize_t ret=0;

  if (!lr||!lr->callback)
    return -1;

  pfd.fd=eth_fd(lr->fd);
  pfd.events=POLLIN;

  tmpbuf=*buf;
  clock_gettime(CLOCK_MONOTONIC, &start);
  gettimeofday(&lr->tstamp_s, NULL);

  for (;;) {
    ret=poll(&pfd, 1, to_ms(lr->ns));
    if (ret==-1) {
      if (errno==EINTR)
        continue;
      return -1;
    }
    else if (ret==0)
      return -1;
    else if (pfd.revents&POLLIN) {
      pfd.revents=0;
      ret=eth_read(lr->fd, tmpbuf, buflen, 0);
      gettimeofday(&lr->tstamp_e, NULL);
      if (ret==-1) {
        if (errno==EINTR)
          continue;
        return -1;
      }
      if (!lr->callback(tmpbuf, ret, arg)) {
        clock_gettime(CLOCK_MONOTONIC, &current);
         if (((current.tv_sec-start.tv_sec)*1000000000LL+(current.tv_nsec-start.tv_nsec))>=lr->ns)
           return -1;
        continue;
      }
      else {
        *buf = tmpbuf;
        return ret;
      }
    }
  }
  /* NOTREACHED */
}

void lr_ns(lr_t *lr, long long ns)
{
  lr->ns=(ns<0)?0:ns;
  sock_util_timeoutns(eth_fd(lr->fd), lr->ns, true, true);
}

void lr_close(lr_t *lr)
{
  eth_close(lr->fd);
  free(lr);
}

bool lrcall_default(u8 *frame, size_t frmlen, void *arg)
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
lr_t *lr_open(const char *device, long long ns) { return NULL; }
void lr_callback(lr_t *lr, lrcall_t callback) { return; }
ssize_t lr_live(lr_t *lr, u8 **buf, size_t buflen, void *arg) { return -1; }
bool lrcall_default(u8 *frame, size_t frmlen, void *arg) { return false; }
void lr_close(lr_t *lr) { return; }
void lr_ns(lr_t *lr, long long ns) {return;}
bool lr_fd(lr_t *lr, eth_t *fd) { return false; }
#endif
