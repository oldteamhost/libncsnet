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

#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <getopt.h>

#include "../include/base.h"
#include "coreutils.h"

typedef struct{
  FILE  *f; size_t curpos, flen;
} binr_t;
const char *run=NULL, *shortopts="p:o:s:c:AOh", *node=NULL;
int         rez=0;
hdopts      opts={.off=16, .snum=1, .offprint=1,
  .asciiprint=1, .infoprint=0, .hexprfx=""};
FILE       *f=NULL;
size_t      binlen=0, ret=0, chunklen=104857600, tot=0, n=0;
u8         *bin=NULL;
binr_t     *binr=NULL;
char        date[20];
struct tm  *t;
time_t      now;

extern const char *util_bytesconv(size_t bytes);

binr_t *binr_open(const char *file)
{
  binr_t *binr;
  if (!(binr=(binr_t*)calloc(1, sizeof(binr_t))))
    goto fail;
  if (!(binr->f=fopen(file, "rb")))
    goto fail;
  fseek(binr->f, 0, SEEK_END);
  binr->flen=ftell(binr->f);
  rewind(binr->f);
  binr->curpos=0;
  return binr;
fail:
  if (binr->f)
    fclose(binr->f);
  if (binr)
    free(binr);
  return NULL;
}

u8 *binr_nxt(binr_t *binr, size_t *rlen, size_t len)
{
  size_t rem;
  u8 *res;

  if (!binr||!binr->f||binr->curpos>=binr->flen)
    goto fail;
  rem=binr->flen-binr->curpos;
  *rlen=(rem<len)?rem:len;
  if (!(res=(u8*)calloc(1, *rlen)))
    goto fail;
  fseek(binr->f, binr->curpos, SEEK_SET);
  if (fread(res, 1, *rlen, binr->f)!=*rlen) {
    if (res)
      free(res);
    goto fail;
  }
  binr->curpos+=*rlen;
  return res;
fail:
  *rlen=0;
  return NULL;
}

void binr_close(binr_t *binr)
{
  if (binr) {
    if (binr->f)
      fclose(binr->f);
    free(binr);
  }
}

/*
 * Outputs the help menu, and terminates the program.
 */
static noreturn void usage(void)
{
  puts("Usage");
  printf("  %s [flags] <file>\n\n", run);
  puts("  -p <prfx>  set your hex prefix");
  puts("  -o <off>   set your offset (def. 16)");
  puts("  -s <num>   set your number spaces (def. 1)");
  puts("  -c <len>   set your chunk len (def. 100 mib)");
  putchar('\n');
  puts("  -A  off display hex in ascii");
  puts("  -O  off display hex offset");
  puts("  -h  show this message and exit");
  infohelp();
  exit(0);
}

static void parsearg(int argc, char **argv)
{
  while ((rez=getopt(argc, argv, shortopts))!=-1) {
    switch (rez) {
      case 'A': opts.asciiprint=0; break;
      case 'O': opts.offprint=0; break;
      case 'p': opts.hexprfx=optarg; break;
      case 'o': opts.off=atoll(optarg); break;
      case 's': opts.snum=atoll(optarg); break;
      case 'c': chunklen=atoll(optarg); break;
      case 'h':
      case '?':
      default:
        usage();
    }
  }
}

int main(int argc, char **argv)
{
  run=argv[0];
  if (argc<=1)
    usage();
  parsearg(argc, argv);
  if (optind<argc)
    node=argv[optind];
  startstring();
  if (!(binr=binr_open(node)))
    errx(1, "err: %s file not found\n", node);
  while (((bin=binr_nxt(binr, &binlen, chunklen)))
    &&binlen>0) {
    printf("chunk %ld in %s (%ld bytes):\n", n,
      util_bytesconv(binlen), binlen);
    hexdump_pro(bin, binlen, &opts);
    putchar('\n');
    tot+=binlen;
    n++;
    free(bin);
  }
  binr_close(binr);
  printf("Stats: total %s (%ld bytes)/%ld num chunks\n",
    util_bytesconv(tot), tot, n);
  now=time(NULL);
  t=localtime(&now);
  strftime(date, sizeof(date), "%H:%M:%S", t);
  printf("Ending %s at %s and clearing the memory\n",
    __FILE_NAME__, date);
  return 0;
}
