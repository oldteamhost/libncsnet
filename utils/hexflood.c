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
#include <stdbool.h>
#include <stdnoreturn.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

#include "coreutils.h"
#include "utils-config.h"

#include "../ncsnet/log.h"
#include "../ncsnet/hex.h"
#include "../ncsnet/intf.h"
#include "../ncsnet/utils.h"
#include "../ncsnet/trace.h"

#undef MAXFRAMELEN
#define MAXFRAMELEN           1400
#undef MAXFDS
#define MAXFDS                1024

#define __DEFAULT_THREADSNUM  1
#define __DEFAULT_FDNUM       1
#define __DEFAULT_UPDT        1000
#define __DEFAULT_PPS         10000
#define __DEFAULT_SEE         0

const struct option longopts[]={
  {"help", no_argument, 0, 'h'},
  {"fdnum", required_argument, 0, 1},
  {"pps", required_argument, 0, 2},
  {"threads", required_argument, 0, 3},
  {"frame", required_argument, 0, 4},
  {"list", required_argument, 0, 5},
  {"updt", required_argument, 0, 6},
  {"see", no_argument, 0, 7},
};

const char             *run=NULL;
eth_t                  *fds[MAXFDS];
size_t                  fdnum=__DEFAULT_FDNUM;
const char             *shortopts="h";
clock_t                 start, end;
size_t                  pps=__DEFAULT_PPS;
size_t                  threadsnum=__DEFAULT_THREADSNUM;
size_t                  total=0;
bool                    hexc=0;
u8                     *hexpkt=NULL;
size_t                  hexpktlen=0;
static size_t           total_calls=0;
static pthread_mutex_t  call_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   call_cond=PTHREAD_COND_INITIALIZER;
size_t                  fdcur=0;
size_t                  updt=__DEFAULT_UPDT;
const char             *listpath=NULL;
size_t                  numlines=0;
size_t                  curline=0;
bool                    see=__DEFAULT_SEE;


/*
 * Outputs the help menu, and terminates the program.
 */
static noreturn void usage(void)
{
  puts("Usage");
  printf("  %s <flags>\n\n", run);
  puts("  -frame <hex>          set frame for flood");
  puts("  -list <path>          set list frames for flood");
  puts("  -pps <num>            set max frames per second (default 10000) (unlimited=0)");
  puts("  -threads <num>        set num threads (default 1)");
  puts("  -fdnum <num>          set max fds for send (default 1)");
  puts("  -udpt <num>           change frame after <udpt> frames (default 10000)");
  puts("  -see                  show packets before send");
  puts("  -h, -help             show this help message and exit");
  infohelp();
  exit(0);
}


/*
 * Gets the number of lines in the file, and writes them to
 * numlines.
 */
static void getnumlines(void)
{
  FILE *f=NULL;
  char c='0';
  f=fopen(listpath, "r");
  if (!f)
    errx(0, "file %s not found!", listpath);
  while ((c=fgetc(f))!=-1)
    if (c=='\n')
      numlines++;
  fclose(f);
}


/*
 * Gets a line from a file by its number, removes the '\n' symbol from
 * it, and converts it to hex, saving the result in hexpkt and the size
 * in hexpktlen.
 */
static void gethexlinelist(size_t line)
{
  size_t _curline=0, linelen=0;
  char charline[MAXFRAMELEN];
  FILE *f=NULL;

  f=fopen(listpath, "r");
  if (!f)
    errx(0, "file %s not found!", listpath);
  while (fgets(charline, sizeof(charline), f)) {
    _curline++;
    if (_curline==line) {
      linelen=strlen(charline);
      if (linelen==0)
        return;
      fclose(f);
      if (charline[linelen-1]!='\0')
        charline[linelen-1]='\0';
      hexpkt=hex_ahtoh(charline, &hexpktlen);
      if (see)
        printf("%s\n", frminfo(hexpkt, hexpktlen, 3, 0));
      if (hexpktlen > MAXFRAMELEN)
        errx(2, "err: max frame len is %lld, your len is \"%lld\"", MAXFRAMELEN, hexpktlen);
      return;
    }
  }
  fclose(f);
}


/*
 * Parses the arguments, includes the desired options, and
 * stores the specified value.
 */
static void parseargs(int argc, char **argv)
{
  int rez, index=0;
  while ((rez=getopt_long_only(argc, argv, shortopts, longopts, &index))!=-1){
    switch (rez) {
    case 'h': usage();
    case 1:
      fdnum=atoll(optarg);
      if (fdnum>MAXFDS)
        errx(1, "err: max num fds is %lld, your num is \"%lld\"", MAXFDS, fdnum);
      break;
    case 2: pps=atoll(optarg); break;
    case 3: threadsnum=atoll(optarg); break;
    case 4:
      hexc=1;
      hexpkt=hex_ahtoh(optarg, &hexpktlen);
      if (hexpktlen>MAXFRAMELEN)
        errx(2, "err: max frame len is %lld, your len is \"%lld\"", MAXFRAMELEN, hexpktlen);
      break;
   case 5:
      listpath=optarg;
      getnumlines();
      if (numlines==0)
        errx(2, "err: lines in file %s is \"%lld\"", optarg, numlines);
      gethexlinelist(0);
      break;
   case 6: updt=atoll(optarg); break;
   case 7: see=1; break;
    }
  }
}


/*
 * Opens the desired number of sockets and writes them to fds.
 * The socket type is set to ETH_P_ALL, you cannot receive
 * packets from it, but you can send them.
 */
static void openfds(void)
{
  const char *dev=NULL;
  size_t i=0;
  dev=intf_getupintf();
  memset(&fds, 0, MAXFDS+1);
  for (;fdnum;fdnum--)
    fds[++i]=eth_open(dev);
}


/*
 * Closes all open sockets after openfds, from fds.
 */
static void closefds(void)
{
  size_t i;
  i=0;
  for (;i<MAXFDS;)
    if (fds[i++])
      eth_close(fds[i]);
}


/*
 * Resets the timer for the number of packets sent per
 * second.
 */
static void resetcall(void)
{
  for (;;) {
    usleep(1000000);
    pthread_mutex_lock(&call_mutex);
    total_calls=0;
    pthread_cond_broadcast(&call_cond);
    pthread_mutex_unlock(&call_mutex);
  }
}


/*
 * If NOT a single frame (-frame) is used, it goes to the next
 * frame in the list (-list), once the list has come to an end,
 * it starts from the beginning.
 */
static void hexupdt(void)
{
  if (hexc)
    return;
  if (curline==numlines)
    curline=0;
  gethexlinelist(++curline);
}


/*
 * Selects a working socket from fds, and sends a packet
 * from it, adding counters, if the number of packets
 * sent corresponds to the number after which it is
 * necessary to update packets (updt), then it updates.
 * At the same time it keeps pps.
 */
static void *hexpreddos(void *arg)
{
  eth_t *fd=NULL;
  if (fdcur>=fdnum)
    fdcur=0;
  while (!fd)
    fd=fds[fdcur++];
  for (;;) {
    total++;
    if (total_calls%updt==0)
      hexupdt();
    if (pps!=0) {
      while (total_calls>=pps)
        pthread_cond_wait(&call_cond, &call_mutex);
      total_calls++;
      eth_send(fd, hexpkt, hexpktlen);
      usleep((1000000/pps));
    }
    else {
      total_calls++;
      eth_send(fd, hexpkt, hexpktlen);
    }
  }
  return NULL;
}


/*
 * Main function for ddos, opens and waits for threads
 * with hexpreddos function, number of threads
 * corresponds to threadsnum.
 */
static void hexddos(void)
{
  pthread_t threads[threadsnum];
  pthread_t reset_thread;
  size_t i;

  pthread_create(&reset_thread, NULL, (void *(*)(void *))resetcall, NULL);

  for (i=0;i<threadsnum;++i)
    pthread_create(&threads[i], NULL, hexpreddos, NULL);
  for (i=0;i<threadsnum;++i)
    pthread_join(threads[i], NULL);
  pthread_join(reset_thread, NULL);
}


/*
 * Called at the signal that occurs at CTRL+C, counts
 * the time of the program in milliseconds, and gives
 * general information about the work done. And close
 * all fds.
 */
static noreturn void stop(int sig)
{
  double elapsed;
  end=clock();
  elapsed=(double)(end-start)/CLOCKS_PER_SEC*1000.0;
  printf("\nEnding %s %ld send packets at %dms\n", __FILE_NAME__, total, (int)elapsed);
  closefds();
  exit(0);
}


/*
 * hexflood.c
 */
int main(int argc, char **argv)
{
  signal(SIGINT, stop);
  run=argv[0];
  if (argc<=1)
    usage();
  startstring();
  parseargs(argc, argv);
  start=clock();
  openfds();
  hexddos();
  return 0;
}
