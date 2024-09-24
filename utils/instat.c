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

#include <net/if.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdnoreturn.h>
#include <stdlib.h>
#include <getopt.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <math.h>

#include "coreutils.h"
#include "utils-config.h"

#include "../include/transport.h"

#define SYSCLASSNET "/sys/class/net"

typedef struct __intfstat_live_info_hdr
{
  size_t rx, tx, rxp, txp, rxerrs, txerrs;
  char flags[256];
  u32 flagshex;
  size_t mtu;
  int index;
  int addrlen, qlen;
  char addr[256];
  char brd[256];
  char speed[256];
} intfstat_live_info_t;

size_t                rxtotal, txtotal, rxptotal, txptotal;
size_t                rxpmin, txpmin, rxpmax, txpmax;
size_t                rxmin, txmin, rxmax, txmax;
size_t                tstamp, tstamp1;
const char           *run=NULL, *shortopts="hlLft:u:d:D:l", *node=NULL;
int                   mainfd=0, unit=0, declen=2;
size_t                wait=5, delay=1;
bool                  f=0, loop=0;
intfstat_live_info_t  i, j, res;


/*
 * Outputs the help menu, and terminates the program.
 */
static noreturn void usage(void)
{

  puts("Usage");
  printf("  %s [flags] <interface>\n\n", run);
  puts("  -t <sec>  set seconds for monitoring");
  puts("  -u <0-2>  set unit for traffic prefix");
  puts("  -d <len>  set declen i.e, 10.<len>");
  puts("  -D <sec>  set delay for read");
  putchar('\n');
  puts("  -L  display list interfaces");
  puts("  -l  infinity, live, loop monitoring");
  puts("  -f  quit on first reply (default)");
  puts("  -h  show this help message and exit");
  infohelp();
  exit(0);
}


static void intfstat_display_interfaces(void)
{
  struct dirent *entry=NULL;
  DIR *dp=NULL;
  if (!(dp=opendir(SYSCLASSNET)))
    errx(1, "err: failed %s open!",
        SYSCLASSNET);
  while ((entry = readdir(dp))) {
    if (entry->d_name[0] == '.')
      continue;
    printf("%s  ", entry->d_name);
  }
  putchar('\n');
  closedir(dp);
  exit(0);
}


/*
 * Parses the arguments, includes the desired options, and
 * stores the specified value.
 */
static void parseargs(int argc, char **argv)
{
  int rez;
  while ((rez=getopt(argc, argv, shortopts))!=-1){
    switch (rez) {
      case 'L': intfstat_display_interfaces(); break;
      case 't': wait=atoll(optarg); break;
      case 'f': f=1; break;
      case 'u': unit=atoi(optarg); if (!(unit<=2)) errx(1, "err: please select unit in this range (0-3)"); break;
      case 'd': declen=atoi(optarg); break;
      case 'D': delay=atoll(optarg); break;
      case 'l': loop=1;  break;
      case 'h':
      case '?':
      default:
        usage();
    }
  }
}


char *genpath(const char *intf, const char *prepath, char *buf, size_t buflen)
{
  memset(buf, 0, buflen);
  snprintf(buf, buflen, "%s/%s%s%s",
    SYSCLASSNET, intf, (prepath)?"/":"",
    (prepath)?prepath:"");
  return buf;
}


bool getfileinfo(int fd, const char *path, const char *fmt, ...)
{
  ssize_t      bytes=0, linelen=0;
  char         line[BUFSIZ];
  char         buf[BUFSIZ];
  char        *ptr;
  va_list      ap;
  int          fd_m;

  if (!fd) {
    fd_m=open(path, O_RDONLY);
    if (fd_m<0)
      return false;
  }
  else fd_m=fd;

  bytes=read(fd_m, buf, sizeof(buf)-1);
  if (bytes<=0) {
    if (!fd)
      close(fd_m);
    return false;
  }

  buf[bytes]='\0';
  ptr=buf;
  while (*ptr&&*ptr!='\n')
    line[linelen++]=*ptr++;
  line[linelen]='\0';

  va_start(ap, fmt);
  vsscanf(line, fmt, ap);
  va_end(ap);

  if (!fd)
    close(fd_m);
  return true;
}


char *getfilestr(int fd, const char *path, char *buf, size_t buflen)
{
  memset(buf, 0, buflen);
  if (getfileinfo(fd, path, "%s", buf))
    return buf;
  return NULL;
}

/*
 * GNU General Public License v2.0 (vnstat)
 * vergoh
 */

#define IEC_UNITMODE   1
#define JEDEC_UNITMODE 2
#define SI_UNITMODE    3

#define DECCONV      "'"
#define UNITPRFXSNUM 7


static const char *unitpfx(int unitmode, int index)
{
  const char *unitpfxs[]={"na",
    "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", /* IEC */
    "B", "KB",  "MB",  "GB",  "TB",  "PB",  "EB",  /* JEDEC */
    "B", "kB",  "MB",  "GB",  "TB",  "PB",  "EB"   /* SI */
  };
  if (index>=UNITPRFXSNUM)
    return *unitpfxs;
  return *(unitpfxs+(unitmode*UNITPRFXSNUM)+index);
}


static const char *unitratepfx(int unitmode, int index)
{
  const char *unitratepfxs[]={"na",
    "B/s",   "KiB/s",   "MiB/s",   "GiB/s",   "TiB/s",   "PiB/s",   "EiB/s",   /* IEC */
    "B/s",   "KB/s",    "MB/s",    "GB/s",    "TB/s",    "PB/s",    "EB/s",    /* JEDEC */
    "B/s",   "kB/s",    "MB/s",    "GB/s",    "TB/s",    "PB/s",    "EB/s",    /* SI */
    "bit/s", "Kibit/s", "Mibit/s", "Gibit/s", "Tibit/s", "Pibit/s", "Eibit/s", /* IEC */
    "bit/s", "kbit/s",  "Mbit/s",  "Gbit/s",  "Tbit/s",  "Pbit/s",  "Ebit/s"   /* SI */
  };
  if (index>=UNITPRFXSNUM)
    return *unitratepfxs;
  return *(unitratepfxs+(unitmode*UNITPRFXSNUM)+index);
}


static size_t unitdivisor(int unitmode, int index)
{
  if (index>UNITPRFXSNUM)
    return 1;
  if (unitmode == 2 || unitmode == 4)
    return (size_t)(pow(1000, index - 1));
  return (size_t)(pow(1024, index - 1));
}


static int unitspacing(int len, int unitmode, int index)
{
  int l=len;

  /*
   * tune spacing according to unit
   * +1 for space between number and unit
   */
  l-=(int)strlen(unitpfx(unitmode, index))+1;
  if (l < 0)
    l = 1;

  return l;
}


static char *ratestr(int unit, size_t rate, int len, int declen)
{
  static char buffer[256];
  int l, i, p=1024;
  size_t limit;

  if (unit==2||unit==4)
    p=1000;

  for (i=UNITPRFXSNUM-1;i>0;i--) {
    limit=(size_t)(pow(p, i-1))*1000;
    if (rate>=limit) {
      l=unitspacing(len, unit, i+1);
      snprintf(buffer, sizeof(buffer), "%" DECCONV "*.*f %s",
        l, declen, (double)rate/(double)(unitdivisor(unit, i+1)),
        unitratepfx(unit, i+1));
      return buffer;
    }
  }

  l=unitspacing(len, unit, 1);
  snprintf(buffer, sizeof(buffer), "%" DECCONV "*.0f %s",
    l, (double)rate/(double)(unitdivisor(unit, 1)),
    unitratepfx(unit, 1));
  return buffer;
}


static char *trafficrate(size_t bytes, time_t interval, int len, int rateunit, int declen)
{
  static char buffer[256];
  size_t b=bytes;

  if (interval==0) {
    snprintf(buffer, sizeof(buffer), "%*s", len, "n/a");
    return buffer;
  }
  if (rateunit==1)
    b*=8;
  return ratestr(rateunit, b/(size_t)interval,
      len, declen);
}


size_t ccalc(size_t *a, size_t *b, short issize_t)
{
  if (*b >= *a)
   return *b - *a;
  else {
    if (*a>sizeof(u32)||*b>sizeof(u32)
      ||issize_t==1)
      return SIZE_MAX-*a+*b;
    else
      return sizeof(u32)-*a+*b;
  }
}


static void live_info_other(intfstat_live_info_t *i)
{
  char tmpbuf[BUFSIZ];
  char path[1024];

  getfilestr(0, genpath(node, "mtu",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->mtu=strtoull(tmpbuf, NULL, 0);
  getfilestr(0, genpath(node, "ifindex",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->index=atoi(tmpbuf);
  getfilestr(0, genpath(node, "addr_len",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->addrlen=atoi(tmpbuf);
  getfilestr(0, genpath(node, "address",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  snprintf(i->addr, i->addrlen*8, "%s", tmpbuf);
  getfilestr(0, genpath(node, "speed",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  if (tmpbuf[0]!='\0')
    snprintf(i->speed, sizeof(i->speed), "%s Mbit/s", tmpbuf);
  else
    snprintf(i->speed, sizeof(i->speed), "0");
  getfilestr(0, genpath(node, "broadcast",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  snprintf(i->brd, sizeof(i->brd), "%s", tmpbuf);
  getfilestr(0, genpath(node, "tx_queue_len",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->qlen=atoi(tmpbuf);
}


static void live_info_stats(intfstat_live_info_t *i)
{
  char tmpbuf[BUFSIZ];
  char path[1024];

  getfilestr(0, genpath(node, "statistics/rx_bytes",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->rx=strtoull(tmpbuf, NULL, 0);
  getfilestr(0, genpath(node, "statistics/tx_bytes",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->tx=strtoull(tmpbuf, NULL, 0);
  getfilestr(0, genpath(node, "statistics/tx_packets",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->txp=strtoull(tmpbuf, NULL, 0);
  getfilestr(0, genpath(node, "statistics/rx_packets",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->rxp=strtoull(tmpbuf, NULL, 0);
  getfilestr(0, genpath(node, "statistics/rx_errors",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->rxerrs=strtoull(tmpbuf, NULL, 0);
  getfilestr(0, genpath(node, "statistics/tx_errors",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));
  i->txerrs=strtoull(tmpbuf, NULL, 0);
}


static void live_info_flags(intfstat_live_info_t *i)
{
  char tmpbuf[BUFSIZ];
  char path[1024];
  u32 flags=0;
  int j=0;

  getfilestr(0, genpath(node, "flags",
    path, sizeof(path)), tmpbuf, sizeof(tmpbuf));

  if (tmpbuf[0]=='0'&&(tmpbuf[1]=='x'||tmpbuf[1]=='X')) j=2;
  while(tmpbuf[j]!='\0') {
    flags=(flags<<4)|chex_atoh(tmpbuf[j]);
    j++;
  }
  i->flagshex=flags;
  snprintf(i->flags, sizeof(i->flags),
      "<%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
#if defined (IFF_LOWER_UP)
      "%s"
#endif
#if defined (IFF_DORMANT)
      "%s"
#endif
#if defined (IFF_ECHO)
      "%s"
#endif
      ">" ,
    (flags&IFF_UP)?"UP,":"",
    (flags&IFF_BROADCAST)?"BROADCAST,":"",
    (flags&IFF_DEBUG)?"DEBUG,":"",
    (flags&IFF_LOOPBACK)?"LOOPBACK,":"",
    (flags&IFF_POINTOPOINT)?"POINTTOPOINT,":"",
    (flags&IFF_NOTRAILERS)?"NOTRAILERS,":"",
    (flags&IFF_RUNNING)?"RUNNING,":"",
    (flags&IFF_NOARP)?"NOARP,":"",
    (flags&IFF_PROMISC)?"PROMISC,":"",
    (flags&IFF_ALLMULTI)?"ALLMULTI,":"",
    (flags&IFF_MASTER)?"MASTER,":"",
    (flags&IFF_SLAVE)?"SLAVE,":"",
    (flags&IFF_MULTICAST)?"MULTICAST,":"",
    (flags&IFF_PORTSEL)?"PORTSEL,":"",
    (flags&IFF_AUTOMEDIA)?"AUTOMEDIA,":"",
    (flags&IFF_DYNAMIC)?"DYNAMIC,":""
#if defined (IFF_LOWER_UP)
    ,(flags&IFF_LOWER_UP)?"LOWER_UP,":""
#endif
#if defined (IFF_DORMANT)
    ,(flags&IFF_DORMANT)?"DORMANT,":""
#endif
#if defined (IFF_ECHO)
    ,(flags&IFF_ECHO)?"ECHO,":""
#endif
  );
  if (i->flags[strlen(i->flags)-2]==',') {
    i->flags[strlen(i->flags)-2]='>';
    i->flags[strlen(i->flags)-1]='\0';
  }
}


static void live_info(intfstat_live_info_t *i)
{
  live_info_flags(i);
  live_info_stats(i);
  live_info_other(i);
}


static void finish(void)
{
  char date[20];
  struct tm *t;
  time_t now;

  now=time(NULL);
  t=localtime(&now);
  strftime(date, sizeof(date), "%H:%M:%S", t);
  printf("Ending %s at %s and clearing the memory\n",
    __FILE_NAME__, date);
}


static noreturn void finish_live(int sig)
{
  tstamp1=((size_t)time(NULL))-(tstamp1);
  printf("\n----%s INTFSTAT Statistics----\n", node);
  printf("total %ld/%ld bytes, %ld/%ld pkts (rx/tx)\n",
      rxtotal, txtotal, rxptotal, txptotal);
  printf("rx and tx (pkts) min/avg/max %ld/%ld/%ld|%ld/%ld/%ld\n",
      rxpmin/delay, rxptotal/tstamp1,rxpmax/delay,
      txpmin/delay, txptotal/tstamp1, txpmax/delay);
  printf("rx min %s....", trafficrate(rxmin, delay, 1, unit, declen));
  printf("avg %s....", trafficrate(rxtotal, (time_t)tstamp1, 1, unit, declen));
  printf("max %s\n", trafficrate(rxmax, delay, 1, unit, declen));
  printf("tx min %s....", trafficrate(txmin, delay, 1, unit, declen));
  printf("avg %s....", trafficrate(txtotal, (time_t)tstamp1, 1, unit, declen));
  printf("max %s", trafficrate(txmax, delay, 1, unit, declen));
  putchar('\n');
  putchar('\n');
  finish();
  exit(0);
}


/*
 * instat.c
 */
int main(int argc, char **argv)
{
  char path[BUFSIZ];
  run=argv[0];
  if (argc<=1)
    usage();
  parseargs(argc, argv);
  if (optind<argc)
    node=argv[optind];

  genpath(node, NULL, path, sizeof(path));
  mainfd=open(path, O_RDONLY);
  if (mainfd<0) {
    printf("err: interface %s not found! (Check list interfaces \"%s -L\")\n", node, run);
    exit(1);
  }
  close(mainfd);

  startstring();

  rxtotal=txtotal=rxptotal=txptotal=rxpmax=txpmax=0;
  rxpmin=txpmin=rxmin=txmin=SIZE_MAX;
  rxmax=txmax=0;
  signal(SIGINT, finish_live);
  tstamp1=(size_t)time(NULL);

  live_info(&j);
  printf("%s: id=%d speed=%s flags=%s mtu=%ld\n  qlen=%d addr=%s brd=%s\n\n",
    node, j.index, j.speed, j.flags, j.mtu, j.qlen, j.addr, j.brd);
  for (;;) {
    tstamp=(size_t)time(NULL);
    if (!f&&!loop&&(tstamp-tstamp1)>=wait)
      finish_live(0);
    else {
      if (f)
        if ((tstamp-tstamp1)>=15)
          printf("It looks like this interface is not being used, try (Ctrl+C).\n");
    }
    delayy((delay*1000));
    tstamp=((size_t)time(NULL)-tstamp);

    i.rx=j.rx;
    i.tx=j.tx;
    i.rxp=j.rxp;
    i.txp=j.txp;
    i.txerrs=j.txerrs;
    i.rxerrs=j.rxerrs;

    live_info(&j);

    res.rx=ccalc(&i.rx, &j.rx, 1);
    res.tx=ccalc(&i.tx, &j.tx, 1);
    res.rxp=ccalc(&i.rxp, &j.rxp, 1);
    res.txp=ccalc(&i.txp, &j.txp, 1);
    res.rxerrs=ccalc(&i.rxerrs, &j.rxerrs, 1);
    res.txerrs=ccalc(&i.txerrs, &j.txerrs, 1);

    if (f&&!res.rx&&!res.tx&&!res.rxp&&!res.txp)
      continue;

    rxtotal+=res.rx;
    txtotal+=res.tx;
    rxptotal+=res.rxp;
    txptotal+=res.txp;

    if (rxmin>res.rx)
      rxmin=res.rx;
    if (txmin>res.tx)
      txmin=res.tx;
    if (rxmax<res.rx)
      rxmax=res.rx;
    if (txmax<res.tx)
      txmax=res.tx;
    if (rxpmin>res.rxp)
      rxpmin=res.rxp;
    if (txpmin>res.txp)
      txpmin=res.txp;
    if (rxpmax<res.rxp)
      rxpmax=res.rxp;
    if (txpmax<res.txp)
      txpmax=res.txp;

    printf("%s stats:", node);
    if (res.rxerrs||res.txerrs) {
      putchar(' ');
      if (res.rxerrs)
        printf("tx=%ld", res.rxerrs);
      if (res.rxerrs&&res.txerrs)
        printf("/");
      if (res.txerrs)
        printf("rx=%ld", res.txerrs);
      printf(" errs....");
    }
    else putchar(' ');
    printf("rx=%s", trafficrate(res.rx, delay, 1,
      unit, declen));
    printf("....tx=%s....%ld/%ld pps\n", trafficrate(res.tx,
      delay, 1, unit, declen), res.rxp/delay,
      res.txp/delay);
    if (f)
      finish_live(0);
  }

  return 0;
}
