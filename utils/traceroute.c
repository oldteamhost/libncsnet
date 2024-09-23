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
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <getopt.h>
#include <pthread.h>
#include <float.h>
#include <string.h>

#include "coreutils.h"
#include "utils-config.h"

#include "../ncsnet/dns.h"
#include "../include/transport.h"

#define ECHO_TR      0
#define SYN_TR       1
#define COOKIE_TR    2
#define CRAP_TR      3
#define LITE_CRAP_TR 4
#define LAST_TR      LITE_CRAP_TR

typedef struct __intf_info
{
  const char *devicefind;
  char device[IFNAMSIZ];
  mac_t src;
  ip4_t srcip;
} intf_info_hdr;

typedef struct __traceroute_hop
{
  ip4_t source;
  double rtt_1, rtt_2, rtt_3;
  int hopid, hop;
  bool ok, reached;
} tr_hop_t;

size_t          tmplen;
u8             *tmp;
const char     *run=NULL, *shortopts="hl:H:s:f:I:m:a", *node=NULL;
int             rez=0, id=0, is=0;
char            ip4buf[16];
intf_info_hdr   intfhdr={0};
intf_t         *i=NULL;
ncsnet_t       *n=NULL;
ncstime_t       maxwait=to_ns(150);
int             vvv=0;
const char     *data=NULL;
size_t          datalen=0;
int             proto=ECHO_TR;
int             srcport=8000;
int             dstport=80;
ip4_t           dstip={0};
int             lastidip=0;
int             ttl=1, tos=0, mttl=30;
bool            csrcip=0, csrcmac=0, csrcport=0, all=0;
size_t          nreceived=0, ntransmitted=0;
int             off=0;
tr_hop_t        curhop;

const struct option
            longopts[]={
  {"help", no_argument, 0, 'h'},
  {"echo", no_argument, 0, 1},
  {"cookie", no_argument, 0, 2},
  {"syn", no_argument, 0, 3},
  {"srcport", required_argument, 0, 4},
  {"dstport", required_argument, 0, 5},
  {"hex", required_argument, 0, 'H'},
  {"tos", required_argument, 0, 6},
  {"src", required_argument, 0, 7},
  {"srcmac", required_argument, 0, 8},
  {"maxwait", required_argument, 0, 9},
  {"crap", no_argument, 0, 10},
  {"lite-crap", no_argument, 0, 11},
  {"df", no_argument, 0, 12},
  {"mf", no_argument, 0, 13},
  {"rf", no_argument, 0, 14},
  {"all", no_argument, 0, 'a'}
};


/*
 * Outputs the help menu, and terminates the program.
 */
static noreturn void usage(void)
{
  puts("Usage");
  printf("  %s [flags] <target>\n\n", run);
  puts("  -maxwait <time>  set your timeout");
  puts("  -I <device>      set your interface");
  puts("  -m <ttl>         set max ttl (hops)");
  puts("  -f <ttl>         set first ttl");
  puts("  -H, -hex <hex>   set payload in hex");
  puts("  -s <str>         set payload in string");
  puts("  -l <num>         set payload len");
  puts("  -tos <num>       set type of service");
  puts("  -srcport <num>   set your srcport");
  puts("  -dstport <num>   set your dstport");
  puts("  -src <ip>        set your srcip");
  putchar('\n');
  puts("  -a, -all    use all methods and protos");
  puts("  -echo       use icmp echo packets (default)");
  puts("  -syn        use tcp syn packets");
  puts("  -crap       use udp packets");
  puts("  -lite-crap  use udp-lite packets");
  puts("  -cookie     use sctp cookie packets");
  puts("  -df         set Don't fragment flag");
  puts("  -mf         set More fragment flag");
  puts("  -rf         set Reserved fragment flag");
  puts("  -h, -help   show this help message and exit");
  infohelp();
  exit(0);
}


/*
 * Parses arguments, applies options
 */
static void parsearg(int argc, char **argv)
{
  while ((rez=getopt_long_only(argc, argv, shortopts, longopts, &id))!=-1) {
    switch (rez) {
      case 1: proto=ECHO_TR; break;
      case 3: proto=SYN_TR; break;
      case 2: proto=COOKIE_TR; break;
      case 4:
        srcport=atoi(optarg);
        if (srcport>USHRT_MAX)
          errx(1, "err: srcport only in range (0-%ld)",
            USHRT_MAX);
        csrcport=1;
        break;
      case 5:
        dstport=atoi(optarg);
        if (dstport>USHRT_MAX)
          errx(1, "err: dstport only in range (0-%ld)",
            USHRT_MAX);
        break;
      case 6:
        tos=atoi(optarg);
        if (tos>UCHAR_MAX)
          errx(1, "err: tos only in range (0-%ld)",
            UCHAR_MAX);
        break;
      case 7: ip4t_pton(optarg, &intfhdr.srcip); csrcip=1; break;
      case 8: mact_pton(optarg, &intfhdr.src); csrcmac=1; break;
      case 9: maxwait=delayconv(optarg); break;
      case 10: proto=CRAP_TR; break;
      case 11: proto=LITE_CRAP_TR; break;
      case 12: off|=IP4_DF; break;
      case 13: off|=IP4_MF; break;
      case 14: off|=IP4_RF; break;
      case 'a': all=1; break;
      case 'l':
        datalen=atoi(optarg);
        if (datalen>1400)
          errx(1, "err: maximum ETH payload is (1400), your is \"%d\"", datalen);
        data=random_str(datalen, DEFAULT_DICTIONARY);
        break;
      case 'H':
        data=(char*)hex_ahtoh(optarg, &datalen);
        if (!data)
          errx(0,"err: invalid hex string specification");
        if (datalen>1400)
          errx(1, "err: maximum ETH payload is (1400), your is \"%d\"", datalen);
        break;
      case 's':
        data=optarg;
        datalen=data?strlen(data):0;
        if (datalen>1400)
          errx(1, "err: maximum ETH payload is (1400), your is \"%d\"", datalen);
        break;
      case 'f':
        ttl=atoi(optarg);
        if (ttl>UCHAR_MAX)
          errx(1, "err: ttl only in range (0-%ld)",
            UCHAR_MAX);
        break;
      case 'm':
        mttl=atoi(optarg);
        if (mttl>UCHAR_MAX)
          errx(1, "err: max ttl only in range (0-%ld)",
            UCHAR_MAX);
        break;
      case 'I': intfhdr.devicefind=optarg; break;
      case 'h':
      case '?':
      default:
        usage();
    }
  }
}


/*
 * Creates a package for traceroute, shifts mac header creation
 * to ncssend.
 */
static u8 *build_traceroute_probe(size_t *probelen)
{
  u8 *res=NULL, *ip=NULL, *msg=NULL;
  ip4h_t *iphdr;
  int pr=0;

  switch (proto) {
    case ECHO_TR: pr=PR_ICMP; break;
    case SYN_TR: pr=PR_TCP; break;
    case CRAP_TR: pr=PR_UDP; break;
    case LITE_CRAP_TR: pr=IPPROTO_UDPLITE; break;
    case COOKIE_TR: pr=PR_SCTP; break;
  }


  if (!csrcport)
    srcport=random_srcport();
  switch (pr) {
    case PR_UDP:
      res=udp_build(srcport, dstport, (u8*)data, datalen, probelen);
      udp4_check(res, *probelen, intfhdr.srcip, dstip, false);
      break;
    case PR_ICMP:
      msg=icmp4_msg_echo_build(random_u16(), random_u16(), data, probelen);
      if (!msg)
        return NULL;
      res=icmp_build(ICMP4_ECHO, 0, msg, *probelen, probelen);
      icmp4_check(res, *probelen, false);
      free(msg);
      break;
    case PR_TCP:
      res=tcp_build(srcport, dstport, random_u32(), 0, 0, TCP_FLAG_SYN, 1024, 0, NULL, 0, (u8*)data, datalen, probelen);
      tcp4_check(res, *probelen, intfhdr.srcip, dstip, false);
      break;
    case PR_SCTP:
      msg=sctp_cookie_build(SCTP_COOKIE_ECHO, 0, (u8*)data, datalen, probelen);
      res=sctp_build(srcport, dstport, random_u32(), msg, *probelen, probelen);
      sctp_check(res, *probelen, false, false);
      break;
    case IPPROTO_UDPLITE:
      res=udplite_build(srcport, dstport, (u8*)data, datalen, probelen);
      udplite4_check(res, *probelen, intfhdr.srcip, dstip, 0, false);
      break;

  }
  if (!res)
    return NULL;

  ip=ip4_build(intfhdr.srcip, dstip, pr, ttl, random_u16(), tos, off,
    NULL, 0, res, *probelen, probelen);
  if (!ip) {
    free(res);
    return NULL;
  }

  iphdr=(ip4h_t*)ip;
  lastidip=ntohs(iphdr->id);
  curhop.hop=iphdr->ttl;

  free(res);
  return ip;
}


/*
 * Filters received packets. If the packet came from the target, it
 * puts reached=1 in the current hop, if not, it checks if ttl exeed
 * message came and if it came to us.
 */
static bool __received_traceroute_callback(u8 *frame, size_t frmlen)
{
  mach_t   *datalink;
  icmph_t  *icmphdr;
  ip4h_t   *iphdr, *iphdr_2;

  datalink=(mach_t*)frame;
  if (ntohs(datalink->type)!=ETH_TYPE_IPV4)
    return 0;
  iphdr=(ip4h_t*)(frame+14);
  if (ip4t_compare(dstip, iphdr->src)) {
    curhop.source=iphdr->src;
    return (curhop.reached=1);
  }
  if (iphdr->proto!=PR_ICMP)
    return 0;
  icmphdr=(icmph_t*)(frame+(14+20));
  if (icmphdr->type!=ICMP4_TIMEXCEED)
    return 0;
  if (!ip4t_compare(intfhdr.srcip, iphdr->dst))
    return 0;
  curhop.source=iphdr->src;

  iphdr_2=(ip4h_t*)((frame)+(14+20+(sizeof(icmph_t)+4)));
  if (ntohs(iphdr_2->id)!=lastidip)
    return 0;
  return 1;
}


/*
 * Calculate the response time between two time
 * points in real milliseconds. And update
 * statistics of maximum rtt and minimum rtt.
 */
static double tvrtt(struct timeval *start, struct timeval *end)
{
  double rtt;
  rtt=((((end->tv_sec-start->tv_sec)*1000000+
    (end->tv_usec-start->tv_usec))/1000.0));
  return rtt;
}


/*
 * Prototype callback for filtering.
 */
static bool received_traceroute_callback(u8 *frame, size_t frmlen)
{
  bool ret=0;

  ret=__received_traceroute_callback(frame, frmlen);
  curhop.ok=ret;
  nreceived+=(int)ret;

  if (curhop.ok&&curhop.hopid==0)
    curhop.rtt_1=tvrtt(&n->sock.recvfd.lr->tstamp_s,
      &n->sock.recvfd.lr->tstamp_e);
  else if (curhop.ok&&curhop.hopid==1)
    curhop.rtt_2=tvrtt(&n->sock.recvfd.lr->tstamp_s,
      &n->sock.recvfd.lr->tstamp_e);
  else if (curhop.ok&&curhop.hopid==2)
    curhop.rtt_3=tvrtt(&n->sock.recvfd.lr->tstamp_s,
      &n->sock.recvfd.lr->tstamp_e);

  return ret;
}


/*
 * Callback for interface information.
 */
static int intf_read_callback(const intf_entry *entry, void *arg)
{
  intf_info_hdr *n=(intf_info_hdr*)arg;
  if (n->devicefind)
    if (strcmp(n->devicefind, entry->intf_name))
      return 0;
  if (!(entry->intf_flags&INTF_FLAG_UP)) {
    if (n->devicefind)
      errx(1, "err: interface %s is down!", intfhdr.devicefind);
    return 0;
  }
  if (entry->intf_flags&(INTF_FLAG_LOOPBACK|INTF_FLAG_POINTOPOINT)) {
    if (n->devicefind)
      errx(1, "err: interface %s unsuitable!", intfhdr.devicefind);
    return 0;
  }
  strncpy(n->device, entry->intf_name, IFNAMSIZ-1);
  n->device[IFNAMSIZ-1]='\0';
  if (entry->intf_flags&INTF_FLAG_UP) {
    if (!csrcmac)
      n->src=entry->intf_link_addr.addr_eth;
    if (entry->intf_addr.type==ADDR_TYPE_IP&&!csrcip)
      n->srcip=entry->intf_addr.addr_ip4;

    return 1;
  }
  return 0;
}


/*
 * Get information about the interface.
 */
static bool get_infointf(void)
{
  i=intf_open();
  if (!i)
    return 0;
  if (!(intf_loop(i, intf_read_callback, &intfhdr))) {
    errx(1, "err: interface not found!");
    intf_close(i);
    return 0;
  }
  intf_close(i);
  return 1;
}


/*
 * Receives dns, if it doesn't, it returns (????),
 * otherwise (<dns>).
 */
const char *getdns(ip4_t dst)
{
  static char res[2048+2];
  struct sockaddr_in sa;
  char dnsbuf[2048];

  memset(dnsbuf, 0, sizeof(dnsbuf));
  memset(&sa, 0, sizeof(sa));
  sa.sin_family=AF_INET;
  sa.sin_addr.s_addr=ip4t_u32(&dst);

  if (getnameinfo((struct sockaddr*)&sa,
    sizeof(sa), dnsbuf, sizeof(dnsbuf),
    NULL, 0, 0)==0) {
    snprintf(res, sizeof(res), "(%s)", dnsbuf);
    return res;
  }

  return "(\?\?\?)";
}


/*
 * Called at the SIGINT signal (ctrl+c), or at normal program
 * termination. Outputs statistics if they were not output
 * for the last target, final message, and clears all allocated
 * memory.
 */
static noreturn void finish(int sig)
{

  char date[20];
  struct tm *t;
  time_t now;

  printf("\n----%s TRACEROUTE Statistics----\n", ip4t_ntop_c(&dstip));
  printf("%ld packets transmitted, %ld packets received", ntransmitted, nreceived);
  if (nreceived>ntransmitted)
    printf(" -- somebody's printing up packets!\n");
  else
    printf(", %ld%% packet loss\n", (size_t)
      (((ntransmitted-nreceived)*100) / ntransmitted));
  printf("target %s %s %d hops\n", ip4t_ntop_c(&dstip),
    (curhop.reached)?"was reached in":"has been missed for", curhop.hop);
  putchar('\n');

  now=time(NULL);
  t=localtime(&now);
  strftime(date, sizeof(date), "%H:%M:%S", t);
  printf("Ending %s at %s and clearing the memory\n", __FILE_NAME__, date);

  if (n)
    ncsclose(n);
  exit(0);
}


/*
 * traceroute.c
 */
int main(int argc, char **argv)
{
  signal(SIGINT, finish);
  run=argv[0];
  if (argc<=1)
    usage();
  parsearg(argc, argv);
  if (optind<argc)
    node=argv[optind];
  startstring();
  if (!check_root_perms())
    errx(1, "err: raw sockets on UNIX only sudo, (try \"sudo %s\")",
      argv[0]);
  if ((is=this_is(node))!=IPv6) {
    if (getipv4(node, ip4buf, 16)==-1)
      errx(1, "err: failed resolv for target \"%s\"", node);
    ip4t_pton(ip4buf, &dstip);
  }
  else
    errx(1, "err: only ip4 hosts");
  get_infointf();
  n=ncsopen_s(intfhdr.device);
  if (!n)
    errx(1, "err: failed open socket!");
  ncsopts(n, NCSOPT_PROTO|NCSOPT_RTIMEOUT, PR_IP, maxwait);

  mttl=mttl-(ttl-1); /* fix size */
  for (;mttl;mttl--) {
    printf("%d  ", ttl);
    fflush(stdout);
    for (curhop.hopid=0;curhop.hopid<3;++curhop.hopid) {
      tmp=build_traceroute_probe(&tmplen);
      ncssend(n, tmp, tmplen);
      ntransmitted++;
      free(tmp);
      ncsrecv(n, received_traceroute_callback, 1);
      if (!curhop.ok&&all) {
        if (proto==LAST_TR) {
          proto=0;
          goto print;
        }
        proto++;
        curhop.hopid--;
        continue;
      }
print:
      if (!curhop.ok) {
        putchar('.');
        fflush(stdout);
      }
      else break;
    }
    if (!curhop.ok)
      putchar('\n');
    if (curhop.ok) {
      printf("%s %s    %0.4f %0.4f %0.4f (ms)\n",
        ip4t_ntop_c(&curhop.source), getdns(curhop.source),
        curhop.rtt_1, curhop.rtt_2, curhop.rtt_3);
    }
    if (curhop.reached)
      break;
    ttl++;
  }

  finish(0);
  return 0;
}
