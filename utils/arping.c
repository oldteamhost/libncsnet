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

#include "../include/network.h"

typedef struct __intf_info
{
  const char *devicefind;
  char device[IFNAMSIZ];
  mac_t src;
  ip4_t srcip;
} intf_info_hdr;

arp_op_request_ethip *arpreq=NULL;
const char           *run=NULL, *node=NULL, *shortopts="hI:w:bn:fs:i:o:ve0BDt:";
int                   is=0, rez=0;
char                  ip4buf[16]={0};
eth_t                *eth=NULL;
intf_info_hdr         intfhdr={0};
intf_t               *i=NULL;
bool                  b=0, reply_state=2, f=0, csrc=0, yes=0, v=0,
                        e=0, _0=0, B=0, D=0, t=0;
ip4_t                 target={0};
u8                   *req=NULL;
size_t                reqlen=0, rbytes=0, num=10, totalnum=0;
size_t                nreceived=0, ntransmitted=0;
double                tsum=0.0, tmin=DBL_MAX, tmax=-DBL_MAX;
ncstime_t             wait=to_ns(1000), delay=to_ns(1000);
const char           *tmpmac=NULL;
lr_t                 *lr=NULL;
u8                   *received=NULL;
u16                   arphdr=ARP_HDR_ETH, op=ARP_OP_REQUEST;
const char           *arpreplytype=NULL;
mac_t                *dstmac_eth=NULL;
double                currtt=0.0;


/*
 * Outputs the help menu, and terminates the program.
 */
static noreturn void usage(void)
{
  puts("Usage");
  printf("  %s [flags] <target>\n\n", run);
  puts("  -I <device>  set your interface and his info");
  puts("  -n <count>   set how many packets to send");
  puts("  -o <num>     set your num operation, advice 1-4");
  puts("  -i <time>    set interval between packets, ex: see down");
  puts("  -w <time>    set wait time or timeout, ex: 10s or 10ms");
  puts("  -t <mac>     set obviously target mac");
  putchar('\n');
  puts("  -b  keep on broadcasting, do not unicast");
  puts("  -f  quit on first reply");
  puts("  -0  use IP address 0.0.0.0 in spa");
  puts("  -B  use IP address 255.255.255.255 how target");
  puts("  -D  display line mode (! reply) (. noreply)");
  puts("  -e  display info in easy (wireshark) style");
  puts("  -v  display all info, very verbose");
  puts("  -h  show this help message and exit");
  infohelp();
  exit(0);
}


/*
 * Outputs arp packet information in a simple format,
 * something like,
 * ... bytes ... > ... ARP Who has ...? Tell ...
 * ... bytes ... > ... ARP ... at ... ... ms
 */
static void arping_arp_info_easy(u8 *arp, size_t arplen, double rtt)
{
  arp_op_request_ethip *arpreqhdr;
  char mactmp_1[MAC_ADDR_STRING_LEN+1];
  char mactmp_2[MAC_ADDR_STRING_LEN+1];
  char mactmp[MAC_ADDR_STRING_LEN+1];
  char ip4tmp[IP4_ADDR_STRING_LEN+1];
  mach_t *datalink;
  arph_t *arphdr;

  datalink=(mach_t*)arp;

  if (arplen>sizeof(mach_t)) {
    arphdr=(arph_t*)(arp+ETH_HDR_LEN);
    if (arplen>(sizeof(mach_t)+sizeof(arph_t))) {
      arpreqhdr=(arp_op_request_ethip*)((arp)+(ETH_HDR_LEN+sizeof(arph_t)));
      if (ntohs(arphdr->op)==ARP_OP_REQUEST) {
        ip4t_ntop(&arpreqhdr->spa, ip4tmp, sizeof(ip4tmp));
        mact_ntop(&datalink->dst, mactmp, sizeof(mactmp));
        printf("%ld bytes %s > %s ARP Who has %s? Tell %s",
          arplen, mact_ntop_c(&datalink->src), mactmp,
          ip4t_ntop_c(&arpreqhdr->tpa), ip4tmp);
      }
      else if (ntohs(arphdr->op)==ARP_OP_REPLY) {
        mact_ntop(&datalink->dst, mactmp, sizeof(mactmp));
        mact_ntop(&datalink->src, mactmp_1, sizeof(mactmp_1));
        printf("%ld bytes %s > %s ARP %s at %s",
          arplen, mactmp_1, mactmp, ip4t_ntop_c(&arpreqhdr->tpa),
          mact_ntop_c(&arpreqhdr->sha));
      }
      else if (ntohs(arphdr->op)==ARP_OP_RARP_REPLY) {
        mact_ntop(&datalink->dst, mactmp, sizeof(mactmp));
        mact_ntop(&datalink->src, mactmp_1, sizeof(mactmp_1));
        printf("%ld bytes %s > %s RARP %s is at %s",
          arplen, mactmp_1, mactmp, mact_ntop_c(&arpreqhdr->tha),
          ip4t_ntop_c(&arpreqhdr->tpa));
      }
      else if (ntohs(arphdr->op)==ARP_OP_RARP_REQUEST) {
        mact_ntop(&datalink->dst, mactmp_2, sizeof(mactmp_2));
        mact_ntop(&datalink->src, mactmp_1, sizeof(mactmp_1));
        mact_ntop(&arpreqhdr->sha, mactmp, sizeof(mactmp));
        printf("%ld bytes %s > %s RARP Who is %s? Tell %s",
          arplen, mactmp_1, mactmp_2, mact_ntop_c(&arpreqhdr->tha),
          mactmp);
      }
    }
  }
  if (rtt)
    printf(" %0.4f ms\n", rtt);
  else
    putchar('\n');
}


/*
 * Outputs all the information about the arp packet,
 * something like,
 * ... bytes ... > ... [...] hdr=... hln=... op=... pln=... pro=...
 *   req ...|... > ...|...
 */
static void arping_arp_info(u8 *arp, size_t arplen, double rtt)
{
  char mactmp_1[MAC_ADDR_STRING_LEN+1];
  char mactmp_2[MAC_ADDR_STRING_LEN+1];
  char mactmp[MAC_ADDR_STRING_LEN+1];
  char ip4tmp[IP4_ADDR_STRING_LEN+1];
  arp_op_request_ethip *arpreqhdr;
  mach_t *datalink;
  arph_t *arphdr;

  datalink=(mach_t*)arp;
  mact_ntop(&datalink->src, mactmp_1, sizeof(mactmp_1));
  mact_ntop(&datalink->dst, mactmp_2, sizeof(mactmp_2));
  printf("%ld bytes %s > %s [%hu]", arplen,
    mactmp_1, mactmp_2, ntohs(datalink->type));

  if (arplen>sizeof(mach_t)) {
    arphdr=(arph_t*)(arp+ETH_HDR_LEN);
    printf(" hdr=%hu hln=%hhu op=%hu pln=%hhu pro=%hu", ntohs(arphdr->hdr),
      arphdr->hln, ntohs(arphdr->op), arphdr->pln, ntohs(arphdr->pro));
    if (arplen>(sizeof(mach_t)+sizeof(arph_t))) {
      arpreqhdr=(arp_op_request_ethip*)((arp)+ETH_HDR_LEN+sizeof(arph_t));
      mact_ntop(&arpreqhdr->sha, mactmp, sizeof(mactmp));
      ip4t_ntop(&arpreqhdr->tpa, ip4tmp, sizeof(ip4tmp));
      printf("\n  req %s|%s > %s|%s", mactmp,
        ip4t_ntop_c(&arpreqhdr->spa), mact_ntop_c(&arpreqhdr->tha),
        ip4tmp);
    }
  }

  if (rtt)
    printf(" %0.4f ms\n", rtt);
  else
    putchar('\n');
}


/*
 * Callback to receive arp, checks payload type, operation,
 * header, protocol, address length, and whether the sender's
 * ip matches the receiver's ip.
 */
static bool __received_arp_callback(u8 *frame, size_t frmlen)
{
  mach_t *datalink;
  arph_t *arp;

  datalink=(mach_t*)frame;

  /* The payload type will definitely be ARP */
  if (ntohs(datalink->type)!=ETH_TYPE_ARP)
    return 0;

  arp=(arph_t*)(frame+sizeof(mach_t));

  switch (ntohs(arp->op)) {
    case ARP_OP_REPLY: arpreplytype="arp-reply"; break;
    case ARP_OP_REQUEST: arpreplytype="arp-request"; break;
    case ARP_OP_RARP_REPLY: arpreplytype="rarp-reply"; break;
    case ARP_OP_RARP_REQUEST: arpreplytype="rarp-request"; break;
    default: return 0;
  }

  /* ARPHRD check and this darned FDDI hack here :-(
   * iputils/arping.c */
  if (ntohs(arp->hdr)!=arphdr&&
    (arphdr!=ARP_HRD_FDDI||
     ntohs(arp->hdr)!=htons(ARP_HDR_ETH)))
    return 0;
  if (ntohs(arp->hdr)==ARP_HDR_AX25||
    ntohs(arp->hdr)==ARP_HDR_RESERVED) {
    if (ntohs(arp->pro)!=AX25_PRO_IP)
      return 0;
  }
  else if (ntohs(arp->pro)!=ARP_PRO_IP)
    return 0;

  if (arp->pln!=4) /* only ipv4 */
    return 0;
  if (arp->hln!=6) /* only mac as long as 6*/
    return 0;

  /*
   * The ip4 address of the recipient inside
   * the ARP request must match the local ip4
   * address, otherwise, the packet was not
   * addressed to us.
   */
  arpreq=(arp_op_request_ethip*)((frame)+(sizeof(mach_t)+sizeof(arph_t)));
  if (!ip4t_compare(arpreq->tpa, intfhdr.srcip))
    return 0;

  return 1;
}


/*
 * Prototype callback for arp reception.
 */
static bool received_arp_callback(u8 *frame, size_t frmlen, void *arg)
{
  reply_state=__received_arp_callback(frame, frmlen);
  if (reply_state)
    nreceived++;
  return reply_state;
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
  if (entry->intf_flags&(INTF_FLAG_LOOPBACK|INTF_FLAG_NOARP)) {
    if (n->devicefind)
      errx(1, "err: interface %s is not ARPable!", intfhdr.devicefind);
    return 0;
  }
  strncpy(n->device, entry->intf_name, IFNAMSIZ-1);
  n->device[IFNAMSIZ-1]='\0';
  if (entry->intf_flags&INTF_FLAG_UP) {
    if (!csrc)
      n->src=entry->intf_link_addr.addr_eth;
    ip4t_fill(&n->srcip, 0, 0, 0, 0);
    if (entry->intf_addr.type==ADDR_TYPE_IP&&!_0)
      n->srcip=entry->intf_addr.addr_ip4;

    return 1;
  }
  return 0;
}


/*
 * Create an arp probe, initially broadcast mac as the destination mac, then
 * if -b is not enabled and a response is received, replace it with the
 * actual destination mac address.
 */
static void build_arp(void)
{
  size_t  arplen, arpoplen;
  u8     *arp, *arp_op;
  mac_t   dstmac_arp;

  mact_fill(&dstmac_arp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  if (!b&&reply_state&&arpreq)
    *dstmac_eth=arpreq->sha;
  if (t)
    mact_pton(tmpmac, dstmac_eth);

  arp_op=arp_op_request_build(MAC_ADDR_LEN, IP4_ADDR_LEN,
    intfhdr.src.octet, intfhdr.srcip.octet, dstmac_arp.octet,
    target.octet, &arpoplen);
  if (!arp_op)
    return;
  arp=arp_build(arphdr, ARP_PRO_IP, MAC_ADDR_LEN, IP4_ADDR_LEN, op, arp_op, arpoplen, &arplen);
  free(arp_op);
  if (!arp)
    return;
  req=eth_build(intfhdr.src, *dstmac_eth, ETH_TYPE_ARP, arp, arplen, &reqlen);
  free(arp);

  if (v)
    arping_arp_info(req, reqlen, 0);
  else if (e)
    arping_arp_info_easy(req, reqlen, 0);
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
    intf_close(i);
    errx(1, "err: interface not found!");
  }
  intf_close(i);
  return 1;
}


/*
 * A delay of a specified number of nanoseconds
 */
static void nsdelay(long long ns)
{
  struct timespec req, rem;
  req.tv_sec=(ns/1000000000);
  req.tv_nsec=(ns%1000000000);
  nanosleep(&req, &rem);
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
  tsum+=rtt;
  if (rtt>tmax)
    tmax=rtt;
  if (rtt<tmin)
    tmin=rtt;

  return rtt;
}


/*
 * Called at the SIGINT signal (ctrl+c), or at normal program
 * termination. Outputs statistics if they were not output
 * for the last target, final message, and clears all allocated
 * memory.
 */
static noreturn void finish(int sig)
{
  struct tm *t=NULL;
  char date[20]={0};
  time_t now=0;

  now=time(NULL);
  t=localtime(&now);

  if (!D) {
    printf("\n----%s ARPING Statistics----\n", ip4t_ntop_c(&target));
    printf("%ld packets transmitted, %ld packets received",
      ntransmitted, nreceived);
    if (ntransmitted) {
      if (nreceived>ntransmitted)
        printf(" -- somebody's printing up packets!\n");
      else
        printf(", %ld%% packet loss\n", (size_t)
          (((ntransmitted-nreceived)*100)/ntransmitted));
    }
    if (nreceived)
      printf("round-trip (ms)  min/avg/max = %f/%f/%f\n",
        tmin, tsum / nreceived, tmax);
    putchar('\n');
    strftime(date, sizeof(date), "%H:%M:%S", t);
    printf("Ending %s at %s and clearing the memory\n",
      __FILE_NAME__, date);
  }
  else {
    if (nreceived>ntransmitted)
      printf(" 0%% packet loss\n");
    if (ntransmitted) {
      printf(" %ld%% packet loss\n", (size_t)
        (((ntransmitted-nreceived)*100)/ntransmitted));
    }
  }
  if (dstmac_eth)
    free(dstmac_eth);
  if (received)
    free(received);
  if (nreceived)
    exit(0);
  else
    exit(1);
}


/*
 * Parses arguments, applies options
 */
static void parsearg(int argc, char **argv)
{
  while ((rez=getopt(argc, argv, shortopts))!=-1) {
    switch (rez) {
      case 'I': intfhdr.devicefind=optarg; break;
      case 'w': wait=delayconv(optarg); break;
      case 'i': delay=delayconv(optarg); break;
      case 'b': b=1; break;
      case 'n': num=atoll(optarg); break;
      case 'f': num=1; f=1; break;
      case 's': csrc=1; mact_pton(optarg, &intfhdr.src); break;
      case 'o': op=atoi(optarg); break;
      case 'v': v=1; break;
      case 'e': e=1; break;
      case '0': _0=1; break;
      case 'B': B=1; break;
      case 'D': D=1; break;
      case 't': t=1; tmpmac=optarg; break;
      case 'h':
      case '?':
      default: usage();
    }
  }
}


/*
 * arping.c
 */
int main(int argc, char **argv)
{
  signal(SIGINT, finish);
  run=argv[0];
  if (argc<=1)
    usage();
  parsearg(argc, argv);
  if (optind<argc&&!B)
    node=argv[optind];
  if (!D)
    startstring();
  if (B)
    ip4t_fill(&target, 255, 255, 255, 255);
  if (!check_root_perms())
    errx(1, "err: raw sockets on UNIX only sudo, (try \"sudo %s\")",
      argv[0]);
  if (!(get_infointf()))
    errx(1, "err: interface %s not found!", intfhdr.devicefind);
  eth=eth_open(intfhdr.device);
  if (!eth)
    errx(1, "err: failed open socket!");
  if (!B) {
    if ((is=this_is(node))!=IPv6) {
      if (getipv4(node, ip4buf, 16)==-1)
        errx(1, "err: failed resolv for target \"%s\"", node);
      ip4t_pton(ip4buf, &target);
    }
    else
      errx(1, "err: only ip4 hosts");
  }
  lr=lr_open(intfhdr.device, wait);
  if (!lr)
    errx(1, "err: failed open recv socket!");
  lr_callback(lr, received_arp_callback);
  received=(u8*)calloc(1, 256);
  dstmac_eth=(mac_t*)calloc(1, sizeof(mac_t));
  mact_fill(dstmac_eth, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

  totalnum=num;
  for (;num;num--) {
    build_arp();
    if ((eth_send(eth, req, reqlen))>0) {
      ntransmitted++;
      rbytes=lr_live(lr, &received, 256, NULL);
      if (reply_state) {
        currtt=tvrtt(&lr->tstamp_s, &lr->tstamp_e);
        if (v)
          arping_arp_info(received, rbytes, currtt);
        else if (e)
          arping_arp_info_easy(received, rbytes, currtt);
        else if (!D)
          printf("%ld bytes from %s %s (%s) id=%ld time=%.4f ms\n",
            rbytes, arpreplytype, ip4t_ntop_c(&arpreq->spa),
            mact_ntop_c(&arpreq->sha), (totalnum-num), currtt);
      }
      else {
        if (!D)
          printf("The last transmission was not answered "
            "within the specified timeout!\n");
        if (f)
          num++;
      }
    }
    if (D) {
      putchar((reply_state)?'!':'.');
      fflush(stdout);
    }
    if (req)
      free(req);
    if ((num-1))
      nsdelay(delay);
  }

  finish(0);
  return 0;
}
