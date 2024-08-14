/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer. 2. Redistributions in binary form must reproduce the above copyright notice,
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
#include <stdbool.h>
#include <getopt.h>
#include <stdnoreturn.h>

#include "coreutils.h"
#include "utils-config.h"

#include "../ncsnet/log.h"
#include "../ncsnet/utils.h"
#include "../ncsnet/udp.h"
#include "../ncsnet/tcp.h"
#include "../ncsnet/ip.h"
#include "../ncsnet/icmp.h"
#include "../ncsnet/linuxread.h"
#include "../ncsnet/dns.h"
#include "../ncsnet/trace.h"

#define MODE_ICMP IPPROTO_ICMP
#define MODE_TCP  IPPROTO_TCP
#define MODE_UDP  IPPROTO_UDP
#define MODE_SCTP IPPROTO_SCTP

/*
 * This is where a message like:
 *   <bytes_received> bytes from <protocol> <ip>[? :<port>] [? ([dns])]: <various_information> time=<rttms> ms
 *
 * <various_information> for,
 *   icmp:     icmp_seq=<seq> ttl=<ttl>
 *   tcp:      flags=<tcpflags> ttl<ttl>
 *   udp:      ttl=<ttl>
 *   sctp:     chunk=<chunk> vtag=<vtag> ttl=<ttl>
 *   icmperr:  [? srcport=<srcport>] [? icmp_seq=<seq>] <(error)>
 */
char        v0msg[4096];

size_t      triptime=0;
size_t      tmin=999999999;
size_t      tmax=0;
size_t      tsum=0;
int         vvv=0;
long long   maxwait=to_ns(10000); /* classic 10s timeout */
size_t      npackets=10;          /* classic 10 requests per host */
const char *v123msg;              /* trace pkt msg */
bool        filter=0;
size_t      nreceived=0;
u8         *packet;
bool        noreply=0;

static bool received_ping_sctp_callback(u8 *frame, size_t frmlen, ip4h_t *ip);
static bool received_ping_udp_callback(u8 *frame, size_t frmlen, ip4h_t *ip);
static bool received_ping_tcp_callback(u8 *frame, size_t frmlen, ip4h_t *ip);
static bool received_ping_icmp_callback(u8 *frame, size_t frmlen, ip4h_t *ip);
static bool received_ping_callback(u8 *frame, size_t frmlen);
static void tvsub(struct timeval *out, struct timeval *in);
static void pr_pack(u8 *buf, ssize_t cc);
static void tvrtt(void);

struct sockaddr_storage
           *src, *dst;
int         fd;
size_t      ntransmitted=0;
bool        rxc=0, txc=0, origc=0;
size_t      rx, tx, orig;
u8          ipopt[256];
int         ipopts_first_hop_offset, ipopts_last_hop_offset, ipoptslen;
int         optsnum=0;
u8         *tcpopt=NULL;
size_t      tcpoptlen=0;
int         mtu=0;
bool        df=0,mf=0,evil=0;
u32         mask;
lr_t       *lr;
int         tos=0;
int         dstport=80 /* default dstport */ ,srcport;
int         ident;
int         ttl;
size_t      seq=0;
size_t      ack;
size_t      urp;
int         winlen=1024;
bool        seqc=0, ttlc=0, identc=0, srcportc=0;
u8          flags=TCP_FLAG_SYN;
int         type=8 /*default icmp type echo*/ ,code=0,icmpid;
size_t      chunktype=SCTP_INIT_ACK,vtag=0;
bool        adler32cksum=0;
bool        icmpidc=0;
bool        maskc=0;
size_t      datalen;
const char *data;
bool        badsum=0;
size_t      itag=0,arwnd=0,itsn=0;
int         nis=0,nos=0;
bool        itagc=0,arwndc=0,itsnc=0,nisc=0,nosc=0;
const char *v123sendmgs;
bool        streamc=0, protoloadc=0, tsnc=0;
int         stream;
size_t      protoload, tsn;
mac_t       macsrc, macdst;
int         mactype=0;
bool        eth=0;
eth_t      *fdeth;

static void pinger(void);
static u8  *icmpmsgbuild(size_t *msglen);
static u8  *sctpchunkbuild(size_t *chunklen);
static u8  *pingbuild(size_t *pinglen);

const char *run;
int         is=0;
long long   delay=to_ns(1000); /* classic one second delay */
const char *node=NULL;
char        ip4buf[16];
char      **targets;
size_t      num=0;
bool        tcp=0, icmp=0, udp=0, sctp=0;
int         mode=MODE_ICMP; /* default mode icmp */
bool        printstats=0;
const char *lasttarget=NULL;
char        currentdns[1024];
const char *shortopts="h";
const struct option
            longopts[]={
  {"help", no_argument, 0, 'h'},
  {"badsum", no_argument, 0, 1},
  {"ipopt", required_argument, 0, 2},
  {"src", required_argument, 0, 3},
  {"data-len", required_argument, 0, 4},
  {"data-string", required_argument, 0, 5},
  {"num", required_argument, 0, 6},
  {"tos", required_argument, 0, 7},
  {"ident", required_argument, 0, 8},
  {"df", no_argument, 0, 9},
  {"ttl", required_argument, 0, 10},
  {"mtu", required_argument, 0, 11},
  {"tcpopts", required_argument, 0, 12},
  {"macsrc", required_argument, 0, 13},
  {"noreply", no_argument, 0, 14},
  {"macdst", required_argument, 0, 15},
  {"maxwait", required_argument, 0, 16},
  {"tcp", no_argument, 0, 17},
  {"dstport", required_argument, 0, 18},
  {"srcport", required_argument, 0, 19},
  {"v", no_argument, 0, 20},
  {"vv", no_argument, 0, 21},
  {"vvv", no_argument, 0, 22},
  {"delay", required_argument, 0, 23},
  {"seq", required_argument, 0, 24},
  {"ack", required_argument, 0, 25},
  {"urp", required_argument, 0, 26},
  {"win", required_argument, 0, 27},
  {"tos", required_argument, 0, 28},
  {"flags", required_argument, 0, 29},
  {"type", required_argument, 0, 30},
  {"code", required_argument, 0, 31},
  {"id", required_argument, 0, 32},
  {"icmp", no_argument, 0, 33},
  {"udp", no_argument, 0, 34},
  {"rx", required_argument, 0, 35},
  {"orig", required_argument, 0, 36},
  {"tx", required_argument, 0, 37},
  {"mask", required_argument, 0, 38},
  {"sctp", no_argument, 0, 39},
  {"chunk", required_argument, 0, 40},
  {"vtag", required_argument, 0, 41},
  {"adler32", no_argument, 0, 42},
  {"data", required_argument, 0, 43},
  {"mactype", required_argument, 0, 44},
  {"itag", required_argument, 0, 45},
  {"arwnd", required_argument, 0, 46},
  {"nos", required_argument, 0, 47},
  {"nis", required_argument, 0, 48},
  {"itsn", required_argument, 0, 49},
  {"tsn", required_argument, 0, 50},
  {"stream", required_argument, 0, 51},
  {"protoload", required_argument, 0, 52},
  {"eth", no_argument, 0, 53},
  {"mf", no_argument, 0, 54},
  {"rf", no_argument, 0, 55},
};

static void parsearg(int argc, char **argv);
static void prefinish(const char *target);
static void ping(const char *target);
static noreturn void finish(int sig);
static void nsdelay(long long ns);
static noreturn void usage(void);
int main(int argc, char **argv);
static void targetsproc(void);
static void dnsproc(void);

/*
 * Outputs the help menu, and terminates the program.
 */
static noreturn void usage(void)
{
  puts("Usage");
  printf("  %s [mode] [flags] <target,target, ..,> \n\n", run);
  puts("  -n, -num <num>\tstop after <num> pkts");
  puts("  -data-string <str>\tappend a custom ASCII string to payload");
  puts("  -data-len <num>\tappend random data to payload");
  puts("  -data <hex>\t\tappend hex data to payload");
  puts("  -badsum\t\tsend packets with a bogus checksum additional proto");
  puts("  -maxwait <time>\tset your max timeout for receive pkts");
  puts("  -v, -vv, -vvv\t\tincrease verbosity level (higher is greater effect)");
  puts("  -delay <time>\t\tadjust delay between probes");
  puts("  -noreply\t\tdo not show the response from the host");
  puts("");
  puts("  -src <ip4addr>\tset your spoof src");
  puts("  -tos <num>\t\tset your type of service field");
  puts("  -ident <num>\t\tset your identification field");
  puts("  -df\t\t\tset Don't Fragment flag");
  puts("  -mf\t\t\tset More fragments flag");
  puts("  -rf\t\t\tset Reserved flag");
  puts("  -ttl <num>\t\tset your ttl");
  puts("  -mtu <num>\t\tfragment send packets");
  puts("  -ipopt <fmt>\t\tadding ip option in packets\n\t\t\t(fmt <R|S [route]|L [route]|T|U |[HEX]>)");
  puts("  -eth");
  puts("    -macsrc <macaddr>\tset source mac address");
  puts("    -macdst <macaddr>\tset dest mac address");
  puts("    -mactype <num>\tset payload type in mac header");
  puts("  -icmp");
  puts("    -type <8,13,15,17>\tset icmp message type");
  puts("    -code <num>\t\tset your code");
  puts("    -id <num>\t\tset your ident");
  puts("    -seq <num>\t\tset your sequence");
  puts("    -type 13");
  puts("      -orig <num>\tset originate timestamp");
  puts("      -rx <num>\t\tset receive timestamp");
  puts("      -tx <num>\t\tset transmit timestamp");
  puts("    -type 17");
  puts("      -mask <ip4addr>\tset addr for mask");
  puts("  -tcp");
  puts("    -flags <fmt>\tcustomize TCP flags (S,A,P,F,R,C,P,U,E)");
  puts("    -dstport <num>\tset destination port");
  puts("    -srcport <num>\tset custom source port");
  puts("    -seq <num>\t\tset custom sequence number");
  puts("    -ack <num>\t\tset custom ack number");
  puts("    -urp <num>\t\tset custom urp number");
  puts("    -win <num>\t\tset custom window size");
  puts("    -tcpopts <hex> \tset your tcp options");
  puts("  -udp");
  puts("    -dstport <num>\tset destination port");
  puts("    -srcport <num>\tset custom source port");
  puts("  -sctp");
  puts("    -dstport <num>\tset destination port");
  puts("    -srcport <num>\tset custom source port");
  puts("    -chunk <0-2,10-11>\tset type sctp chunk");
  puts("    -vtag <type>\tset your vtag");
  puts("    -chunk 1|2");
  puts("      -itag <num>\tset your itag");
  puts("      -arwnd <num>\tset your arwnd");
  puts("      -nos <num>\tset your nos");
  puts("      -nis <num>\tset your nis");
  puts("      -itsn <num>\tset your itsn");
  puts("    -chunk 0");
  puts("      -tsn <num>\tset your tsn");
  puts("      -stream <num>\tset your stream id");
  puts("      -seq <num>\tset your sequence number");
  puts("      -protoload <num>\tset your protoload");
  puts("    -adler32\t\tset adler32 checksum");
  infohelp();
  exit(0);
}


/*
 * Subtract 2 timeval structs:  out = out - in.
 * Out is assumed to be >= in.
*/
static void tvsub(struct timeval *out, struct timeval *in)
{
  if ((out->tv_usec-=in->tv_usec)<0) {
    out->tv_sec--;
    out->tv_usec+=1000000;
  }
  out->tv_sec-=in->tv_sec;
}


/* Calculates the response time, minimum, maximum,
 * and current.
 */
static void tvrtt(void)
{
  tvsub(&lr->tstamp_e, &lr->tstamp_s);
  triptime=lr->tstamp_e.tv_sec*1000+(lr->tstamp_e.tv_usec/1000);
  tsum+=triptime;
  if (triptime<tmin)
    tmin=triptime;
  if (triptime>tmax)
    tmax=triptime;
}


/*
 * SCTP packet filtering, and message generation.
 */
static bool received_ping_sctp_callback(u8 *frame, size_t frmlen, ip4h_t *ip)
{
  struct sockaddr_in dst_t, *src_t;
  char chunktypestr[1024];
  u8 *chunktype=NULL;
  sctph_t *sctp;

  sctp=(sctph_t*)(frame+(ETH_HDR_LEN+sizeof(ip4h_t)));
  chunktype=(u8*)(sctp+sizeof(u8));

  switch (*chunktype) {
  case SCTP_ABORT:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=abort ");
    break;
  case SCTP_INIT:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=initack ");
    break;
  case SCTP_COOKIE_ECHO:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=cookie ");
    break;
  case SCTP_COOKIE_ACK:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=cookieack ");
    break;
  case SCTP_HEARTBEAT:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=heartbeat ");
    break;
  case SCTP_SHUTDOWN:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=shutdown ");
    break;
  case SCTP_SHUTDOWN_ACK:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=shutdownack ");
    break;
  case SCTP_SHUTDOWN_COMPLETE:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=shutdowncomplete ");
    break;
  case SCTP_SACK:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=sack ");
    break;
  case SCTP_DATA:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=data ");
    break;
  default:
    snprintf(chunktypestr, sizeof(chunktypestr), "chunk=%hhu ", *chunktype);
    break;
  }

  /* Check if the packet is addressed to us. */
  dst_t.sin_addr.s_addr=ip->src;
  src_t=(struct sockaddr_in*)dst;
  if (dst_t.sin_addr.s_addr==src_t->sin_addr.s_addr) {
    snprintf(v0msg, sizeof(v0msg), "%ld bytes from SCTP %s:%hu%s: %svtag=%lu ttl=%hhu", frmlen, ip4buf, ntohs(sctp->srcport), currentdns, chunktypestr, (unsigned long)ntohl(sctp->vtag), ip->ttl);
    return true;
  }
  return false;
}


/*
 * UDP packet filtering, and message generation.
 */
static bool received_ping_udp_callback(u8 *frame, size_t frmlen, ip4h_t *ip)
{
  struct sockaddr_in dst_t, *src_t;
  udph_t *udp;

  udp=(udph_t*)(frame+(ETH_HDR_LEN+sizeof(ip4h_t)));

  /* Check if the packet is addressed to us. */
  dst_t.sin_addr.s_addr=ip->src;
  src_t=(struct sockaddr_in*)dst;
  if (dst_t.sin_addr.s_addr==src_t->sin_addr.s_addr) {
    snprintf(v0msg, sizeof(v0msg), "%ld bytes from UDP %s:%hu%s: ttl=%hhu", frmlen, ip4buf, ntohs(udp->srcport), currentdns, ip->ttl);
    return true;
  }
  return false;
}


/*
 * TCP packet filtering, and message generation.
 */
static bool received_ping_tcp_callback(u8 *frame, size_t frmlen, ip4h_t *ip)
{
  struct sockaddr_in dst_t, *src_t;
  char tflags[10];
  char *p=NULL;
  tcph_t *tcp;

  tcp=(tcph_t*)(frame+(ETH_HDR_LEN+sizeof(ip4h_t)));

  /*
   * Checks all TCP flags, if any of them are set, then
   * adds the corresponding letter to tflags, via the
   * p pointer.
   */
  p = tflags;
  if (tcp->th_flags & TCP_FLAG_SYN)
    *p++ = 'S';
  if (tcp->th_flags & TCP_FLAG_FIN)
    *p++ = 'F';
  if (tcp->th_flags & TCP_FLAG_RST)
    *p++ = 'R';
  if (tcp->th_flags & TCP_FLAG_PSH)
    *p++ = 'P';
  if (tcp->th_flags & TCP_FLAG_ACK)
    *p++ = 'A';
  if (tcp->th_flags & TCP_FLAG_URG)
    *p++ = 'U';
  if (tcp->th_flags & TCP_FLAG_ECE)
    *p++ = 'E';
  if (tcp->th_flags & TCP_FLAG_CWR)
    *p++ = 'C';
  *p++ = '\0';

  /* Check if the packet is addressed to us. */
  dst_t.sin_addr.s_addr=ip->src;
  src_t=(struct sockaddr_in*)dst;
  if (dst_t.sin_addr.s_addr==src_t->sin_addr.s_addr) {
    snprintf(v0msg, sizeof(v0msg), "%ld bytes from TCP %s:%hu%s: flags=%s ttl=%hhu", frmlen, ip4buf, ntohs(tcp->th_sport), currentdns, tflags, ip->ttl);
    return true;
  }
  return false;
}


/*
 * ICMP packet filtering, and message generation. Works
 * with types, info, echo, tstamp, mask, redirect,
 * paramprob, timexceed, unreach, srcquench.
 */
static bool received_ping_icmp_callback(u8 *frame, size_t frmlen, ip4h_t *ip)
{
  icmph_t *icmp, *icmp2;
  char protoinfo[4096];
  u32 *unsed=NULL;
  ip4h_t *ip2;
  struct in_addr iptmp;
  struct sockaddr_in dst_t, *src_t;
  u16 *icmp_seq=NULL;

  /*
   * We get the ICMP header, which is known to come after
   * the MAC header and the IP4 header.
     */
  icmp=(icmph_t*)(frame+(ETH_HDR_LEN+sizeof(ip4h_t)));

  /*
   * ICMP echo/info/tstamp/mask reply aee
   */
  if (icmp->type==ICMP4_ECHOREPLY||icmp->type==ICMP4_INFOREPLY||icmp->type==ICMP4_TSTAMPREPLY||icmp->type==ICMP4_MASKREPLY) {

    /* Check if the packet is addressed to us. */
    dst_t.sin_addr.s_addr=ip->src;
    src_t=(struct sockaddr_in*)dst;
    if (dst_t.sin_addr.s_addr==src_t->sin_addr.s_addr) {

      /*
       * Get seq from ICMP message, as we know it is after mac
       * header, ip header, icmp header, and id field which size
       * is 16 bits. Or here: [mac_hdr + ip4_hdr +
       *   icmp_hdr + id (16 bit)].
       *
       *        1. MAC_HEADER
       * 0000   (40 b0 76 47 8f 9a 04 bf  6d 0d 3a 50 08 00 45 00) +
       *        2. IP_HEADER
       * 0010   (00 1c 00 00 00 00 6f 01  fd eb ad c2 de 65 c0 a8
       *                 3. ICMP_HEADER  4. ICMP_ID  5.ICMP_SEQ (target)
       * 0020   01 25) + (00 00 1f 43) + (e0 ba)  +  (00 02)
       *
       */
      icmp_seq=(u16*)(frame+(ETH_HDR_LEN+sizeof(ip4h_t))+(sizeof(icmph_t)+sizeof(u16)));

      snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s%s: icmp_seq=%hu ttl=%hhu", frmlen, ip4buf, currentdns, ntohs(*icmp_seq), ip->ttl);
      return true;
    }
  }

  /*
   * ICMP unreach/tstamp/srcquench/redirect/timexceed/paramprob
   */
  if (icmp->type==ICMP4_UNREACH||icmp->type==ICMP4_SRCQUENCH||icmp->type==ICMP4_REDIRECT||icmp->type==ICMP4_TIMEXCEED||icmp->type==ICMP4_PARAMPROB) {

    /*
     * Get the IP4 header from the received packet, but only the
     * one that lies in the ICMP message, here: [mac_hdr + ip4_hdr +
     *   icmp_hdr + error_msg (one unsed ore gateway field weighing 32 bytes)].
     *
     *        1. MAC_HEADER                                 2. IP_HEADER
     * 0000   (40 b0 76 47 8f 9a 04 bf 6d 0d 3a 50 08 00) + (45 c0
     * 0010   00 38 67 c2 00 00 3c 01 81 66 0a c8 c8 47 c0 a8
     *                 3. ICMP_HEADER                 4. ICMP4_MSG_ERROR   5. IP_HEADER (target)
     * 0020   01 25) + (03 01 fc fe 00 00 00 00 45) + (00 00) +            (1c 10 4b
     * 0030   00 00 c3 01 45 1e c0 a8 01 25 c0 a8 20 02) 08 00
     * 0040   58 eb 9f 12 00 02
     *
     */
    ip2=(ip4h_t*)(frame+((ETH_HDR_LEN+sizeof(ip4h_t)))+sizeof(icmp4h_t)+sizeof(u32));

    /*
     * Does our IP4 address match the IP4 address of the sender inside the
     * IP4 header that is in the UNREACH message.
     */
    dst_t.sin_addr.s_addr=ip2->src;
    src_t=(struct sockaddr_in*)src;
    iptmp.s_addr=ip->src;
    if (dst_t.sin_addr.s_addr!=src_t->sin_addr.s_addr)
      return false;

    /* Get the unsed/gateway field from the ICMP message from the error.
     * That is:  [mac_hdr + ip4_hdr + icmp_hdr]
     *
     *        1. MAC_HEADER                                 2. IP_HEADER
     * 0000   (40 b0 76 47 8f 9a 04 bf 6d 0d 3a 50 08 00) + (45 c0
     * 0010   00 38 67 c2 00 00 3c 01 81 66 0a c8 c8 47 c0 a8
     *                 3. ICMP_HEADER                 4. ICMP4_MSG_ERROR (target)
     * 0020   01 25) + (03 01 fc fe 00 00 00 00 45) + (00 00) 1c 10 4b
     * 0030   00 00 c3 01 45 1e c0 a8 01 25 c0 a8 20 02 08 00
     * 0040   58 eb 9f 12 00 02
     */
    unsed=(u32*)(frame+((ETH_HDR_LEN+sizeof(ip4h_t)))+(sizeof(icmp4h_t)));

    if (ip2->proto==IPPROTO_ICMP) {

      /*
       * We get the ICMP header, but, the one that lies in the ICMP message.
       * Right there: [mac_hdr + ip4_hdr + icmp_hdr + icmp4_msg_unreach
       *   (one unsed field weighing 32 bytes) + ip4_hdr + icmp_hdr].
       *
       *        1. MAC_HEADER                                 2. IP_HEADER
       * 0000   (40 b0 76 47 8f 9a 04 bf 6d 0d 3a 50 08 00) + (45 c0
       * 0010   00 38 67 c2 00 00 3c 01 81 66 0a c8 c8 47 c0 a8
       *                 3. ICMP_HEADER                 4. ICMP4_MSG_ERROR   5. IP_HEADER
       * 0020   01 25) + (03 01 fc fe 00 00 00 00 45) + (00 00) +              (1c 10 4b
       *                                                     6. ICMP_HEADER (target)
       * 0030   00 00 c3 01 45 1e c0 a8 01 25 c0 a8 20 02) + (08 00
       * 0040   58 eb) 9f 12 00 02
       *
       */
      icmp2=(icmph_t*)(frame+((ETH_HDR_LEN+sizeof(ip4h_t)))+(sizeof(icmp4h_t)+sizeof(u32))+(sizeof(ip4h_t)));

      if (ip2->proto==IPPROTO_ICMP&&(icmp2->type==ICMP4_ECHO||icmp2->type==ICMP4_INFO||icmp2->type==ICMP4_TSTAMP)) {
	u16 *icmp_seq=NULL;

	/*
	 * If the type of ICMP message inside the ICMP message UNREACH
	 * (after the ip4 header), matches one of these, then we get the
	 * seq that lies after all this and the id field weighing 16 bits,
	 * skip it and come to the seq field. Here: [mac_hdr + ip4_hdr +
	 *   icmp_hdr + icmp4_msg_unreach (one unsed field weighing 32 bytes) +
	 *   ip4_hdr + icmp_hdr + id (16bit)].
	 *
	 *        1. MAC_HEADER                                 2. IP_HEADER
	 * 0000   (40 b0 76 47 8f 9a 04 bf 6d 0d 3a 50 08 00) + (45 c0
	 * 0010   00 38 67 c2 00 00 3c 01 81 66 0a c8 c8 47 c0 a8
	 *                 3. ICMP_HEADER                 4. ICMP4_MSG_ERROR   5. IP_HEADER
	 * 0020   01 25) + (03 01 fc fe 00 00 00 00 45) + (00 00) +              (1c 10 4b
	 *                                                     6. ICMP_HEADER
	 * 0030   00 00 c3 01 45 1e c0 a8 01 25 c0 a8 20 02) + (08 00
	 *                 7. ICMP_ID (16 bit)  8. ICMP_SEQ (target)
	 * 0040   58 eb) + (9f 12) +            (00 02)
	 *
	 */
	icmp_seq=(u16*)(frame+((ETH_HDR_LEN+sizeof(ip4h_t)))+(sizeof(icmp4h_t)+sizeof(u32))+(sizeof(ip4h_t)+sizeof(icmph_t)+sizeof(u16)));

	sprintf(protoinfo, "icmp_seq=%hu", ntohs(*icmp_seq));
      }
    }
    else if (ip2->proto==IPPROTO_UDP) {
      u16 *srcport=NULL;
      srcport=(u16*)(frame+((ETH_HDR_LEN+sizeof(ip4h_t)))+(sizeof(icmp4h_t)+sizeof(u32))+(sizeof(ip4h_t)+sizeof(u16)));
      sprintf(protoinfo, "srcport=%hu", ntohs(*srcport));
    }
    else if (ip2->proto==IPPROTO_TCP||ip2->proto==IPPROTO_SCTP) {
      u16 *srcport=NULL;
      srcport=(u16*)(frame+((ETH_HDR_LEN+sizeof(ip4h_t)))+(sizeof(icmp4h_t)+sizeof(u32))+(sizeof(ip4h_t)));
      sprintf(protoinfo, "srcport=%hu ", ntohs(*srcport));
    }
    else
      protoinfo[0]='\0';

    /* Build v0 message */
    if (icmp->type==ICMP4_UNREACH) {
      switch (icmp->code) {
      case ICMP4_UNREACH_HOST:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Destination Host Unreachable)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
	break;
      case ICMP4_UNREACH_NET:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Destination Network Unreachable)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
	break;
      case ICMP4_UNREACH_PROTO:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Destination Protocol Unreachable)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
	break;
      case ICMP4_UNREACH_PORT:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Destination Port Unreachable)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
	break;
      case ICMP4_UNREACH_NEEDFRAG:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Fragmentation needed and DF set)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
	break;
      case ICMP4_UNREACH_SRCFAIL:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Source Route Failed)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
	break;
      default:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Dest Unreachable, Bad Code: 0x%x)", frmlen, ncs_inet_ntoa(iptmp), protoinfo, icmp->code);
	break;
      }
    }
    else if (icmp->type==ICMP4_SRCQUENCH)
      snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Source Quench)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
    else if (icmp->type==ICMP4_TIMEXCEED) {
      switch (icmp->code) {
      case ICMP4_TIMEXCEED_INTRANS:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Time to live exceeded in transit)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
	break;
      case ICMP4_TIMEXCEED_REASS:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Fragment reassembly time exceeded)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
	break;
      default:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Time exceeded, Bad Code: 0x%x)", frmlen, ncs_inet_ntoa(iptmp), protoinfo, icmp->code);
	break;
      }
    }
    else if (icmp->type==ICMP4_PARAMPROB) {
      switch (icmp->code) {
      case 0:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Parameter problem: error detected at byte (ptr_unsed) %u)", frmlen, ncs_inet_ntoa(iptmp), protoinfo, *unsed);
	break;
      default:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Unspecified parameter problem)", frmlen, ncs_inet_ntoa(iptmp), protoinfo);
	break;
      }
    }
    else if (icmp->type==ICMP4_REDIRECT) {
      switch (icmp->code) {
      case ICMP4_REDIRECT_NET:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Network Redirect (New addr: %u))", frmlen, ncs_inet_ntoa(iptmp), protoinfo, *unsed);
	break;
      case ICMP4_REDIRECT_HOST:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Host Redirect (New addr: %u))", frmlen, ncs_inet_ntoa(iptmp), protoinfo, *unsed);
	break;
      case ICMP4_REDIRECT_TOSNET:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Type of Service and Network Redirect (New addr: %u))", frmlen, ncs_inet_ntoa(iptmp), protoinfo, *unsed);
	break;
      case ICMP4_REDIRECT_TOSHOST:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Type of Service and Host Redirect (New addr: %u))", frmlen, ncs_inet_ntoa(iptmp), protoinfo, *unsed);
	break;
      default:
	snprintf(v0msg, sizeof(v0msg), "%ld bytes from ICMP %s: %s (Redirect, Bad Code: 0x%x (New addr: %u))", frmlen, ncs_inet_ntoa(iptmp), protoinfo, icmp->code, *unsed);
	break;
      }
    }
    return true;
  }

  return false;
}


/*
 * Filters received packets, and at the same time emits messages
 * about their reception, for laying level 0. Handles IP4, IP6,
 * ICMP, TCP, TCP, SCTP, UDP, ICMP6.
 */
static bool received_ping_callback(u8 *frame, size_t frmlen)
{
  int fragoff=0;
  bool valid=0;
  size_t hlen, tmplen=frmlen;
  ip4h_t *ip;
  u8 *frmtmp=frame;

  /*
   * Get IP4 header, brings a pointer to the packet, skipping
   * the MAC header. And getting hlen.
   */
  ip=(ip4h_t*)(frame+ETH_HDR_LEN);
  hlen=ip->ihl<<2;
  frmlen-=hlen;

  /* Validate packet */
  valid=read_util_validate_pkt(frame+ETH_HDR_LEN, (u32*)&frmlen);
  if (!valid)
    return false;

  /* Frag check */
  fragoff=8*(ntohs(ip->off)&8191);
  if (fragoff) {
    snprintf(v0msg, sizeof(v0msg), "%ld bytes from %s%s: ttl=%hhu (incomplete)", frmlen, ip4buf, currentdns, ip->ttl);
    return true;
  }

  /* v0 message build and filtering */
  if (ip->proto==IPPROTO_ICMP)
    filter=received_ping_icmp_callback(frame, frmlen, ip);
  else if (ip->proto==IPPROTO_TCP)
    filter=received_ping_tcp_callback(frame, frmlen, ip);
  else if (ip->proto==IPPROTO_UDP)
    filter=received_ping_udp_callback(frame, frmlen, ip);
  else if (ip->proto==IPPROTO_SCTP)
    filter=received_ping_sctp_callback(frame, frmlen, ip);
  else
    filter=false;
  if (filter==0)
    return false;

  /* v123 message build */
  if (vvv==1)
    v123msg=frminfo(frmtmp, tmplen, LOW_DETAIL, 0);
  else if (vvv==2)
    v123msg=frminfo(frmtmp, tmplen, MEDIUM_DETAIL, 0);
  else if (vvv==3)
    v123msg=frminfo(frmtmp, tmplen, HIGH_DETAIL, 0);

  return true;
}


/*
 * Parses arguments, applies options
 */
static void parsearg(int argc, char **argv)
{
  int rez, index=0;
  while ((rez=getopt_long_only(argc, argv, shortopts, longopts, &index))!=-1) {
    switch (rez) {
    case 'h': usage();
    case 1: badsum=1; break;
    case 2:
      memset(ipopt, 0, sizeof(ipopt));
      ipoptslen = parse_ipopts(optarg, ipopt, sizeof(ipopt),
        &ipopts_first_hop_offset, &ipopts_last_hop_offset, NULL, 0);
      break;
    case 3: {
      struct sockaddr_in *addr4;
      if (ncs_inet_pton(AF_INET, optarg, &((struct sockaddr_in*)src)->sin_addr)==1) {
        addr4=(struct sockaddr_in*)src;
        addr4->sin_family=AF_INET;
        addr4->sin_port=0;
      }
      else
	errx(1, "err: invalid convert ipaddr \"%s\"", optarg);
      break;
    }
    case 4:
      datalen=atoll(optarg);
      if (datalen>1400)
	errx(1, "err: maximum ETH payload is (1400), your is \"%d\"", datalen);
      data=random_str(datalen, DEFAULT_DICTIONARY);
     break;
    case 5:
      data=optarg;
      datalen=data?strlen(data):0;
      if (datalen>1400)
	errx(1, "err: maximum ETH payload is (1400), your is \"%d\"", datalen);
      break;
    case 6: npackets=atoll(optarg); break;
    case 7: tos=atoi(optarg); break;
    case 8: ident=atoi(optarg); identc=1; break;
    case 9: df=1; break;
    case 10: ttl=atoi(optarg); ttlc=1; break;
    case 11: mtu=atoi(optarg); break;
    case 12: tcpopt=hexbin(optarg, &tcpoptlen); if (!tcpopt) errx(0,"err: invalid hex string specification"); break;
    case 13: mac_aton(&macsrc, optarg); break;
    case 14: noreply=1; if (vvv>=0) vvv=1; break;
    case 15: mac_aton(&macdst, optarg); break;
    case 16: maxwait=delayconv(optarg); break;
    case 17: tcp=1; break;
    case 18: dstport=atoi(optarg); break;
    case 19: srcport=atoi(optarg); srcportc=1; break;
    case 20: vvv=1; break;
    case 21: vvv=2; break;
    case 22: vvv=3; break;
    case 23: delay=delayconv(optarg); break;
    case 24: seq=atoll(optarg); seqc=1; break;
    case 25: ack=atoll(optarg); break;
    case 26: urp=atoll(optarg); break;
    case 27: winlen=atoi(optarg); break;
    case 28: tos=atoi(optarg); break;
    case 29: {
      struct tcp_flags tf;
      memset(&tf, 0, sizeof(struct tcp_flags));
      tf = tcp_util_str_setflags(optarg);
      flags=tcp_util_setflags(&tf);
      break;
    }
    case 30: type=atoi(optarg); break;
    case 31: code=atoi(optarg); break;
    case 32: icmpid=atoi(optarg); icmpidc=1; break;
    case 33: icmp=1; break;
    case 34: udp=1; break;
    case 35: rx=atoll(optarg); rxc=1; break;
    case 36: orig=atoll(optarg); origc=1; break;
    case 37: tx=atoll(optarg); txc=1; break;
    case 38: mask=ncs_inet_addr(optarg); maskc=1; break;
    case 39: sctp=1; break;
    case 40: chunktype=atoi(optarg); break;
    case 41: vtag=atoll(optarg); break;
    case 42: adler32cksum=1; break;
    case 43: data=(char*)hexbin(optarg, &datalen); if (!data) errx(0,"err: invalid hex string specification"); break;
    case 44: mactype=atoi(optarg); break;
    case 45: itag=atoll(optarg); itagc=1; break;
    case 46: arwnd=atoll(optarg); arwndc=1; break;
    case 47: nos=atoi(optarg); nosc=1; break;
    case 48: nis=atoi(optarg); nisc=1; break;
    case 49: itsn=atoll(optarg); itsnc=1; break;
    case 50: tsn=atoll(optarg); tsnc=1; break;
    case 51: stream=atoi(optarg); streamc=1; break;
    case 52: protoload=atoll(optarg); protoloadc=1; break;
    case 53: eth=1; break;
    case 54: mf=1; break;
    case 55: evil=1; break;
    }
  }
}

static u8 *icmpmsgbuild(size_t *msglen)
{
  u8 *msg=NULL;

  if (!icmpidc)
    icmpid=random_u16();
  if (!seqc)
    seq++;

  switch (type) {
  case ICMP6_ECHO:
  case ICMP4_ECHO:
    msg=icmp4_msg_echo_build(icmpid, seq, data, msglen);
    break;
  case ICMP4_INFO:
    msg=icmp4_msg_info_build(icmpid, seq, msglen);
    break;
  case ICMP4_TSTAMP:
    if (!origc)
      orig=random_u32();
    if (!rxc)
      rx=random_u32();
    if (!txc)
      tx=random_u32();
    msg=icmp4_msg_tstamp_build(icmpid, seq, orig, rx, tx, msglen);
    break;
  case ICMP4_MASK:
    if (!maskc)
      mask=ncs_inet_addr(random_ip4());
    msg=icmp4_msg_mask_build(icmpid, seq, mask, msglen);
    break;
  }

  return msg;
}

static u8 *sctpchunkbuild(size_t *chunklen)
{
  u8 *chunk=NULL;

  switch (chunktype) {
  case SCTP_DATA:
    if (!tsnc)
      tsn=random_u32();
    if (!protoloadc)
      protoload=random_u32();
    if (!streamc)
      stream=random_u16();
    if (!seqc)
      seq=random_u16();
    chunk=sctp_data_build(0, tsn, stream, seq, protoload, (u8*)data, datalen, chunklen);
    break;
  case SCTP_COOKIE_ACK:
  case SCTP_COOKIE_ECHO:
    chunk=sctp_cookie_build(chunktype, 0, (u8*)data, datalen, chunklen);
    break;
  case SCTP_INIT_ACK:
  case SCTP_INIT:
    if (!itagc)
      itag=random_u32();
    if (!itsnc)
      itsn=random_u32();
    if (!arwndc)
      arwnd=random_u32();
    if (!nosc)
      nos=random_u16();
    if (!nisc)
      nis=random_u16();
    chunk=sctp_init_build(chunktype, 0, itag, arwnd, nos, nis, itsn, chunklen);
    break;
  }
  return chunk;
}

static u8 *pingbuild(size_t *pinglen)
{
  u8 *ping=NULL, *preping=NULL, *msg=NULL;
  struct sockaddr_in *dst4=NULL, *src4=NULL;
  u16 off=0;

  dst4=(struct sockaddr_in*)dst;
  src4=(struct sockaddr_in*)src;

  if (!srcportc)
    srcport=random_srcport();

  switch (mode) {
  case MODE_UDP:
    preping=udp_build(srcport, dstport, data, pinglen);
    udp4_check(preping, *pinglen, src4->sin_addr.s_addr, dst4->sin_addr.s_addr, badsum);
    break;
  case MODE_TCP:
    if (!seqc)
      seq=random_u32();
    preping=tcp_build(srcport, dstport, seq, ack, 0,
      flags, winlen, urp, tcpopt, tcpoptlen, data,
      pinglen);
    tcp4_check(preping, *pinglen, src4->sin_addr.s_addr, dst4->sin_addr.s_addr, badsum);
    break;
  case MODE_ICMP:
    msg=icmpmsgbuild(pinglen);
    preping=icmp_build(type, code, msg, *pinglen, pinglen);
    icmp4_check(preping, *pinglen, badsum);
    free(msg);
    break;
  case MODE_SCTP:
    msg=sctpchunkbuild(pinglen);
    preping=sctp_build(srcport, dstport, vtag, msg, *pinglen, pinglen);
    sctp_check(preping, *pinglen, adler32cksum, badsum);
    break;
  }

  if (!identc)
    ident=random_u16();
  if (!ttlc)
    ttl=random_num_u32(64, 255);
  if (df)
    off|=IP4_DF;
  if (mf)
    off|=IP4_MF;
  if (evil)
    off|=IP4_RF;

  ping=ip4_build(src4->sin_addr.s_addr, dst4->sin_addr.s_addr, mode, ttl,
    ident, tos, off, ipopt, ipoptslen, preping, *pinglen,
    pinglen);
  free(preping);

  if (eth)
    return (eth_build(macsrc, macdst, mactype, ping, *pinglen, pinglen));

  return ping;
}

/*
 * Send ping probe, and generate v123sendmsg
 */
static void pinger(void)
{
  size_t pinglen;
  u32 flags;
  u8 *ping;

  if (eth)
    flags=0;
  else
    flags=0x01; /* skip mac header*/

  ping=pingbuild(&pinglen);
  if (!ping)
    return;

  if (eth)
    eth_send(fdeth, ping, pinglen);
  else
    ip_send(NULL, fd, dst, mtu, ping, pinglen);
  ntransmitted++;

  v123sendmgs=frminfo(ping, pinglen, LOW_DETAIL, flags);
  if (vvv==2)
    v123sendmgs=frminfo(ping, pinglen, MEDIUM_DETAIL, flags);
  else if (vvv==3)
    v123sendmgs=frminfo(ping, pinglen, HIGH_DETAIL, flags);
  if (vvv>0)
    printf("%s\n%s",v123sendmgs, (vvv>0&&vvv<3) ? "\n" : "");
  free(ping);
}


/*
 * The function that outputs the main messages (about
 * packet reception), here the response time is
 * calculated.
 */
static void pr_pack(u8 *buf, ssize_t cc)
{
  /*
   * If the packet did not arrive within the specified timeout
   * (the filter did not find anything), we output the last
   * packet sent, to which no response was received.
   */
  if (filter==0) {
    puts("A reply packet was not received for the specified timeout.");
    printf("No response transmission ->\n%s\n",v123sendmgs);
    return;
  }

  nreceived++;
  tvrtt();

  if (noreply)
    return;

  /*
   * Display a message about the received packet.
   *
   * v0:   default msg;
   * v1-3: trace pkt msg;
   * v3:   hex and ascii pkt
   */
  if (vvv==0)
    printf("%s time=%ld ms\n", v0msg, triptime);
  else
    printf("%s\n%s", v123msg, (vvv>0&&vvv<3) ? "\n" : "");
}


/*
 * A delay of a specified number of nanoseconds
 */
static void nsdelay(long long ns)
{
  struct timespec req, rem;
  req.tv_sec=ns/1000000000;
  req.tv_nsec=ns%1000000000;
  nanosleep(&req, &rem);
}


/*
 * Outputs classic statistics about ping scans, these
 * are, packets transmitted, packets received, percentage
 * lost, and response time - minimum, average, maximum.
 */
static void prefinish(const char *target)
{
  printf("\n----%s PING Statistics----\n", target);
  printf("%ld packets transmitted, %ld packets received",
    ntransmitted, nreceived);
  if (ntransmitted) {
    if (nreceived>ntransmitted)
      printf(" -- somebody's printing up packets!\n");
    else
      printf(", %ld%% packet loss\n", (size_t)
        (((ntransmitted-nreceived)*100) / ntransmitted));
  }
  if (nreceived)
    printf("round-trip (ms)  min/avg/max = %ld/%ld/%ld\n",
      tmin, tsum / nreceived, tmax);
  putchar('\n');
  printstats=1;
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
  size_t i=0;

  now=time(NULL);
  t=localtime(&now);
  if (printstats==0)
    prefinish(lasttarget);
  strftime(date, sizeof(date), "%H:%M:%S", t);
  printf("Ending %s at %s and clearing the memory\n", __FILE_NAME__, date);
  for (;i<num;i++)
    free(targets[i]);
  free(targets);
  if (src)
    free(src);
  if (dst)
    free(dst);
  if (eth)
    eth_close(fdeth);
  else
    if (fd>0)
      close(fd);
  if (lr)
    lr_close(lr);
  if (nreceived)
    exit(0);
  else
    exit(1);
}


/*
 * Shifts currentdns by two elements without wasting memory, adds
 * a space at the beginning followed by '(', adds ')' at the end.
 */
static void dnsproc(void)
{
  ssize_t len=0, i=0;
  if (currentdns[0]=='\0')
    return;
  len=strlen(currentdns);
  if (len+3>=(ssize_t)sizeof(currentdns))
    return;
  i=len;
  for (;i>=0; i--)
    currentdns[i+2]=currentdns[i];
  currentdns[0]=' ';
  currentdns[1]='(';
  currentdns[len+2]=')';
  currentdns[len+3]='\0';
}


/*
 * Gets the ip4 address and dns name for a specified target, and
 * pings the same target and outputs statistics.
 */
static void ping(const char *target)
{
  struct sockaddr_in *dst4;
  size_t cc=0;

  /* Update variables */
  memset(dst, 0, sizeof(struct sockaddr_storage));
  memset(ip4buf, 0, 16);
  if (mode==MODE_ICMP&&!seqc)
    seq=0;
  nreceived=ntransmitted=0;
  tmin=999999999;
  tmax=tsum=0;

  /* Convert target */
  if ((is=this_is(target))!=IPv6) {
    dst4 = (struct sockaddr_in*)dst;
    if (getipv4(target, ip4buf, 16)==-1)
      errx(1, "err: failed resolv for target \"%s\"", target);
    dst4->sin_addr.s_addr=ncs_inet_addr(ip4buf);
    dst4->sin_port=0;
    dst4->sin_family=AF_INET;
  }
  else
    errx(1, "err: only ip4 hosts");

  /* Get dns */
  memset(&currentdns, 0, sizeof(currentdns));
  currentdns[0]='\0';
  dns_util_getip4(ip4buf, random_srcport(), to_ns(1500), currentdns,
    sizeof(currentdns));
  dnsproc();

  if (icmp)
    mode=MODE_ICMP;
  else if (tcp)
    mode=MODE_TCP;
  else if (sctp)
    mode=MODE_SCTP;
  else if (udp)
    mode=MODE_UDP;

  for (;;) {
    lasttarget=target;
    packet=(u8*)calloc(65535, sizeof(u8));
    pinger();
    cc=lr_live(lr, &packet, 65535);
    if (cc<=0) {
      free(packet);
      prefinish(target);
      return;
    }
    pr_pack(packet, cc);
    free(packet);
    if (npackets&&nreceived>=npackets) {
      prefinish(target);
      return;
    }
    nsdelay(delay);
  }
}


/*
 * Parses comma separated targets into an array of
 * targets.
 */
static void targetsproc(void)
{
  char *cp=NULL, *tmp=NULL, *token=NULL;
  size_t index=0;

  cp=strdup(node);
  tmp=cp;

  while (*++tmp)
    if (*tmp == ',')
      num++;
  num++;
  targets=malloc(num*sizeof(char*));
  token=strtok(cp, ",");
  while (token) {
    targets[index]=strdup(token);
    index++;
    token=strtok(NULL, ",");
  }

  free(cp);
}


/*
 * ping.c
 */
int main(int argc, char **argv)
{
  struct sockaddr_in *src4=NULL;
  const char *dev=NULL;
  char *strsrc=NULL;
  size_t index=0;

  signal(SIGINT, finish);
  run=argv[0];
  if (argc<=1)
    usage();
  startstring();
  parsearg(argc, argv);

  if (optind<argc)
    node=argv[optind];
  if (!check_root_perms())
    errx(1, "err: raw sockets on UNIX only sudo, (try \"sudo %s\")", argv[0]);

  dst=(struct sockaddr_storage*)malloc(sizeof(struct sockaddr_storage));
  src=(struct sockaddr_storage*)malloc(sizeof(struct sockaddr_storage));
  memset(src, 0, sizeof(struct sockaddr_storage));

  src4=(struct sockaddr_in*)src;
  if (!(strsrc=ip4_util_strsrc()))
    errx(1, "err: failed getting source ipaddr");
  src4->sin_addr.s_addr=ncs_inet_addr(strsrc);
  free(strsrc);
  src4->sin_family=AF_INET;
  src4->sin_port=0;

  dev=getinterface();
  lr=lr_open(maxwait);
  lr_callback(lr, received_ping_callback);
  if (eth)
    fdeth=eth_open(dev);
  else
    fd=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  targetsproc();

  for (;index<num;index++) {
    printstats=0;
    ping(targets[index]);
  }

  finish(0);

  /* NOTREACHED */
}
