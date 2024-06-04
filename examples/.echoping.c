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

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdnoreturn.h>
#include <string.h>
#include <float.h>

#include "../ncsnet/icmp.h"
#include "../ncsnet/readpkt.h"
#include "../ncsnet/ncpcap.h"
#include "../ncsnet/utils.h"
#include "../ncsnet/log.h"
#include "../ncsnet/dns.h"

#define ITERATIONS 5
//#define DISPLAY_SENT

static char *strsrc, *strdst, *data;
static u32 dst, src;
static int timeout;
static struct sockaddr_in s;
static char date[1024];

static noreturn void usage(char** argv)
{
  printf("Usage: %s [ip] [timeout (ms)] [size (max 1400)]\n", argv[0]);
  exit(0);
}

static void argsproc(int argc, char** argv)
{
  char ipbuf[16];
  char *clean;
  int is;  
  
  if (argc < 3 + 1)
    usage(argv);
  if (atoi(argv[3]) > 1400)
    usage(argv);
  if (!check_root_perms())
    errx(1, "Only <sudo> run!");

  timeout = atoi(argv[2]);
  
  strdst = argv[1];
  is = this_is(strdst);
  if (is == IPv4)
    dst = inet_addr(strdst);
  else if (is == DNS) {
    assert((ip4_util_strdst(strdst, ipbuf, sizeof(ipbuf)) == 0));
    strdst = ipbuf;
  }
  else if (is == _URL_) {
    clean = clean_url(strdst);
    assert(clean);
    assert((ip4_util_strdst(clean, ipbuf, sizeof(ipbuf)) == 0));
    strdst = ipbuf;
    free(clean);
  }
  else
    errx(1, "Incorrect target format only: URL, DNS, IPv4, are available!");    
  
  strsrc = ip4_util_strsrc();
  src = inet_addr(strsrc);
  dst = inet_addr(strdst);
  s.sin_addr.s_addr = dst;
  s.sin_family = AF_INET;
  data = random_str(atoi(argv[3]),
		    DEFAULT_DICTIONARY);
  get_current_date(date, 1024);
}

static void send_icmppkt(int fd, int i)
{
  u8 *res;
  u32 pktlen;
  
  res = icmp4_build_pkt(src, dst, 121, random_u16(), 0, false, NULL, 0, i,
      random_u16(), ICMP4_ECHO, 0, data, strlen(data), &pktlen, false);
  if (!res)
    return;
  
  ip4_send(NULL, fd, &s, 0, res, pktlen);
  
#if defined(DISPLAY_SENT)
  read_util_tracepkt(TRACE_PKT_SENT, res, pktlen, 0, LOW_DETAIL);
#endif
  free(res);
}

static double recv_icmppkt(pcap_t *p)
{
  struct icmp4_hdr *icmph = NULL;
  struct ip4_hdr *ip = NULL;
  const void *datap = NULL;
  struct link_header l;
  const u8 *pkt = NULL;
  struct timeval tmp;
  u32 pktlen;
  double rtt;

  pkt = ncpcap_ipread(p, &pktlen, to_ns(timeout), &tmp, &l, true);
  ip = (struct ip4_hdr*)pkt;
  datap = read_util_ip4getdata_up(ip, &pktlen);
  if (!datap)
    return -1;
  
  icmph = (struct icmp4_hdr*)datap;
  if (!icmph || icmph->type != ICMP4_ECHOREPLY)
    rtt = -1;
  else
    read_util_tracepkt(TRACE_PKT_RCVD, pkt, (pktlen + l.headerlen), rtt, LOW_DETAIL);
  
  return rtt;
}

int main(int argc, char** argv)
{
  pcap_t *p;
  int fd, i = 1;

  double rtts[ITERATIONS];
  double total_rtt = 0;
  double min_rtt = DBL_MAX;
  double max_rtt = 0;
  double tmprtt = 0;
  double avg_rtt = 0;

  memset(rtts, 0, sizeof(rtts));

  argsproc(argc, argv);
  printf("Starting ECHOPING (ncsock example) %s at %s\n", get_time(), date);
  p = ncpcap_openlive(NULL, 512, 0, to_ns(1));
  if (!p)
    return -1;
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  ncpcap_filter(p, "icmp and dst host %s and src host %s", strsrc, strdst);

  for (; i <= ITERATIONS;) {
    send_icmppkt(fd, i++);
    tmprtt = recv_icmppkt(p);
    if (tmprtt >= 0) {
      rtts[i-2] = tmprtt;
      total_rtt += tmprtt;
      if (tmprtt < min_rtt) min_rtt = tmprtt;
      if (tmprtt > max_rtt) max_rtt = tmprtt;
    }
    delayy(300);
  }
  
  avg_rtt = total_rtt / 10;
  printf("\nEnding results is (avg=%0.2f, min=%0.2f, max=%0.2f)\n",
	 avg_rtt, min_rtt, max_rtt);
  
  pcap_close(p);
  if (data)
    free(data);
  free(strsrc);
  close(fd);

  return 0;
}

