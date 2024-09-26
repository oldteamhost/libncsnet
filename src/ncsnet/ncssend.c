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

//#include <ncsnet/ncsnet.h>
#include "../../ncsnet/ncsnet.h"

static int __ip_v(void *frame, size_t frmlen, bool eth)
{
  size_t skip;
  ip4h_t *ip;
  if (eth)
    skip=ETH_HDR_LEN;
  else
    skip=0;
  ip=(ip4h_t*)frame+skip;
  return ip->version;
}

static bool __get_route(const char *to, addr_t *gateway)
{
  route_entry entry;
  route_t    *r;

  r=route_open();
  if (!r)
    return 0;
  addr_pton(to, &entry.route_dst);
  if ((route_get(r, &entry))==-1) {
    route_close(r);
    return 0;
  }
  route_close(r);
  *gateway=entry.route_gw;
  return 1;
}


/*
 * Callback to filter and accept ARP response
 */
static ip4_t tmpsrc;
static bool received_arp_callback(u8 *frame, size_t frmlen, void *arg)
{
  arp_op_request_ethip *arpreq;
  mach_t *datalink;

  datalink=(mach_t*)frame;

  /* The payload type will definitely be ARP */
  if (ntohs(datalink->type)!=ETH_TYPE_ARP)
    return false;

  /*
   * The ip4 address of the recipient inside
   * the ARP request must match the local ip4
   * address, otherwise, the packet was not
   * addressed to us.
   */
  arpreq=(arp_op_request_ethip*)((frame)+(sizeof(mach_t)+sizeof(arph_t)));
  if (!ip4t_compare(arpreq->tpa, tmpsrc))
    return false;

  return true;
}


/*
 * Gets the destination MAC address by sending/receiving
 * an ARP request/response to the gateway address it
 * first receives, and stores it in n->dstmac.
 */
static bool __proc_arpreq(ncsnet_t *n, const char *to, mac_t *dst)
{
  arp_op_request_ethip *arpreq;
  u8                   *arp, *buf;
  size_t                arplen=0;
  addr_t                gw;
  mac_t                 srcmaceth;
  mac_t                 srcmacarp;
  lrcall_t              tmpcb;

  /*
   * Obtaining a route (gateway) to send the packet
   * to the "to".
   */

  __get_route(to, &gw);


  /*
   * Now send ETH frame to broadcast with ARP request
   * to the gateway received earlier, specify zero as
   * hardware source address in ARP request.
   */

  mact_fill(&srcmaceth, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
  mact_fill(&srcmacarp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  arp=arp_ethip4_build_pkt(n->sock.sendfd.srcmac, srcmaceth, ARP_OP_REQUEST,
    n->sock.sendfd.srcmac, n->sock.sendfd.src.srcip4, srcmacarp, gw.addr_ip4,
    &arplen);
  eth_send(n->sock.sendfd.dlt_802_3.eth2, arp, arplen);
  free(arp);

  /* For callback */
  ip4t_copy(&tmpsrc, &n->sock.sendfd.src.srcip4);


  /*
   * Now receive an ARP response where we get the mac
   * address of the remote host in the sha field
   * inside the ARP response.
   */
  tmpcb=lr_getcallback(n->sock.recvfd.lr);
  lr_callback(n->sock.recvfd.lr, received_arp_callback);
  buf=(u8*)calloc(1, DEFAULT_RBUFLEN);
  lr_live(n->sock.recvfd.lr, &buf, DEFAULT_RBUFLEN, NULL);
  arpreq=(arp_op_request_ethip*)((buf)+(sizeof(mach_t)+sizeof(arph_t)));
  mact_copy(dst, &arpreq->sha);
  free(buf);
  lr_callback(n->sock.recvfd.lr, tmpcb);

  return 1;
}

static bool __proc_arpcache(ncsnet_t *n, const char *to, mac_t *dst)
{
  char ip[32], hw_type[32], flags[32], mac[32], mask[32], device[32];
  const char *gwstr;
  char line[256];
  int found=0;
  addr_t gw;
  FILE *fp;

  __get_route(to, &gw);
  if (gw.type!=ADDR_TYPE_IP)
    return 0;
  gwstr=ip4t_ntop_c(&gw.addr_ip4);

  fp=fopen("/proc/net/arp", "r");
  if (!fp)
    return found;
  fgets(line, sizeof(line), fp);
  while (fgets(line, sizeof(line), fp)) {
    sscanf(line, "%31s %31s %31s %31s %31s %31s", ip, hw_type, flags, mac, mask, device);
    if (strcmp(device, n->sock.dev))
      continue;
    if (strcmp(ip, gwstr))
      continue;
    found=1;
    break;
  }
  if (found)
    mact_pton(mac, dst);
  fclose(fp);
  if (mact_compare(*dst, n->sock.sendfd.srcmac))
    found=0;
  return found;
}


static bool __get_dstmac(ncsnet_t *n, const char *to, mac_t *dst)
{
  if ((__proc_arpreq(n, to, dst)))
    return 1;
  if ((__proc_arpcache(n, to, dst)))
    return 1;
  return 0;
}

static u8 *__generate_802_3_ip(ncsnet_t *n, u8 *frame, size_t frmlen, size_t *outlen)
{
  mac_t dst;
  u8 *res;

  if ((__ip_v(frame, frmlen, 0)==4)) {
    ip4h_t *ip4hdr;
    ip4hdr=(ip4h_t*)frame;
    __get_dstmac(n, (ip4t_ntop_c(&ip4hdr->dst)),&dst);
    n->sock.sendfd.dlt_802_3.mactype=ETH_TYPE_IPV4;
  }
  else {
    ip6h_t *ip6hdr;
    ip6hdr=(ip6h_t*)frame;
    ip6hdr->hoplimit=0;

    /* fix warning on getmac */
    n->sock.sendfd.dlt_802_3.mactype=ETH_TYPE_IPV6;
  }

  res=eth_build(n->sock.sendfd.srcmac, dst,
    n->sock.sendfd.dlt_802_3.mactype, frame,
    frmlen, outlen);

  return res;
}

static u8 *__generate_ip(ncsnet_t *n, u8 *frame, size_t frmlen, size_t *outlen, ncsaddr_ip *nip)
{
  u8 *ip, *res;

  if (nip->af==4)
    ip=ip4_build(n->sock.sendfd.src.srcip4, nip->dst.dst4, n->sock.proto,
      random_num_u32(54, 200), random_u16(), 0, 0, NULL, 0, frame, frmlen, outlen);
  else
    ip=ip6_build(n->sock.sendfd.src.srcip6, nip->dst.dst6, 0, 1, n->sock.proto,
        random_num_u32(54, 200), frame, frmlen, outlen);

  res=__generate_802_3_ip(n, ip, *outlen, outlen);

  free(ip);
  return res;
}

void *__ncssend_getnip_generic(int af, ip4_t *ip4, ip6_t *ip6)
{
  static u8 tmp[sizeof(ncsaddr_ip)]; /* наеб system */
  memset(tmp, 0, sizeof(ncsaddr_ip));
  ncsaddr_ip *res=(ncsaddr_ip*)tmp;
  res->af=af;
  if (ip4)
    res->dst.dst4=*ip4;;
  if (ip6)
    res->dst.dst6=*ip6;;
  return (void*)res;
}

ssize_t __ncssend(ncsnet_t *n, void *frame, size_t frmlen, void *arg)
{
  size_t sndfrmlen=0;
  u8 *sndfrm=NULL;
  ncsaddr_ip *nip;
  ssize_t ret=0;
  bool edited=0;

  if (!n)
    n=ncsopen();

  /* RAW send */
  if (n->sock.proto==PR_RAW) {
    sndfrm=(u8*)frame;
    sndfrmlen=frmlen;
    goto send;
  }

  /* For send IP (auto datalink) */
  if (n->sock.proto==PR_IP) {
    sndfrm=__generate_802_3_ip(n, (u8*)frame, frmlen, &sndfrmlen);
    edited=1;
    goto send;
  }

  /* For send IPPROTO-S (auto datalink and ip header) */
  if (arg) {
    nip=(ncsaddr_ip*)arg;
    sndfrm=__generate_ip(n, frame, frmlen, &sndfrmlen, nip);
    edited=1;
    goto send;
  }

send:
  ret=eth_send(n->sock.sendfd.dlt_802_3.eth2,
    sndfrm, sndfrmlen);
  if (n->sock.sinfolvl>0&&sndfrm&&sndfrmlen)
    printf("%s\n", frminfo(sndfrm, sndfrmlen, n->sock.sinfolvl, 0));
  if (edited)
    free(sndfrm);
  return ret;
}
