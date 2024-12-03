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

//#include <ncsnet/tcp.h>
#include "../../ncsnet/tcp.h"

static bool tcp_callback(u8 *frame, size_t frmlen, void *arg)
{
  tcph_t *tcphdr;
  mach_t *link;
  tcp_t *t;

  t=(tcp_t*)arg;
  if (frmlen<14)
    return 0;

  link=(mach_t*)frame;
  if (ntohs(link->type)!=ETH_TYPE_IPV4
      &&t->bind.family==4)
    return 0;
  if (ntohs(link->type)!=ETH_TYPE_IPV6
      &&t->bind.family==6)
    return 0;

  if (((frmlen-14)<sizeof(ip4h_t)&&
    t->bind.family==4)||((frmlen-14)
      <sizeof(ip6h_t)&&t->bind.family==6))
    return 0;
  if (t->bind.family==4) {
    ip4h_t *tmp;
    tmp=(ip4h_t*)(frame+14);
    if (!ip4t_compare(tmp->src, t->bind.ip4))
      return 0;
    if (tmp->proto!=6)
      return 0;
    if (((frmlen-14)-sizeof(ip4h_t))
        <sizeof(tcph_t))
      return 0;
    tcphdr=(tcph_t*)((frame+14)+sizeof(ip4h_t));
  }
  else if (t->bind.family==6) {
    ip6h_t *tmp;
    tmp=(ip6h_t*)(frame+14);
    if (!ip6t_compare(tmp->src, t->bind.ip6))
      return 0;
    if (tmp->nxt!=6)
      return 0;
    if (((frmlen-14)-sizeof(ip6h_t))
        <sizeof(tcph_t))
      return 0;
    tcphdr=(tcph_t*)((frame+14)+sizeof(ip6h_t));
  }

  if (ntohs(tcphdr->th_sport)!=t->bind.port)
    return 0;
  if (tcphdr->th_flags==0x12&&t->state==TCP_SYN_SENT) {
    t->state=TCP_SYN_RECEIVED;
    t->seq=ntohl(tcphdr->th_seq);
    t->ack=ntohl(tcphdr->th_ack);
    printf("%u and %u\n", t->ack, t->seq);
  }

  return 1;
}

tcp_t *tcp_open(const char *device, long long ns)
{
  tcp_t *tcp;
  tcp=(tcp_t*)calloc(1, sizeof(tcp_t));
  if (!tcp)
    return NULL;
  if (!(tcp->sfd=eth_open(device)))
    goto free;
  if (!(tcp->rfd=lr_open(device, ns)))
    goto free;
  lr_callback(tcp->rfd, tcp_callback);
  return tcp;
free:
  if (tcp->sfd)
    eth_close(tcp->sfd);
  if (tcp->rfd)
    lr_close(tcp->rfd);
  free(tcp);
  return NULL;
}

void tcp_add_link(tcp_t *tcp, u8 *link, size_t linklen)
{
  if (!link||!linklen)
    return;
  tcp->link=link;
  tcp->linklen=linklen;
}

static u8 *__tcpframe(u8 *link, size_t linklen, u8 *tcp,
  size_t tcplen, tcp_info_t *src, tcp_info_t *dst,
  size_t *reslen)
{
  u8 *res, *ip;
  size_t iplen;

  *reslen=(linklen+20+tcplen);
  res=(u8*)calloc(1, *reslen);
  if (src->family==4&&dst->family==4) {
    tcp4_check(tcp, tcplen, src->ip4, dst->ip4, 0);
    ip=ip4_build(src->ip4, dst->ip4, 6, random_num_u32(64, 255),
      random_u16(), 0, IP4_DF, NULL, 0, tcp, tcplen,
      &iplen);
    if (!ip)
      return NULL;
    memcpy(res, link, linklen);
    memcpy((res+14), ip, iplen);
  }
  /* ..., ip6 */

  free(ip);
  return res;
}

static bool __tcpunconnect(tcp_t *tcp, tcp_info_t *src, tcp_info_t *dst)
{
  size_t tcpflen, reslen;
  u8 *tcpf, *res;

  if (tcp->state!=TCP_ESTABLISHED_CONNECTON)
    return 1;
  if (!src||!dst||!tcp)
    return 0;

  tcp->state=TCP_FIN_WAIT_1;
  tcpf=tcp_build(src->port, dst->port,
    random_u32(), 0, 0, TCP_FLAG_RST, 1024, 0,
    NULL, 0, NULL, 0, &tcpflen);
  res=__tcpframe(tcp->link, tcp->linklen, tcpf,
    tcpflen, src, dst, &reslen);
  free(tcpf);
  eth_send(tcp->sfd, res, reslen);
  free(res);

  return 1;
}

bool tcp_handshake(tcp_t *tcp, tcp_info_t *src, tcp_info_t *dst)
{
  size_t tcpflen, reslen;
  u8 *tcpf, *res, *rbuf;
  ssize_t ret;

  if (!src||!dst||!tcp)
    return 0;
  memcpy(&tcp->bind, dst, sizeof(tcp_info_t));
  memcpy(&tcp->src, src, sizeof(tcp_info_t));

  tcp->state=TCP_SYN_SENT;
  tcp->seq=random_u32();
  tcp->ack=0;
  tcpf=tcp_build(src->port, dst->port,
    tcp->seq, tcp->ack, 0, TCP_FLAG_SYN, 1024, 0,
    NULL, 0, NULL, 0, &tcpflen);
  res=__tcpframe(tcp->link, tcp->linklen, tcpf,
    tcpflen, src, dst, &reslen);
  free(tcpf);
  ret=eth_send(tcp->sfd, res, reslen);
  free(res);

  rbuf=calloc(1, USHRT_MAX);
  ret=lr_live(tcp->rfd, &rbuf, USHRT_MAX, tcp);
  free(rbuf);
  if (ret==-1)
    return 0;
  if (tcp->state!=TCP_SYN_RECEIVED) {
    tcp->state=TCP_CLOSED;
    return 0;
  }

  tcpf=tcp_build(src->port, dst->port,
    tcp->ack, (tcp->seq+1), 0, TCP_FLAG_ACK, 1024, 0,
    NULL, 0, NULL, 0, &tcpflen);
  res=__tcpframe(tcp->link, tcp->linklen, tcpf,
    tcpflen, src, dst, &reslen);
  free(tcpf);
  eth_send(tcp->sfd, res, reslen);
  free(res);

  tcp->state=TCP_ESTABLISHED_CONNECTON;
  return 1;
}

void tcp_send(tcp_t *tcp, const u8 *buf, size_t buflen)
{
  return;
}

void tcp_recv(tcp_t *tcp, u8 *buf, size_t buflen)
{
  return;
}


void tcp_close(tcp_t *tcp)
{
  if (!tcp)
    return;
  __tcpunconnect(tcp, &tcp->src,
    &tcp->bind);
  if (tcp->sfd)
    eth_close(tcp->sfd);
  if (tcp->rfd)
    lr_close(tcp->rfd);
  if (tcp->link)
    free(tcp->link);
  free(tcp);
}