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

#include <ncsnet/ncsnet.h>
#include <ncsnet/random.h>

static int intf_read_callback(const intf_entry *entry, void *arg)
{
  ncsnet_t *n=(ncsnet_t*)arg;
  if (entry->intf_flags&INTF_FLAG_LOOPBACK||
    entry->intf_flags&INTF_FLAG_POINTOPOINT)
    return 0;
  if (entry->intf_flags&INTF_FLAG_UP) {
    snprintf(n->sock.dev, IFNAMSIZ, "%s", entry->intf_name);
    n->sock.sendfd.srcmac=entry->intf_link_addr.addr_eth;
    n->sock.sendfd.srctype=entry->intf_addr.type;
    if (entry->intf_addr.type==ADDR_TYPE_IP)
      n->sock.sendfd.src.srcip4=entry->intf_addr.addr_ip4;
    else if (entry->intf_addr.type==ADDR_TYPE_IP6)
       n->sock.sendfd.src.srcip6=entry->intf_addr.addr_ip6;
    return 1;
  }
  return 0;
}

static bool intf_read(ncsnet_t *n)
{
  intf_t *i;
  i=intf_open();
  if (!i)
    return 0;
  if (!(intf_loop(i, intf_read_callback, n)))
    return 0;
  intf_close(i);
  return 1;
}

ncsnet_t *ncsopen(void)
{
  ncsnet_t *n=calloc(1, sizeof(ncsnet_t));
  if (!n) {
    __ncsseterror(
        "%s: allocated failed\n", __FUNCTION__);
    return NULL;
  }
  if (!intf_read(n)) {
    __ncsseterror(
        "%s: failed read interface (check network)\n", __FUNCTION__);
    goto fail;
  }


  /*
   * There is no point in supporting dlt 802.11 used for
   * wifi networks, because the system, if the interface
   * is not in monitoring mode, simply converts the dlt
   * 802.11 packet into an ethernet 2 packet.
   */
  n->sock.sendfd.dlttype=DLT_EN10MB;
  if (n->sock.sendfd.dlttype==DLT_EN10MB) {
    if (!(n->sock.sendfd.dlt_802_3.eth2=eth_open((n->sock.dev)))) {
      __ncsseterror(
          "%s: failed open ethernet fd\n", __FUNCTION__);
      goto fail;
    }
  }
  randutils_open(__cmwc_random_num_call);
  n->sock.bind=0;
  n->sock.recvfd.lr=lr_open(DEFAULT_RTIMEOUT);
  n->sock.rbuflen=DEFAULT_RBUFLEN;
  n->sock.bindproto=DEFAULT_BINDPROTO;
  n->sock.proto=DEFAULT_PROTO;
  n->sock.rinfolvl=DEFAULT_RINFO;
  n->sock.sinfolvl=DEFAULT_SINFO;

  return n;

fail:
  ncsclose(n);
  return NULL;
}

void __ncsopen_info(ncsnet_t *n)
{
  char srcmac[MAC_ADDR_STRING_LEN];

  mact_ntop(&n->sock.sendfd.srcmac, srcmac, MAC_ADDR_STRING_LEN);
  printf("sendfd: intf=%s dlt=%s, srcmac=%s", n->sock.dev,
      (n->sock.sendfd.dlttype==DLT_EN10MB)?"eth":"wifi", srcmac);
  if (n->sock.sendfd.srctype==ADDR_TYPE_IP)
    printf(" inet=%s", ip4t_ntop_c(&n->sock.sendfd.src.srcip4));
  else if (n->sock.sendfd.srctype==ADDR_TYPE_IP6)
    printf(" inet=%s", ip6t_ntop_c(&n->sock.sendfd.src.srcip6));
  if (n->sock.sendfd.dlttype==DLT_EN10MB)
    printf(" eth=%s mactype:%hu\n", (n->sock.sendfd.dlt_802_3.eth2)?"yes":"fuck",
        ntohs(n->sock.sendfd.dlt_802_3.mactype));
}

/*
 * The example on which the interface was made
 *
 * u8 *tcp, *buf;
 * ip4h_t *iphdr;
 * ncnet_t *n;
 *
 * tcp=tcp_build_pkt(...);
 *
 * n = ncsopen();
 * if (!n)
 *   ncsperror("open");
 * ncsopts(n, RTIMEOUT|BUFLEN|GENERATELINK, 100, 65535, 1);
 *
 * if ((ncssend(n, IP, tcp, frmlen))<0)
 *   ncsperror("send");
 * if ((ncsrecv(n, recv_callback))<0);
 *   ncsperror("recv");
 *
 * buf = ncsbuf(ncsbuflen()-10);
 * ncsfreebuf();
 *
 * if ((ncsrecv(n, recv_callback))<0);
 *   ncsperror("recv");
 *
 * char tmpbuf[ncsbuflen()];
 * ncswritebuf(tmpbuf, ncsbuflen(), ncsbuflen()-10);
 * ncsfreebuf();
 *
 * iphdr=(ip4h_t*)tmpbuf;
 *
 * ncsclose(n);
 *
*/

