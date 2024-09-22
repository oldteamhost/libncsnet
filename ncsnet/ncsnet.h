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

#ifndef NCSNETHDR
#define NCSNETHDR

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <sys/cdefs.h>

#include "eth.h"
#include "utils.h"
#include "trace.h"
#include "addr.h"
#include "route.h"
#include "random.h"
#include "arp.h"
#include "linuxread.h"
#include "intf.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

/* Type to represent time in nanoseconds. */
typedef long long ncstime_t;


/*
 * An infinite structure to represent the buffer(s), for
 * receiving packets. Contains the time points of reception
 * start and end in nanoseconds. The buffer to receive, the
 * number of bytes received, its identifier, and a pointer
 * to the next such buffer (for infinity).
 */

typedef struct ncsnet_rbuf_hdr{
  struct timeval tstamp_s, tstamp_e;
  struct ncsnet_rbuf_hdr *nxt;
  size_t received;
  int    index;
  u8    *rbuf;
} ncsnet_rbuf;


/*
 * Socket to receive packets, contains infinite buffers, and a
 * linuxread object descriptor (see ncsnet/trace/linuxread.c)
 */

typedef struct ncsnet_sock_hdr_recv
{
  ncsnet_rbuf *rbuf;
  lr_t        *lr;
} ncsnet_sock_recv;


/*
 * Socket to receive packets, contains sender data such as MAC,
 * IP4 v IP6 address. Descriptor to send, etc.
 */

typedef struct ncsnet_sock_hdr_send
{
  int   srctype, dlttype;
  mac_t srcmac;

  struct dlt_802_11_hdr {
    eth_t *eth2;
    u16    mactype;
  } dlt_802_3;

  union {
    ip4_t  srcip4;
    ip6_t  srcip6;
  } src;
} ncsnet_sock_send;


/*
 * The ncsnet_t socket, for sending, receiving, and binding. Contains
 * the previous structures, but supplements them with options, interface
 * device, and mapping address.
 */

typedef struct ncsnet_sock_hdr
{
  char              dev[IFNAMSIZ];
  ncstime_t         rtimeout;
  int               proto, bindproto;
  size_t            rbuflen;
  int               bind;
  int               rinfolvl, sinfolvl;

  ncsnet_sock_send  sendfd;
  ncsnet_sock_recv  recvfd;

  union {
    ip4_t ip4;
    ip6_t ip6;
    mac_t mac;
  } ncsnet_bind;
} ncsnet_sock;


/* ncsnet_t */
typedef struct ncsnet_hdr
{
  ncsnet_sock sock;
} ncsnet_t;


__BEGIN_DECLS


/*
 * ncsopen(), ncsclose(n)
 *
 * Creates an “ncsnet_t” object, opens sockets, sets default
 * option values, gets active interface, sender data, etc. Must
 * be closed, and cleared with “ncsclose”.
 */

ncsnet_t *ncsopen(void);
ncsnet_t *ncsopen_s(const char *device);
void      ncsclose(ncsnet_t *n);
void      __ncsopen_info(ncsnet_t *n);




/*
 * ncsopts(n, NCSOPT_RTIMEOUT|NCSOPT_RBUFLEN, 543, 1000)
 *
 * In fact, options are not passed through flags, the “|”
 * operation is needed only to pass several options into
 * one variable at once. So, when passing an option, e.g.
 * “NCSOPT_RTIMEOUT”, the function “___opts_set” is called,
 * which adds this option to the static array “_opts” and
 * increments “optscount” by 1, at the same time returning
 * its value 0x01, just to avoid an error.
 *
 * Thus, unlike simple flag passing, we preserve the order
 * of the options, and can safely use va_list without
 * worrying about the order.
 */

#define NCSOPT_RTIMEOUT      ____opt_set(1)
#define NCSOPT_RBUFLEN       ____opt_set(2)
#define NCSOPT_PROTO         ____opt_set(3)
#define NCSOPT_BINDPROTO     ____opt_set(4)
#define NCSOPT_RINFO         ____opt_set(5)
#define NCSOPT_SINFO         ____opt_set(6)

#define NCSOPTSCOUNT         6

#define DEFAULT_RTIMEOUT     to_ns(2000)
#define DEFAULT_RBUFLEN      4096
#define DEFAULT_PROTO        PR_RAW
#define DEFAULT_BINDPROTO    0
#define DEFAULT_RINFO        0
#define DEFAULT_SINFO        0

int ____opt_set(int code);
bool ncsopts(ncsnet_t *n, int opts, ...);




/*
 * ncsbind(n, addr)
 *
 * Binds the socket to the specified host at its ip4|ip6|mac
 * address. After binding, “ncsrecv” does not need to specify
 * a “callback” because “ncsbind” generates its own callback
 * that will wait for a packet from the socket's associated
 * address. Also, if ncsnet has received additional information
 * via options that may be useful for the callback (e.g. “
 * NCSOPT_BINDPROTO”), it will certainly use it.
 */

#define __BINDTYPE_IP4 0x05
#define __BINDTYPE_IP6 0x06
#define __BINDTYPE_MAC 0x07

#define ncsbind(n, addr) _Generic((addr), \
    ip4_t: __ncsbind_ip4,                 \
    ip6_t: __ncsbind_ip6,                 \
    mac_t: __ncsbind_mac)((n),(addr))

bool __bind_callback(u8 *frame, size_t fmrlen);
bool __ncsbind_general(ncsnet_t *n, int bind, ip4_t *ip4, ip6_t *ip6, mac_t *mac);

inline bool __ncsbind_ip4(ncsnet_t *n, ip4_t ip4) {
  return __ncsbind_general(n, __BINDTYPE_IP4, &ip4, NULL, NULL);
}
inline bool __ncsbind_ip6(ncsnet_t *n, ip6_t ip6) {
  return __ncsbind_general(n, __BINDTYPE_IP6, NULL, &ip6, NULL);
}
inline bool __ncsbind_mac(ncsnet_t *n, mac_t mac) {
  return __ncsbind_general(n, __BINDTYPE_MAC, NULL, NULL, &mac);
}




/*
 * ncsrecv(n, callback, 1)
 *
 * The function receives a packet by filtering it with the specified
 * “callback”, and saves it to a buffer with the specified “id_rb”
 * (index recv buffer), which can then be retrieved by “ncsrbuf”,
 * or written by “ncsrbuf_write”, deleted (by clearing memory) by
 * “ncsrbuf_free”, retrieved by “ncsrbuf_len”, or retrieved by
 * “ncsrbuf_rtt” to get its length (which was received), or
 * retrieved by “ncsrbuf_rtt” to get the difference in round-trip
 * time.
 *
 * ncsnet_t {
 *   buffers {           ncsrbuf(n, 7855, ncsrbuf_len(n, 7855))
 *     index[buflen]     ^
 *     index[buflen]     |
 *     index[buflen] <---|
 *     ...,              |
 *   }         --------> createbuf(7855);
 * }           ^
 *             |
 * ncsrecv(n, NULL, 7855);
 * ncstime_t ms = ncsrbuf_rtt(n, 7855)/1000000LL;
 */

ssize_t ncsrecv(ncsnet_t *n, lrcall_t callback, int id_rb);

u8       *ncsrbuf(ncsnet_t *n, int id_rb, size_t getlen);
ncstime_t ncsrbuf_rtt(ncsnet_t *n, int id_rb);
size_t    ncsrbuf_len(ncsnet_t *n, int id_rb);
bool      ncsrbuf_write(ncsnet_t *n, int id_rb, void *dst, size_t dstlen, size_t getlen);
void      ncsrbuf_free(ncsnet_t *n, int id_rb);

void __ncsrbuf_create(ncsnet_t *n, int index);
ncsnet_rbuf *__ncsrbuf_get(ncsnet_t *n, int index);
u8 *__ncsrbuf_getrbuf(ncsnet_t *n, int index);
void __ncsrbuf_free(ncsnet_t *n, int index);
void __ncsrbuf_all_free(ncsnet_rbuf *rbuf);




/*
 * ncserorr(), ncsperror()
 *
 * Functions to handle errors, “ncserror” returns an error
 * in “const char *”; “ncsperror” writes the error to
 * stdout.
 */

#define NCSERRMAXLEN 2048

const char *ncserror(void);
void        ncsperror(void);
void        __ncsseterror(const char *fmt, ...);




/*
 * ncssend(n, buf, buflen)
 *
 * Sends the specified packet through the socket open on
 * “ncsopen”, depends on “NCSOPT_PROTO”, by standard this
 * option is set to 255 (PR_RAW), and “ncssend” does not
 * touch the packet, and just sends it. In the case when
 * it is set to (PR_IP) for example, “ncssend” will
 * consider that the packet to be sent does not contain
 * Ethernet II header and will generate it, etc.
*/

#define PR_IP          0
#define PR_RAW         255

#define PR_ICMP        1    /* ICMP */
#define PR_IGMP        2    /* IGMP */
#define PR_GGP         3    /* gateway-gateway protocol */
#define PR_IPIP        4    /* IP in IP */
#define PR_ST          5    /* ST datagram mode */
#define PR_TCP         6    /* TCP */
#define PR_CBT         7    /* CBT */
#define PR_EGP         8    /* exterior gateway protocol */
#define PR_IGP         9    /* interior gateway protocol */
#define PR_BBNRCC      10    /* BBN RCC monitoring */
#define PR_NVP         11    /* Network Voice Protocol */
#define PR_PUP         12    /* PARC universal packet */
#define PR_ARGUS       13    /* ARGUS */
#define PR_EMCON       14    /* EMCON */
#define PR_XNET        15    /* Cross Net Debugger */
#define PR_CHAOS       16    /* Chaos */
#define PR_UDP         17    /* UDP */
#define PR_MUX         18    /* multiplexing */
#define PR_DCNMEAS     19    /* DCN measurement */
#define PR_HMP         20    /* Host Monitoring Protocol */
#define PR_PRM         21    /* Packet Radio Measurement */
#define PR_IDP         22    /* Xerox NS IDP */
#define PR_TRUNK1      23    /* Trunk-1 */
#define PR_TRUNK2      24    /* Trunk-2 */
#define PR_LEAF1       25    /* Leaf-1 */
#define PR_LEAF2       26    /* Leaf-2 */
#define PR_RDP         27    /* "Reliable Datagram" proto */
#define PR_IRTP        28    /* Inet Reliable Transaction */
#define PR_TP          29    /* ISO TP class 4 */
#define PR_NETBLT      30    /* Bulk Data Transfer */
#define PR_MFPNSP      31    /* MFE Network Services */
#define PR_MERITINP    32    /* Merit Internodal Protocol */
#define PR_SEP         33    /* Sequential Exchange proto */
#define PR_3PC         34    /* Third Party Connect proto */
#define PR_IDPR        35    /* Interdomain Policy Route */
#define PR_XTP         36    /* Xpress Transfer Protocol */
#define PR_DDP         37    /* Datagram Delivery Proto */
#define PR_CMTP        38    /* IDPR Ctrl Message Trans */
#define PR_TPPP        39    /* TP++ Transport Protocol */
#define PR_IL          40    /* IL Transport Protocol */
#define __PR_IPV6      41    /* IPv6 */
#define PR_SDRP        42    /* Source Demand Routing */
#define PR_ROUTING     43    /* IPv6 routing header */
#define PR_FRAGMENT    44    /* IPv6 fragmentation header */
#define PR_RSVP        46    /* Reservation protocol */
#define PR_GRE         47    /* General Routing Encap */
#define PR_MHRP        48    /* Mobile Host Routing */
#define PR_ENA         49    /* ENA */
#define PR_ESP         50    /* Encap Security Payload */
#define PR_AH          51    /* Authentication Header */
#define PR_INLSP       52    /* Integated Net Layer Sec */
#define PR_SWIPE       53    /* SWIPE */
#define PR_NARP        54    /* NBMA Address Resolution */
#define PR_MOBILE      55    /* Mobile IP, RFC 2004 */
#define PR_TLSP        56    /* Transport Layer Security */
#define PR_SKIP        57    /* SKIP */
#define PR_ICMPV6      58    /* ICMP for IPv6 */
#define PR_NONE        59    /* IPv6 no next header */
#define PR_DSTOPTS     60    /* IPv6 destination options */
#define PR_ANYHOST     61    /* any host internal proto */
#define PR_CFTP        62    /* CFTP */
#define PR_ANYNET      63    /* any local network */
#define PR_EXPAK       64    /* SATNET and Backroom EXPAK */
#define PR_KRYPTOLAN   65    /* Kryptolan */
#define PR_RVD         66    /* MIT Remote Virtual Disk */
#define PR_IPPC        67    /* Inet Pluribus Packet Core */
#define PR_DISTFS      68    /* any distributed fs */
#define PR_SATMON      69    /* SATNET Monitoring */
#define PR_VISA        70    /* VISA Protocol */
#define PR_IPCV        71    /* Inet Packet Core Utility */
#define PR_CPNX        72    /* Comp Proto Net Executive */
#define PR_CPHB        73    /* Comp Protocol Heart Beat */
#define PR_WSN         74    /* Wang Span Network */
#define PR_PVP         75    /* Packet Video Protocol */
#define PR_BRSATMON    76    /* Backroom SATNET Monitor */
#define PR_SUNND       77    /* SUN ND Protocol */
#define PR_WBMON       78    /* WIDEBAND Monitoring */
#define PR_WBEXPAK     79    /* WIDEBAND EXPAK */
#define PR_EON         80    /* ISO CNLP */
#define PR_VMTP        81    /* Versatile Msg Transport*/
#define PR_SVMTP       82    /* Secure VMTP */
#define PR_VINES       83    /* VINES */
#define PR_TTP         84    /* TTP */
#define PR_NSFIGP      85    /* NSFNET-IGP */
#define PR_DGP         86    /* Dissimilar Gateway Proto */
#define PR_TCF         87    /* TCF */
#define PR_EIGRP       88    /* EIGRP */
#define PR_OSPF        89    /* Open Shortest Path First */
#define PR_SPRITERPC   90    /* Sprite RPC Protocol */
#define PR_LARP        91    /* Locus Address Resolution */
#define PR_MTP         92    /* Multicast Transport Proto */
#define PR_AX25        93    /* AX.25 Frames */
#define PR_IPIPENCAP   94    /* yet-another IP encap */
#define PR_MICP        95    /* Mobile Internet Ctrl */
#define PR_SCCSP       96    /* Semaphore Comm Sec Proto */
#define PR_ETHERIP     97    /* Ethernet in IPv4 */
#define PR_ENCAP       98    /* encapsulation header */
#define PR_ANYENC      99    /* private encryption scheme */
#define PR_GMTP        100   /* GMTP */
#define PR_IFMP        101   /* Ipsilon Flow Mgmt Proto */
#define PR_PNNI        102   /* PNNI over IP */
#define PR_PIM         103   /* Protocol Indep Multicast */
#define PR_ARIS        104   /* ARIS */
#define PR_SCPS        105   /* SCPS */
#define PR_QNX         106   /* QNX */
#define PR_AN          107   /* Active Networks */
#define PR_IPCOMP      108   /* IP Payload Compression */
#define PR_SNP         109   /* Sitara Networks Protocol */
#define PR_COMPAQPEER  110   /* Compaq Peer Protocol */
#define PR_IPXIP       111   /* IPX in IP */
#define PR_VRRP        112   /* Virtual Router Redundancy */
#define PR_PGM         113   /* PGM Reliable Transport */
#define PR_ANY0HOP     114   /* 0-hop protocol */
#define PR_L2TP        115   /* Layer 2 Tunneling Proto */
#define PR_DDX         116   /* D-II Data Exchange (DDX) */
#define PR_IATP        117   /* Interactive Agent Xfer */
#define PR_STP         118   /* Schedule Transfer Proto */
#define PR_SRP         119   /* SpectraLink Radio Proto */
#define PR_UTI         120   /* UTI */
#define PR_SMP         121   /* Simple Message Protocol */
#define PR_SM          122   /* SM */
#define PR_PTP         123   /* Performance Transparency */
#define PR_ISIS        124   /* ISIS over IPv4 */
#define PR_FIRE        125   /* FIRE */
#define PR_CRTP        126   /* Combat Radio Transport */
#define PR_CRUDP       127   /* Combat Radio UDP */
#define PR_SSCOPMCE    128   /* SSCOPMCE */
#define PR_IPLT        129   /* IPLT */
#define PR_SPS         130   /* Secure Packet Shield */
#define PR_PIPE        131   /* Private IP Encap in IP */
#define PR_SCTP        132   /* Stream Ctrl Transmission */
#define PR_FC          133   /* Fibre Channel */
#define PR_RSVPIGN     134   /* RSVP-E2E-IGNORE */

typedef struct ncsaddr_ip_hdr {
#define AF_IP4 4
#define AF_IP6 6
  int af;
  union {
    ip4_t dst4;
    ip6_t dst6;
  } dst;
} ncsaddr_ip;

#define ncssend(...) \
  _is_ncssend(__VA_ARGS__, _ncssend_to, _ncssend)(__VA_ARGS__)

#define ncssend_getnip(addr) _Generic((addr), \
    ip4_t: __ncssend_getnip_v4,               \
    ip6_t: __ncssend_getnip_v6)((addr))

#define _is_ncssend(_1, _2, _3, _4, NAME, ...) NAME
#define _ncssend(n, frame, frmlen) __ncssend((n), (frame), (frmlen), NULL)
#define _ncssend_to(n, frame, frmlen, naddr) __ncssend((n), (frame), (frmlen), (naddr))

void *__ncssend_getnip_generic(int af, ip4_t *ip4, ip6_t *ip6);
inline void *__ncssend_getnip_v4(ip4_t ip4) { return __ncssend_getnip_generic(AF_IP4, &ip4, NULL); }
inline void *__ncssend_getnip_v6(ip6_t ip6) { return __ncssend_getnip_generic(AF_IP6, NULL, &ip6); }
ssize_t __ncssend(ncsnet_t *n, void *frame, size_t frmlen, void *arg);

__END_DECLS

#endif
