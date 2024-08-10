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

#include <ncsnet/trace.h>

char *read_util_nexthdrtoa(u8 nxthdr, int acronym)
{
  static char buf[129];
  memset(buf, 0, 129);

#define HDRTOA(num, short_name, long_name)	\
  case num:							\
    strncpy(buf, acronym ? short_name : long_name, 128);\
    break;

  switch(nxthdr){
  HDRTOA(0, "hopopt", "IPv6 Hop-by-Hop Option")
  HDRTOA(1, "icmp", "Internet Control Message")
  HDRTOA(2, "igmp", "Internet Group Management")
  HDRTOA(3, "ggp", "Gateway-to-Gateway")
  HDRTOA(4, "ipv4", "IP in IP (encapsulation)")
  HDRTOA(5, "st", "Stream")
  HDRTOA(6, "tcp", "Transmission Control")
  HDRTOA(7, "cbt", "CBT")
  HDRTOA(8, "egp", "Exterior Gateway Protocol")
  HDRTOA(9, "igp", "any private interior gateway")
  HDRTOA(10, "bbn-rcc-mon", "BBN RCC Monitoring")
  HDRTOA(11, "nvp-ii", "Network Voice Protocol")
  HDRTOA(12, "pup", "PARC universal packet protocol")
  HDRTOA(13, "argus", "ARGUS")
  HDRTOA(14, "emcon", "EMCON")
  HDRTOA(15, "xnet", "Cross Net Debugger")
  HDRTOA(16, "chaos", "Chaos")
  HDRTOA(17, "udp", "User Datagram")
  HDRTOA(18, "mux", "Multiplexing")
  HDRTOA(19, "dcn-meas", "DCN Measurement Subsystems")
  HDRTOA(20, "hmp", "Host Monitoring")
  HDRTOA(21, "prm", "Packet Radio Measurement")
  HDRTOA(22, "xns-idp", "XEROX NS IDP")
  HDRTOA(23, "trunk-1", "Trunk-1")
  HDRTOA(24, "trunk-2", "Trunk-2")
  HDRTOA(25, "leaf-1", "Leaf-1")
  HDRTOA(26, "leaf-2", "Leaf-2")
  HDRTOA(27, "rdp", "Reliable Data Protocol")
  HDRTOA(28, "irtp", "Internet Reliable Transaction")
  HDRTOA(29, "iso-tp4", "ISO Transport Protocol Class 4")
  HDRTOA(30, "netblt", "Bulk Data Transfer Protocol")
  HDRTOA(31, "mfe-nsp", "MFE Network Services Protocol")
  HDRTOA(32, "merit-inp", "MERIT Internodal Protocol")
  HDRTOA(33, "dccp", "Datagram Congestion Control Protocol")
  HDRTOA(34, "3pc", "Third Party Connect Protocol")
  HDRTOA(35, "idpr", "Inter-Domain Policy Routing Protocol")
  HDRTOA(36, "xtp", "XTP")
  HDRTOA(37, "ddp", "Datagram Delivery Protocol")
  HDRTOA(38, "idpr-cmtp", "IDPR Control Message Transport Proto")
  HDRTOA(39, "tp++", "TP+")
  HDRTOA(40, "il", "IL Transport Protocol")
  HDRTOA(41, "ipv6", "Ipv6")
  HDRTOA(42, "sdrp", "Source Demand Routing Protocol")
  HDRTOA(43, "ipv6-route", "Routing Header for IPv6")
  HDRTOA(44, "ipv6-frag", "Fragment Header for IPv6")
  HDRTOA(45, "idrp", "Inter-Domain Routing Protocol")
  HDRTOA(46, "rsvp", "Reservation Protocol")
  HDRTOA(47, "gre", "General Routing Encapsulation")
  HDRTOA(48, "dsp", "Dynamic Source Routing Protocol. Historically MHRP")
  HDRTOA(49, "bna", "BNA")
  HDRTOA(50, "esp", "Encap Security Payload")
  HDRTOA(51, "ah", "Authentication Header")
  HDRTOA(52, "i-nlsp", "Integrated Net Layer Security  TUBA")
  HDRTOA(53, "swipe", "IP with Encryption")
  HDRTOA(54, "narp", "NBMA Address Resolution Protocol")
  HDRTOA(55, "mobile", "IP Mobility")
  HDRTOA(56, "tlsp", "Transport Layer Security Protocol using Kryptonet key management")
  HDRTOA(57, "skip", "SKIP")
  HDRTOA(58, "ipv6-icmp", "ICMP for IPv6")
  HDRTOA(59, "ipv6-nonxt", "No Next Header for IPv6")
  HDRTOA(60, "ipv6-opts", "Destination Options for IPv6")
  HDRTOA(61, "anyhost", "any host internal protocol")
  HDRTOA(62, "cftp", "CFTP")
  HDRTOA(63, "anylocalnet", "any local network")
  HDRTOA(64, "sat-expak", "SATNET and Backroom EXPAK")
  HDRTOA(65, "kryptolan", "Kryptolan")
  HDRTOA(66, "rvd", "MIT Remote Virtual Disk Protocol")
  HDRTOA(67, "ippc", "Internet Pluribus Packet Core")
  HDRTOA(68, "anydistribfs", "any distributed file system")
  HDRTOA(69, "sat-mon", "SATNET Monitoring")
  HDRTOA(70, "visa", "VISA Protocol")
  HDRTOA(71, "ipcv", "Internet Packet Core Utility")
  HDRTOA(72, "cpnx", "Computer Protocol Network Executive")
  HDRTOA(73, "cphb", "Computer Protocol Heart Beat")
  HDRTOA(74, "wsn", "Wang Span Network")
  HDRTOA(75, "pvp", "Packet Video Protocol")
  HDRTOA(76, "br-sat-mon", "Backroom SATNET Monitoring")
  HDRTOA(77, "sun-nd", "SUN ND PROTOCOL-Temporary")
  HDRTOA(78, "wb-mon", "WIDEBAND Monitoring")
  HDRTOA(79, "wb-expak", "WIDEBAND EXPAK")
  HDRTOA(80, "iso-ip", "ISO Internet Protocol")
  HDRTOA(81, "vmtp", "VMTP")
  HDRTOA(82, "secure-vmtp", "SECURE-VMTP")
  HDRTOA(83, "vines", "VINES")
  HDRTOA(84, "iptm", "Internet Protocol Traffic Manager. Historically TTP")
  HDRTOA(85, "nsfnet-igp", "NSFNET-IGP")
  HDRTOA(86, "dgp", "Dissimilar Gateway Protocol")
  HDRTOA(87, "tcf", "TCF")
  HDRTOA(88, "eigrp", "EIGRP")
  HDRTOA(89, "ospfigp", "OSPFIGP")
  HDRTOA(90, "sprite-rpc", "Sprite RPC Protocol")
  HDRTOA(91, "larp", "Locus Address Resolution Protocol")
  HDRTOA(92, "mtp", "Multicast Transport Protocol")
  HDRTOA(93, "ax.25", "AX.")
  HDRTOA(94, "ipip", "IP-within-IP Encapsulation Protocol")
  HDRTOA(95, "micp", "Mobile Internetworking Control Pro.")
  HDRTOA(96, "scc-sp", "Semaphore Communications Sec.")
  HDRTOA(97, "etherip", "Ethernet-within-IP Encapsulation")
  HDRTOA(98, "encap", "Encapsulation Header")
  HDRTOA(99, "anyencrypt", "any private encryption scheme")
  HDRTOA(100, "gmtp", "GMTP")
  HDRTOA(101, "ifmp", "Ipsilon Flow Management Protocol")
  HDRTOA(102, "pnni", "PNNI over IP")
  HDRTOA(103, "pim", "Protocol Independent Multicast")
  HDRTOA(104, "aris", "ARIS")
  HDRTOA(105, "scps", "SCPS")
  HDRTOA(106, "qnx", "QNX")
  HDRTOA(107, "a/n", "Active Networks")
  HDRTOA(108, "ipcomp", "IP Payload Compression Protocol")
  HDRTOA(109, "snp", "Sitara Networks Protocol")
  HDRTOA(110, "compaq-peer", "Compaq Peer Protocol")
  HDRTOA(111, "ipx-in-ip", "IPX in IP")
  HDRTOA(112, "vrrp", "Virtual Router Redundancy Protocol")
  HDRTOA(113, "pgm", "PGM Reliable Transport Protocol")
  HDRTOA(114, "any0hop", "any 0-hop protocol")
  HDRTOA(115, "l2tp", "Layer Two Tunneling Protocol")
  HDRTOA(116, "ddx", "D-II Data Exchange")
  HDRTOA(117, "iatp", "Interactive Agent Transfer Protocol")
  HDRTOA(118, "stp", "Schedule Transfer Protocol")
  HDRTOA(119, "srp", "SpectraLink Radio Protocol")
  HDRTOA(120, "uti", "UTI")
  HDRTOA(121, "smp", "Simple Message Protocol")
  HDRTOA(122, "sm", "Simple Multicast Protocol")
  HDRTOA(123, "ptp", "Performance Transparency Protocol")
  HDRTOA(124, "isis-ipv4", "ISIS over IPv4")
  HDRTOA(125, "fire", "fire")
  HDRTOA(126, "crtp", "Combat Radio Transport Protocol")
  HDRTOA(127, "crudp", "Combat Radio User Datagram")
  HDRTOA(128, "sscopmce", "sscopmce")
  HDRTOA(129, "iplt", "iplt")
  HDRTOA(130, "sps", "Secure Packet Shield")
  HDRTOA(131, "pipe", "Private IP Encapsulation within IP")
  HDRTOA(132, "sctp", "Stream Control Transmission Protocol")
  HDRTOA(133, "fc", "Fibre Channel")
  HDRTOA(134, "rsvp-e2e-ignore", "rsvp-e2e-ignore")
  HDRTOA(135, "mobility-hdr", "Mobility Header")
  HDRTOA(136, "udplite", "UDP-Lite [RFC3828]")
  HDRTOA(137, "mpls-in-ip", "MPLS-in-IP [RFC4023]")
  HDRTOA(138, "manet", "MANET Protocols [RFC5498]")
  HDRTOA(139, "hip", "Host Identity Protocol")
  HDRTOA(140, "shim6", "Shim6 Protocol [RFC5533]")
  HDRTOA(141, "wesp", "Wrapped Encapsulating Security Payload")
  HDRTOA(142, "rohc", "Robust Header Compression")
  HDRTOA(143, "ethernet", "RFC 8986 Ethernet next-header")
  HDRTOA(144, "aggfrag", "AGGFRAG encapsulation payload for ESP [draft-ietf-ipsecme-iptfs-18]")
  HDRTOA(253, "experimental1", "Use for experimentation and testing")
  HDRTOA(254, "experimental2", "Use for experimentation and testing")
  default:
    strncpy(buf, acronym ? "unknown" : "Unknown protocol", 128);	\
    break;
  }
  return buf;
#undef HDRTOA
}

