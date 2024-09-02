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

#include <ncsnet/route.h>

int route_get(route_t *r, route_entry *entry)
{
  struct     nlmsghdr *nmsg;
  struct     rtmsg *rmsg;
  struct     rtattr *rta;
  struct     sockaddr_nl snl;
  struct     iovec iov;
  struct     msghdr msg;
  u8         buf[512];
  int        i, af, alen;
  static int seq;

  switch (entry->route_dst.type) {
  case ADDR_TYPE_IP:
    af=AF_INET;
    alen=IP4_ADDR_LEN;
    break;
  case ADDR_TYPE_IP6:
    af=AF_INET6;
    alen=IP6_ADDR_LEN;
    break;
  default:
    errno=EINVAL;
    return -1;
  }
  memset(buf, 0, sizeof(buf));

  nmsg=(struct nlmsghdr*)buf;
  nmsg->nlmsg_len=NLMSG_LENGTH(sizeof(*nmsg))+RTA_LENGTH(alen);
  nmsg->nlmsg_flags=NLM_F_REQUEST;
  nmsg->nlmsg_type=RTM_GETROUTE;
  nmsg->nlmsg_seq=++seq;

  rmsg=(struct rtmsg*)(nmsg+1);
  rmsg->rtm_family=af;
  rmsg->rtm_dst_len=entry->route_dst.bits;

  rta=RTM_RTA(rmsg);
  rta->rta_type=RTA_DST;
  rta->rta_len=RTA_LENGTH(alen);

  /* XXX - gross hack for default route */
  if (af==AF_INET&&ip4t_u32(&entry->route_dst.addr_ip4)==IP4_ADDR_ANY) {
    i=htonl(0x60060606);
    memcpy(RTA_DATA(rta), &i, alen);
  }
  else
    memcpy(RTA_DATA(rta), entry->route_dst.addr_data8, alen);

  memset(&snl, 0, sizeof(snl));
  snl.nl_family=AF_NETLINK;

  iov.iov_base=nmsg;
  iov.iov_len=nmsg->nlmsg_len;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name=&snl;
  msg.msg_namelen=sizeof(snl);
  msg.msg_iov=&iov;
  msg.msg_iovlen=1;

  if (sendmsg(r->nlfd, &msg, 0)<0)
    return -1;

  iov.iov_base=buf;
  iov.iov_len=sizeof(buf);

  if ((i=recvmsg(r->nlfd, &msg, 0))<=0)
    return -1;

  if (nmsg->nlmsg_len<(int)sizeof(*nmsg)||nmsg->nlmsg_len>i||nmsg->nlmsg_seq!=seq) {
    errno=-EINVAL;
    return -1;
  }
  if (nmsg->nlmsg_type==NLMSG_ERROR)
    return -1;

  i-=NLMSG_LENGTH(sizeof(*nmsg));

  while (RTA_OK(rta, i)) {
    if (rta->rta_type==RTA_GATEWAY) {
      entry->route_gw.type=entry->route_dst.type;
      memcpy(entry->route_gw.addr_data8, RTA_DATA(rta), alen);
      entry->route_gw.bits=alen*8;
      return 0;
    }
    rta=RTA_NEXT(rta, i);
  }

  errno=-ESRCH;
  return -1;
}
