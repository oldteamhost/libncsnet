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

#include <ncsnet/intf.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#define PROC_DEV_FILE "/proc/net/dev"
extern int _intf_get_noalias(intf_t *intf, intf_entry *entry);
extern int _intf_get_aliases(intf_t *intf, intf_entry *entry);

static int intf_get_drv_info(intf_t *intf, intf_entry *entry)
{
  struct ifreq ifr;
  struct ethtool_drvinfo drvinfo;
  memset(&ifr, 0, sizeof(ifr));
  memset(&drvinfo, 0, sizeof(drvinfo));

  drvinfo.cmd=ETHTOOL_GDRVINFO;
  ifr.ifr_data=(caddr_t)&drvinfo;
  strncpy(ifr.ifr_name, entry->intf_name, IFNAMSIZ);

  if (ioctl(intf->fd, SIOCETHTOOL, &ifr))
    return -1;

  strncpy(entry->driver_name, drvinfo.driver, INTF_VERS_LEN);
  strncpy(entry->driver_vers, drvinfo.version, INTF_VERS_LEN);
  strncpy(entry->firmware_vers, drvinfo.fw_version, INTF_VERS_LEN);

  return 0;
}

int intf_loop(intf_t *i, intf_handler callback, void *arg)
{
  char *p, buf[BUFSIZ], ebuf[BUFSIZ];
  intf_entry *entry;
  FILE *fp;
  int ret;

  entry=(intf_entry*)ebuf;

  if (!(fp=fopen(PROC_DEV_FILE, "r")))
    return -1;

  i->ifc.ifc_buf=(caddr_t)i->ifcbuf;
  i->ifc.ifc_len=sizeof(i->ifcbuf);

  if (ioctl(i->fd, SIOCGIFCONF, &i->ifc)<0) {
    fclose(fp);
    return -1;
  }

  ret=0;
  while (fgets(buf, sizeof(buf), fp)) {
    if (!(p = strchr(buf, ':')))
      continue;
    *p = '\0';
    for (p = buf; *p == ' '; p++);

    memset(ebuf, 0, sizeof(ebuf));
    _strlcpy(entry->intf_name, p, sizeof(entry->intf_name));
    _strlcpy(entry->os_intf_name, p, sizeof(entry->os_intf_name));
    _strlcpy(entry->pcap_intf_name, p, sizeof(entry->pcap_intf_name));
    intf_get_drv_info(i, entry);
    entry->intf_len=sizeof(ebuf);

    if (_intf_get_noalias(i, entry)<0) {
      ret=-1;
      break;
    }
    if (_intf_get_aliases(i, entry)<0) {
      ret=-1;
      break;
    }
    if ((ret=(*callback)(entry, arg))!=0)
      break;
  }
  if (ferror(fp))
    ret =-1;

  fclose(fp);
  return ret;
}
