/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 * Copyright (c) 2005-2012, Matthew D. Fuller <fullermd@over-yonder.net>. All rights reserved.
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

#include "ncsnet/cidr.h"

char *cidr_to_str(const cidr_t *block, int flags)
{
  int i;
  int zst, zcur, zlen, zmax;
  short pflen;
  short lzer;
  char *toret;
  char tmpbuf[128];
  cidr_t *nmtmp;
  char *nmstr;
  int nmflags;
  u8 moct;
  u16 v6sect;
  
  if ((!block) || (block->proto==CIDR_NOPROTO))
    return NULL;
  if ((flags & CIDR_ONLYADDR) && (flags & CIDR_ONLYPFLEN))
    return NULL;
  toret = malloc(128);
  if(!toret)
    return NULL;

  memset(toret, 0, 128);
  if ((block->proto == CIDR_IPV4 && !(flags & CIDR_FORCEV6))
      || (flags & CIDR_FORCEV4)) {
    if (flags & CIDR_REVERSE) {
      sprintf(toret, "%d.%d.%d.%d.in-addr.arpa",
	      block->addr[15], block->addr[14],
	      block->addr[13], block->addr[12]);
      return toret;
    }
    if (!(flags & CIDR_ONLYPFLEN)) {
      if (flags & CIDR_USEV6) {
	if (flags & CIDR_NOCOMPACT) {
	  if (flags & CIDR_VERBOSE)
	    strcat(toret, "0000:0000:0000:0000:0000:");
	  else
	    strcat(toret, "0:0:0:0:0:");
	}
	else
	  strcat(toret, "::");
	if (flags & CIDR_USEV4COMPAT) {
	  if (flags & CIDR_NOCOMPACT) {
	      if(flags & CIDR_VERBOSE)
		strcat(toret, "0000:");
	      else
		strcat(toret, "0:");
	  }
	}
	else
	  strcat(toret, "ffff:");
      }
      for (i=12; i<=15; i++) {
	sprintf(tmpbuf, "%u", (block->addr)[i]);
	strcat(toret, tmpbuf);
	if (i < 15)
	  strcat(toret, ".");
      }
    }
    if (!(flags & CIDR_ONLYADDR)) {
      if (!(flags & CIDR_ONLYPFLEN))
	strcat(toret, "/");
      if (flags & CIDR_NETMASK) {
	for (i = 12; i <= 15; i++) {
	  moct = (block->mask)[i];
	  if(flags & CIDR_WILDCARD)
	    moct = ~(moct);
	  sprintf(tmpbuf, "%u", moct);
	  strcat(toret, tmpbuf);
	  if (i < 15)
	    strcat(toret, ".");
	}
      }
      else {
	pflen = cidr_get_pflen(block);
	if (pflen == -1) {
	  free(toret);
	  return NULL;
	}
	if (block->proto == CIDR_IPV6 && (flags & CIDR_FORCEV4))
	  pflen -= 96;
	sprintf(tmpbuf, "%u",
		(flags & CIDR_USEV6) ? pflen+96 : pflen);
	strcat(toret, tmpbuf);
      }
    }
  }
  
  else if ((block->proto==CIDR_IPV6 && !(flags & CIDR_FORCEV4))
	  || (flags & CIDR_FORCEV6)) {
    if (flags & CIDR_REVERSE) {
      sprintf(toret, "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
	      "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
	      "%x.%x.%x.%x.%x.ip6.arpa",
	      block->addr[15] & 0x0f, block->addr[15] >> 4,
	      block->addr[14] & 0x0f, block->addr[14] >> 4,
	      block->addr[13] & 0x0f, block->addr[13] >> 4,
	      block->addr[12] & 0x0f, block->addr[12] >> 4,
	      block->addr[11] & 0x0f, block->addr[11] >> 4,
	      block->addr[10] & 0x0f, block->addr[10] >> 4,
	      block->addr[9]  & 0x0f, block->addr[9]  >> 4,
	      block->addr[8]  & 0x0f, block->addr[8]  >> 4,
	      block->addr[7]  & 0x0f, block->addr[7]  >> 4,
	      block->addr[6]  & 0x0f, block->addr[6]  >> 4,
	      block->addr[5]  & 0x0f, block->addr[5]  >> 4,
	      block->addr[4]  & 0x0f, block->addr[4]  >> 4,
	      block->addr[3]  & 0x0f, block->addr[3]  >> 4,
	      block->addr[2]  & 0x0f, block->addr[2]  >> 4,
	      block->addr[1]  & 0x0f, block->addr[1]  >> 4,
	      block->addr[0]  & 0x0f, block->addr[0]  >> 4);
      return toret;
    }
    if (!(flags & CIDR_ONLYPFLEN)) {
      zst = zcur = -1;
      zlen = zmax = 0;
      for (i=0 ; i<=15 ; i+=2) {
	if (block->addr[i]==0 && block->addr[i+1]==0) {
	  if (zcur != -1)
	    zlen++;
	  else {
	    zcur = i;
	    zlen = 1;
	  }
	}
	else {
	  if (zcur!=-1) {
	    if (zlen > zmax) {
	      zst = zcur;
	      zmax = zlen;
	    }
	    zcur = -1;
	  }
	}
      }
      if (zcur != -1 && zlen > zmax) {
	zst = zcur;
	zmax = zlen;
      }
      lzer = 0;
      for (i=0; i<=15; i+=2) {
	if(i==zst && !(flags & CIDR_NOCOMPACT)) {
	  strcat(toret, "::");
	  i += (zmax*2)-2;
	  lzer = 1;
	  continue;
	}
	if (i!=0 && ((flags & CIDR_NOCOMPACT) || lzer==0))
	  strcat(toret, ":");
	lzer = 0;
	v6sect = 0;
	v6sect |= (block->addr)[i] << 8;
	v6sect |= (block->addr)[i+1];
	if(flags & CIDR_VERBOSE)
	  sprintf(tmpbuf, "%.4x", v6sect);
	else
	  sprintf(tmpbuf, "%x", v6sect);
	strcat(toret, tmpbuf);
      }
    }
    
    if (!(flags & CIDR_ONLYADDR)) {
      if (!(flags & CIDR_ONLYPFLEN))
	strcat(toret, "/");
      if(flags & CIDR_NETMASK) {
	nmtmp = cidr_alloc();
	if(!nmtmp) {
	  free(toret);
	  return NULL;
	}
	nmtmp->proto = block->proto;
	for(i=0 ; i<=15 ; i++)
	  if(flags & CIDR_WILDCARD)
	    nmtmp->addr[i] = ~(block->mask[i]);
	  else
	    nmtmp->addr[i] = block->mask[i];
	nmflags = flags;
	nmflags &= ~(CIDR_NETMASK) & ~(CIDR_ONLYPFLEN);
	nmflags |= CIDR_ONLYADDR;
	nmstr = cidr_to_str(nmtmp, nmflags);
	cidr_free(nmtmp);
	if (!nmstr) {
	  free(toret);
	  return NULL;
	}
	strcat(toret, nmstr);
	free(nmstr);
      }
      else {
	pflen = cidr_get_pflen(block);
	if (pflen == -1) {
	  free(toret);
	  return NULL;
	}
	if (block->proto==CIDR_IPV4 && (flags & CIDR_FORCEV6))
	  pflen += 96;
	
	sprintf(tmpbuf, "%u", pflen);
	strcat(toret, tmpbuf);
      }
    }
  }
  else {
    free(toret);
    return NULL;
  }
  return toret;
}
