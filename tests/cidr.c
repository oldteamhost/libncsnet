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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../ncsnet/cidr.h"

#define DWID 9

#define OCTET_BIN(oct)				\
  {						\
    memset(boct, 0, 9);				\
    for(obi = 7 ; obi>=0 ; obi--)		\
      if( ((oct >> obi) & 1) == 1)		\
	boct[7-obi] = '1';			\
      else					\
	boct[7-obi] = '0';			\
  }

#define SHOWBIN(arr, pname)				\
  {							\
  printf("%*s:", DWID, "Bin" pname);			\
  if(proto==CIDR_IPV4) {				\
    for(i=12 ; i<=15 ; i++){				\
      OCTET_BIN(arr[i])					\
      printf(" %s", boct);				\
    }							\
      							\
      printf("\n%*s ", DWID, "");			\
      for(i=12 ; i<=15 ; i++)				\
	printf(" %5d%3s", arr[i], "");			\
      printf("\n");					\
    }							\
    else if(proto==CIDR_IPV6){				\
	for(i=0 ; i<=3 ; i++)				\
	  {						\
	    for(j=i*4 ; j<=(i*4)+3 ; j++)		\
	      {						\
		OCTET_BIN(arr[j])			\
		  printf(" %s", boct);			\
	      }						\
							\
	    printf("\n%*s ", DWID, "");			\
	    for(j=i*4 ; j<=i*4+3 ; j++)			\
	      printf("    %.2x   ", arr[j]);		\
	    if(i<3)					\
	      printf("\n%*s ", DWID, "");		\
	    else					\
	      printf("\n");				\
	  }						\
      }							\
  }

char *pname;
void usage(void);

int main(int argc, char *argv[])
{
  cidr_t *addr, *addr2, *addr3, **kids;
  char *astr, *astr2;
  char boct[9];
  int obi;
  int i, j;
  const char *cstr;
  int goch;
  short proto;
  short showbin, showss;
  uint8_t *bits;

  pname = *argv;
  showbin = showss = 0;

  while((goch=getopt(argc, argv, "bs"))!=-1) {
    switch((char)goch) {
    case 'b':
      showbin = 1;
      break;
    case 's':
      showss = 1;
      break;
    default:
      printf("Unknown argument: '%c'\n", goch);
      usage();
    }
  }

  argc -= optind;
  argv += optind;

  if(argc==0)
    usage();

  while(*argv!=NULL) {
    astr = NULL;
    addr = cidr_from_str(*argv);
    if(addr ==NULL)
      printf("***> ERROR: Couldn't parse address '%s'.\n\n", *argv);
    else {
      proto = cidr_get_proto(addr);
      astr = cidr_to_str(addr, CIDR_ONLYADDR);
      printf("%*s: %s\n", DWID, "Address", astr);
      free(astr);
      
      if(proto==CIDR_IPV6 && cidr_is_v4mapped(addr)==0) {
	  astr = cidr_to_str(addr,
			     CIDR_ONLYADDR | CIDR_FORCEV4 | CIDR_USEV6);
	  printf("%*s: %s\n", DWID, "v4-mapped", astr);
	  free(astr);
      }
      
      if(proto==CIDR_IPV6) {
	astr = cidr_to_str(addr,
			   CIDR_VERBOSE | CIDR_NOCOMPACT | CIDR_ONLYADDR);
	printf("%*s: %s\n", DWID, "Expanded", astr);
	free(astr);
      }
      
      
      astr = cidr_to_str(addr, CIDR_ONLYPFLEN);
      astr2 = cidr_to_str(addr, CIDR_ONLYPFLEN | CIDR_NETMASK);
      printf("%*s: %s (/%s)\n", DWID, "Netmask", astr2, astr);
      free(astr);
      free(astr2);
      
      
      if(showbin==1) {
	bits = cidr_get_addr(addr);
	SHOWBIN(bits, "Addr")
	  free(bits);
	bits = cidr_get_mask(addr);
	SHOWBIN(bits, "Mask")
	  free(bits);
      }
      
      
      astr = cidr_to_str(addr,
			 CIDR_ONLYPFLEN | CIDR_NETMASK | CIDR_WILDCARD);
      printf("%*s: %s\n", DWID, "Wildcard", astr);
      free(astr);
      
      
      /* Network and broadcast */
      addr2 = cidr_addr_network(addr);
      astr = cidr_to_str(addr2, CIDR_NOFLAGS);
      printf("%*s: %s\n", DWID, "Network", astr);
      free(astr);
      cidr_free(addr2);
      
      addr2 = cidr_addr_broadcast(addr);
      astr = cidr_to_str(addr2, CIDR_ONLYADDR);
      printf("%*s: %s\n", DWID, "Broadcast", astr);
      free(astr);
      cidr_free(addr2);
      
      
      /* Range of hosts */
      addr2 = cidr_addr_hostmin(addr);
      astr = cidr_to_str(addr2, CIDR_ONLYADDR);
      addr3 = cidr_addr_hostmax(addr);
      astr2 = cidr_to_str(addr3, CIDR_ONLYADDR);
      printf("%*s: %s - %s\n", DWID, "Hosts", astr, astr2);
      free(astr);
      free(astr2);
      cidr_free(addr2);
      cidr_free(addr3);
      
      
      cstr = cidr_numhost(addr);
      printf("%*s: %s\n", DWID, "NumHosts", cstr);
      
      if(showss==1) {
	addr2 = cidr_net_supernet(addr);
	if(addr2!=NULL) {
	  astr = cidr_to_str(addr2, CIDR_NOFLAGS);
	  printf("%*s: %s\n", DWID, "Supernet", astr);
	  free(astr);
	  cidr_free(addr2);
	}
	else
	  printf("%*s: (none)\n", DWID, "Supernet");
	
	kids = cidr_net_subnets(addr);
	if(kids!=NULL) {
	  astr = cidr_to_str(kids[0], CIDR_NOFLAGS);
	  astr2 = cidr_to_str(kids[1], CIDR_NOFLAGS);
	  printf("%*s: %s\n%*s  %s\n", DWID, "Subnets", astr,
		 DWID, "", astr2);
	  free(astr);
	  free(astr2);
	  cidr_free(kids[0]);
	  cidr_free(kids[1]);
	  free(kids);
	}
	else
	  printf("%*s: (none)\n", DWID, "Subnets");
      }
      
      cidr_free(addr);
      printf("\n");
    }
    
    argv++;
  }
  
  exit(0);
}


void usage(void)
{
  printf("Usage: %s [-bs] address [...]\n"
	 "       -b  Show binary expansions\n"
	 "       -s  Show super and subnets\n"
	 , pname);
  exit(1);
}
