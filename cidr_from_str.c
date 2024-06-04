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

cidr_t *cidr_from_str(const char *addr)
{
  size_t _alen;
  int alen;
  cidr_t *toret, *ctmp;
  const char *pfx, *buf;
  char *buf2;   int i, j;
  int pflen;
  unsigned long octet;
  int nocts, eocts;
  short foundpf, foundmask, nsect;

  if(!addr || (_alen=strlen(addr)) < 1)
    return NULL;
  if(_alen > 1 << 16)
    return NULL;
  
  alen = (int)_alen;
  buf = addr + strspn(addr, "0123456789abcdefABCDEFxX.:/in-rpt");
  if(*buf!='\0')
    return NULL;
  
  toret = cidr_alloc();
  if (!toret)
    return NULL; 

  buf = NULL;
  if(strcasecmp(addr+alen-8, ".ip6.int")==0) {
    toret->proto = CIDR_IPV6;
    buf = addr+alen-8;
  }
  
  if(buf || strcasecmp(addr+alen-5, ".arpa")==0) {
    if(!buf) {
      if(strncasecmp(addr+alen-9, ".ip6", 3)==0) {
	toret->proto = CIDR_IPV6;
	buf = addr+alen-9;
      }
      else if(strncasecmp(addr+alen-13, ".in-addr", 7)==0) {
	toret->proto = CIDR_IPV4;
	buf = addr+alen-13;
      }
      else {
	cidr_free(toret);
	return(NULL);
      }
    }
    buf--;
    if(toret->proto == CIDR_IPV4) {
      for(i=11 ; i<=14 ; /* */)
	{
	  if(buf<addr)
	    break;
	  
	  while(isdigit(*buf) && buf>=addr)
	    buf--;
	  
	  /*
	   * Save that number (++i here to show that this octet is
	   * now set.
	       */
	      octet = strtoul(buf+1, NULL, 10);
	      if(octet > (unsigned long)0xff)
		{
		  		  cidr_free(toret);
		  return(NULL);
		}
	      toret->addr[++i] = octet;


	      /*
	       * Back up a step to get before the '.', and process the
	       * next [previous] octet.  If we were at the beginning of
	       * the string already, the test at the top of the loop
	       * will drop us out.
	       */
	      buf--;
	    }

	  	  if(buf>=addr)
	    {
	      cidr_free(toret);
	      return(NULL);
	    }

	  /*
	   * Now, what about the mask?  We set the netmask bits to
	   * describe how much information we've actually gotten, if we
	   * didn't get all 4 octets.  Because of the way .in-addr.arpa
	   * works, the mask can only fall on an octet boundary, so we
	   * don't need too many fancy tricks.  'i' is still set from
	   * the above loop to whatever the last octet we filled in is,
	   * so we don't even have to special case anything.
	   */
	  for(j=0 ; j<=i ; j++)
	    toret->mask[j] = 0xff;

	  	}
      else if(toret->proto == CIDR_IPV6)
	{
	  /*
	   * This processing happens somewhat similarly to IPV4 above,
	   * the format is simplier, and we need to be a little
	   * sneakier about the mask, since it can fall on a half-octet
	   * boundary with .ip6.arpa format.
	   */
	  for(i=0 ; i<=15 ; i++)
	    {
	      	      if(buf<addr)
		break;

	      	      if(!isxdigit(*buf))
		{
		  		  cidr_free(toret);
		  return(NULL);
		}

	      	      octet = strtoul(buf, NULL, 16);
	      if(octet > (unsigned long)0xff)
		{
		  		  cidr_free(toret);
		  return(NULL);
		}
	      toret->addr[i] = octet << 4;
	      toret->mask[i] = 0xf0;

	      	      if(buf==addr)
		{
		  		  buf--;
		  break;
		}

	      	      if(*--buf != '.')
		{
		  		  cidr_free(toret);
		  return(NULL);
		}

	      	      if(!isxdigit(*--buf))
		{
		  		  cidr_free(toret);
		  return(NULL);
		}

	      	      octet = strtoul(buf, NULL, 16);
	      if(octet > (unsigned long)0xff)
		{
		  		  cidr_free(toret);
		  return(NULL);
		}
	      toret->addr[i] |= octet & 0x0f;
	      toret->mask[i] |= 0x0f;


	      /*
	       * Step back and loop back around.  If that last step
	       * back moves us to before the beginning of the string,
	       * the condition at the top of the loop will drop us out.
	       */
	      while(*--buf=='.' && buf>=addr)
		/* nothing */;
	    }

	  	  if(buf>=addr)
	    {
	      cidr_free(toret);
	      return(NULL);
	    }

	  	}
      else
	{
	  	  cidr_free(toret);
	  return(NULL);
	}

            return(toret);

          }
  buf=NULL; 

  /*
   * It's not a PTR form, so find the '/' prefix marker if we can.  We
   * support both prefix length and netmasks after the /, so flag if we
   * find a mask.
   */
  foundpf=foundmask=0;
  for(i=alen-1 ; i>=0 ; i--)
    {
            if(addr[i]=='.' || addr[i]==':')
	foundmask=1;

            if(addr[i]=='/')
	{
	  foundpf=1;
	  break;
	}
    }

  if(foundpf==0)
    {
            foundmask=0;

      /*
       * pfx is only used if foundpf==1, but set it to NULL here to
       * quiet gcc down.
       */
      pfx=NULL;
    }
  else
    {
            pfx = addr+i;

      if(foundmask==0)
	{
	  /*
	   * If we didn't find a netmask, it may be that it's one of
	   * the v4 forms without dots.  Technically, it COULD be
	   * expressed as a single (32-bit) number that happens to be
	   * between 0 and 32 inclusive, so there's no way to be
	   * ABSOLUTELY sure when we have a prefix length and not a
	   * netmask.  But, that would be a non-contiguous netmask,
	   * which we don't attempt to support, so we can probably
	   * safely ignore that case.  So try a few things...
	   */
	  	  if(pfx[1]=='0' && tolower(pfx[2])=='x')
	    foundmask=1; 	  else if(pfx[1]=='0')
	    foundmask=1; 	  else if(isdigit(pfx[1]))
	    {
	      /*
	       * If we get here, it looks like a decimal number, and we
	       * know there aren't any periods or colons in it, so if
	       * it's valid, it can ONLY be a single 32-bit decimal
	       * spanning the whole 4-byte v4 address range.  If that's
	       * true, it's GOTTA be a valid number, it's GOTTA reach
	       * to the end of the strong, and it's GOTTA be at least
	       * 2**31 and less than 2**32.
	       */
	      octet = strtoul(pfx+1, &buf2, 10);
	      if(*buf2=='\0' && octet >= (unsigned long)(1<<31)
		 && octet <= (unsigned long)0xffffffff)
		foundmask=1; 
	      octet=0; buf2=NULL; 	    }
	}
    }
  i=0; 

  /*
   * Now, let's figure out what kind of address this is.  A v6 address
   * will contain a : within the first 5 characters ('0000:'), a v4
   * address will have a . within the first 4 ('123.'), UNLESS it's
   * just a single number (in hex, octal, or decimal).  Anything else
   * isn't an address we know anything about, so fail.
   */
  if((buf = strchr(addr, ':'))!=NULL && (buf-addr)<=5)
    toret->proto = CIDR_IPV6;
  else if((buf = strchr(addr, '.'))!=NULL && (buf-addr)<=4)
    toret->proto = CIDR_IPV4;
  else
    {
      /*
       * Special v4 forms
       */
      if(*addr=='0' && tolower(*(addr+1))=='x')
	{
	  	  buf = (addr+2) + strspn(addr+2, "0123456789abcdefABCDEF");
	  if(*buf=='\0' || *buf=='/')
	    toret->proto = CIDR_IPV4; 	}
      else if(*addr=='0')
	{
	  	  	  buf = (addr+1) + strspn(addr+1, "01234567");
	  if(*buf=='\0' || *buf=='/')
	    toret->proto = CIDR_IPV4; 	}
      else
	{
	  	  buf = (addr) + strspn(addr, "0123456789");
	  if(*buf=='\0' || *buf=='/')
	    toret->proto = CIDR_IPV4; 	}

            if(toret->proto == 0)
	{
	  	  cidr_free(toret);
	  return(NULL);
	}
    }
  buf=NULL; 

  /*
   * So now we know what sort of address it is, we can go ahead and
   * have a parser for either.
   */
  if(toret->proto==CIDR_IPV4)
    {
      /*
       * Parse a v4 address.  Now, we're being a little tricksy here,
       * and parsing it from the end instead of from the front.
       */

      /*
       * First, find out how many bits we have.  We need to have 4 or
       * less...
       */
      buf = strchr(addr, '.');
            for(nsect=0 ; buf!=NULL && (pfx!=NULL?buf<pfx:1) ; buf=strchr(buf, '.'))
	{
	  nsect++; 	  buf++; 	  if(nsect>3)
	    {
	      	      cidr_free(toret);
	      return(NULL);
	    }
	}
      buf=NULL;       nsect++; 
      /*
       * First, initialize this so we can skip building the bits if we
       * don't have to.
       */
      pflen=-1;

      /*
       * Initialize the first 12 octets of the address/mask to look
       * like a v6-mapped address.  This is the correct info for those
       * octets to have if/when we decide to use this v4 address as a
       * v6 one.
       */
      for(i=0 ; i<=9 ; i++)
	toret->addr[i] = 0;
      for(i=10 ; i<=11 ; i++)
	toret->addr[i] = 0xff;
      for(i=0 ; i<=11 ; i++)
	toret->mask[i] = 0xff;

      /*
       * Handle the prefix/netmask.  If it's not set at all, slam it to
       * the maximum, and put us at the end of the string to start out.
       * Ditto if the '/' is the end of the string.
       */
      if(foundpf==0)
	{
	  pflen=32;
	  i=alen-1;
	}
      else if(foundpf==1 && *(pfx+1)=='\0')
	{
	  pflen=32;
	  i=(int)(pfx-addr-1);
	}

      /*
       * Or, if we found it, and it's a NETMASK, we need to parse it
       * just like an address.  So, cheat a little and call ourself
       * recursively, and then just count the bits in our returned
       * address for the pflen.
       */
      if(foundpf==1 && foundmask==1 && pflen==-1)
	{
	  ctmp = cidr_from_str(pfx+1);
	  if(ctmp==NULL)
	    {
	      	      cidr_free(toret);
	      return(NULL); 	    }
	  	  for(i=0 ; i<=11 ; i++)
	    ctmp->mask[i] = 0;
	  for(i=12 ; i<=15 ; i++)
	    ctmp->mask[i] = ctmp->addr[i];

	  	  pflen = cidr_get_pflen(ctmp);
	  cidr_free(ctmp);
	  if(pflen==-1)
	    {
	      	      cidr_free(toret);
	      return(NULL); 	    }

	  	  i = (int)(pfx-addr-1);
	}

      /*
       * Finally, if we did find it and it's a normal prefix length,
       * just pull it it, parse it out, and set ourselves to the first
       * character before the / for the address reading
       */
      if(foundpf==1 && foundmask==0 && pflen==-1)
	{
	  pflen = (int)strtol(pfx+1, NULL, 10);
	  i = (int)(pfx-addr-1);
	}


      /*
       * If pflen is set, we need to turn it into a mask for the bits.
       * XXX pflen actually should ALWAYS be set, so we might not need
       * to make this conditional at all...
       */
      if(pflen>0)
	{
	  	  if(pflen<0 || pflen>32)
	    {
	      	      cidr_free(toret);
	      return(NULL);
	    }

	  /*
	   * Now pflen is in the 0...32 range and thus good.  Set it in
	   * the structure.  Note that memset zero'd the whole thing to
	   * start.  We ignore mask[<12] with v4 addresses normally,
	   * but they're already set to all-1 anyway, since if we ever
	   * DO care about them, that's the most appropriate thing for
	   * them to be.
	   *
	   * This is a horribly grody set of macros.  I'm only using
	   * them here to test them out before using them in the v6
	   * section, where I'll need them more due to the sheer number
	   * of clauses I'll have to get written.  Here's the straight
	   * code I had written that the macro should be writing for me
	   * now:
	   *
	   * if(pflen>24)
	   *   for(j=24 ; j<pflen ; j++)
	   *     toret->mask[15] |= 1<<(31-j);
	   * if(pflen>16)
	   *   for(j=16 ; j<pflen ; j++)
	   *     toret->mask[14] |= 1<<(23-j);
	   * if(pflen>8)
	   *   for(j=8 ; j<pflen ; j++)
	   *     toret->mask[13] |= 1<<(15-j);
	   * if(pflen>0)
	   *   for(j=0 ; j<pflen ; j++)
	   *     toret->mask[12] |= 1<<(7-j);
	   */
#define UMIN(x,y) ((x)<(y)?(x):(y))
#define MASKNUM(x) (24-((15-x)*8))
#define WRMASKSET(x)							\
	  if(pflen>MASKNUM(x))						\
	    for(j=MASKNUM(x) ; j<UMIN(pflen,MASKNUM(x)+8) ; j++)	\
	      toret->mask[x] |= 1<<(MASKNUM(x)+7-j);

	  WRMASKSET(15);
	  WRMASKSET(14);
	  WRMASKSET(13);
	  WRMASKSET(12);

#undef WRMASKET
#undef MASKNUM
#undef UMIN
	} 

      /*
       * Now we have 4 octets to grab.  If any of 'em fail, or are
       * outside the 0...255 range, bomb.
       */
      nocts = 0;

            while(i>0 && addr[i]=='/')
	i--;

      for( /* i */ ; i>=0 ; i--)
	{
	  /*
	   * As long as it's still a number or an 'x' (as in '0x'),
	   * keep backing up.  Could be hex, so don't just use
	   * isdigit().
	   */
	  if((isxdigit(addr[i]) || tolower(addr[i])=='x') && i>0)
	    continue;

	  /*
	   * It's no longer a number.  So, grab the number we just
	   * moved before.
	   */
	  	  if(i==0)
	    i--;
	  	  if(addr[i+1]=='0' && tolower(addr[i+2])=='x')
	    octet = strtoul(addr+i+1, &buf2, 16);
	  else if(addr[i+1] == '0')
	    octet = strtoul(addr+i+1, &buf2, 8);
	  else
	    octet = strtoul(addr+i+1, &buf2, 10);

	  	  if(!(*buf2=='.' || *buf2=='/' || *buf2=='\0'))
	    {
	      cidr_free(toret);
	      return(NULL);
	    }
	  buf2=NULL; 
	  /*
	   * Now, because of the way compressed IPv4 addresses work,
	   * this number CAN be greater than 255, IF it's the last bit
	   * in the address (the first bit we parse), in which case it
	   * must be no bigger than needed to fill the unaccounted-for
	   * 'slots' in the address.
	   *
	   * See
	   * <http://www.opengroup.org/onlinepubs/007908799/xns/inet_addr.html>
	   * for details.
	   */
	  if( (nocts!=0 && octet>255)
	      || (nocts==0 && octet>(0xffffffff >> (8*(nsect-1)))) )
	    {
	      cidr_free(toret);
	      return(NULL);
	    }

	  	  toret->addr[15-nocts++] = octet & 0xff;

	  /*
	   * If this is the 'last' piece of the address (the first we
	   * process), and there are fewer than 4 pieces total, we need
	   * to extend it out into additional fields.  See above
	   * reference.
	   */
	  if(nocts==1)
	    {
	      if(nsect<=3)
		toret->addr[15-nocts++] = (octet >> 8) & 0xff;
	      if(nsect<=2)
		toret->addr[15-nocts++] = (octet >> 16) & 0xff;
	      if(nsect==1)
		toret->addr[15-nocts++] = (octet >> 24) & 0xff;
	    }

	  /*
	   * If we've got 4 of 'em, we're actually done.  We got the
	   * prefix above, so just return direct from here.
	   */
	  if(nocts==4)
	    return(toret);
	}

      /*
       * If we get here, it failed to get all 4.  That shouldn't
       * happen, since we catch proper abbreviated forms above.
       */
      cidr_free(toret);
      return(NULL);
    }
  else if(toret->proto==CIDR_IPV6)
    {
		  
      /*
       * Parse a v6 address.  Like the v4, we start from the end and
       * parse backward.  However, to handle compressed form, if we hit
       * a ::, we drop off and start parsing from the beginning,
       * because at the end we'll then have a hole that is what the ::
       * is supposed to contain, which is already automagically 0 from
       * the memset() we did earlier.  Neat!
       *
       * Initialize the prefix length
       */
      pflen=-1;

            if(foundpf==0)
	{
	  pflen = 128;
	  	  i=alen-1;
	}
      else if(foundpf==1 && *(pfx+1)=='\0')
	{
	  pflen = 128;
	  i=(int)(pfx-addr-1);
	}

      /*
       * If we got a netmask, rather than a prefix length, parse it and
       * count the bits, like we did for v4.
       */
      if(foundpf==1 && foundmask==1 && pflen==-1)
	{
	  ctmp = cidr_from_str(pfx+1);
	  if(ctmp==NULL)
	    {
	      	      cidr_free(toret);
	      return(NULL); 	    }
	  	  for(i=0 ; i<=15 ; i++)
	    ctmp->mask[i] = ctmp->addr[i];

	  	  pflen = cidr_get_pflen(ctmp);
	  cidr_free(ctmp);
	  if(pflen==-1)
	    {
	      	      cidr_free(toret);
	      return(NULL); 	    }

	  	  i = (int)(pfx-addr-1);
	}

            if(foundpf==1 && foundmask==0 && pflen==-1)
	{
	  pflen = (int)strtol(pfx+1, NULL, 10);
	  i = (int)(pfx-addr-1);
	}


      /*
       * Now, if we have a pflen, turn it into a mask.
       * XXX pflen actually should ALWAYS be set, so we might not need
       * to make this conditional at all...
       */
      if(pflen>0)
	{
	  	  if(pflen<0 || pflen>128)
	    {
	      	      cidr_free(toret);
	      return(NULL);
	    }

	  /*
	   * Now save the pflen.  See comments on the similar code up in
	   * the v4 section about the macros.
	   */
#define UMIN(x,y) ((x)<(y)?(x):(y))
#define MASKNUM(x) (120-((15-x)*8))
#define WRMASKSET(x)							\
	  if(pflen>MASKNUM(x))						\
	    for(j=MASKNUM(x) ; j<UMIN(pflen,MASKNUM(x)+8) ; j++)	\
	      toret->mask[x] |= 1<<(MASKNUM(x)+7-j);

	  WRMASKSET(15);
	  WRMASKSET(14);
	  WRMASKSET(13);
	  WRMASKSET(12);
	  WRMASKSET(11);
	  WRMASKSET(10);
	  WRMASKSET(9);
	  WRMASKSET(8);
	  WRMASKSET(7);
	  WRMASKSET(6);
	  WRMASKSET(5);
	  WRMASKSET(4);
	  WRMASKSET(3);
	  WRMASKSET(2);
	  WRMASKSET(1);
	  WRMASKSET(0);

#undef WRMASKET
#undef MASKNUM
#undef UMIN
	}


      /*
       * Now we have 16 octets to grab.  If any of 'em fail, or are
       * outside the 0...0xff range, bomb.  However, we MAY have a
       * v4-ish form, whether it's a formal v4 mapped/compat address,
       * or just a v4 address written in a v6 block.  So, look for
       * .-separated octets, but there better be exactly 4 of them
       * before we hit a :.
       */
      nocts = 0;

            while(i>0 && addr[i]=='/')
	i--;

      for( /* i */ ; i>=0 ; i--)
	{
	  /*
	   * First, check the . cases, and handle them all in one
	   * place.  These can only happen at the beginning, when we
	   * have no octets yet, and if it happens at all, we need to
	   * have 4 of them.
	   */
	  if(nocts==0 && addr[i]=='.')
	    {
	      i++; 
	      for( /* i */ ; i>0 && nocts<4 ; i--)
		{
		  		  if(addr[i]==':' && nocts<3)
		    {
		      cidr_free(toret);
		      return(NULL);
		    }

		  		  if(addr[i]!='.' && addr[i]!=':')
		    continue;

		  		  octet = strtoul(addr+i+1, NULL, 10);
		  		  if(octet>255)
		    {
		      cidr_free(toret);
		      return(NULL);
		    }

		  		  toret->addr[15-nocts] = octet & 0xff;
		  nocts++;

		  		}

	      /*
	       * At this point, 4 dotted-decimal octets should be
	       * consumed.  i has gone back one step past the : before
	       * the decimal, so addr[i+1] should be the ':' that
	       * preceeds them.  Verify.
	       */
	      if(nocts!=4 || addr[i+1]!=':')
		{
		  cidr_free(toret);
		  return(NULL);
		}
	    }

	  /*
	   * Now we've either gotten 4 octets filled in from
	   * dotted-decimal stuff, or we've filled in nothing and have
	   * no dotted decimal.
	   */


	  	  if(addr[i]!=':' && i>0)
	    continue;

	  	  if(addr[i]==':' && addr[i+1]==':')
	    {
	      /*
	       * If i is 0, we're already at the beginning of the
	       * string, so we can just return; we've already filled in
	       * everything but the leading 0's, which are already
	       * zero-filled from the memory
	       */
	      if(i==0)
		return(toret);

	      	      break;
	    }

	  	  if(!isxdigit(addr[i]) && addr[i]!=':' && i>0)
	    {
	      cidr_free(toret);
	      return(NULL);
	    }

	  /*
	   * It's no longer a number.  So, grab the number we just
	   * moved before.
	   */
	  	  if(i==0)
	    i--;
	  octet = strtoul(addr+i+1, &buf2, 16);
	  if(*buf2!=':' && *buf2!='/' && *buf2!='\0')
	    {
	      	      cidr_free(toret);
	      return(NULL);
	    }
	  buf2=NULL;

	  	  if(octet>0xffff)
	    {
	      cidr_free(toret);
	      return(NULL);
	    }

	  	  toret->addr[15-nocts] = octet & 0xff;
	  nocts++;
	  toret->addr[15-nocts] = (octet>>8) & 0xff;
	  nocts++;

	  	  if(nocts==16)
	    return(toret);
	}

      /*
       * Now, if i is >=0 and we've got two :'s, jump around to the
       * front of the string and start parsing inward.
       */
      if(i>=0 && addr[i]==':' && addr[i+1]==':')
	{
	  	  eocts = nocts;

	  	  j=i;

	  	  i=0;
	  while(i<j)
	    {
	      /*
	       * The first char better be a number.  If it's not, bail
	       * (a leading '::' was already handled in the loop above
	       * by just returning).
	       */
	      if(i==0 && !isxdigit(addr[i]))
		{
		  cidr_free(toret);
		  return(NULL);
		}

	      /*
	       * We should be pointing at the beginning of a digit
	       * string now.  Translate it into an octet.
	       */
	      octet = strtoul(addr+i, &buf2, 16);
	      if(*buf2!=':' && *buf2!='/' && *buf2!='\0')
		{
		  		  cidr_free(toret);
		  return(NULL);
		}
	      buf2=NULL;

	      	      if(octet>0xffff)
		{
		  cidr_free(toret);
		  return(NULL);
		}

	      	      toret->addr[nocts-eocts] = (octet>>8) & 0xff;
	      nocts++;
	      toret->addr[nocts-eocts] = octet & 0xff;
	      nocts++;

	      /*
	       * Discussion: If we're in this code block, it's because
	       * we hit a ::-compression while parsing from the end
	       * backward.  So, if we hit 15 octets here, it's an
	       * error, because with the at-least-2 that were minimized,
	       * that makes 17 total, which is too many.  So, error
	       * out.
	       */
	      if(nocts==15)
		{
		  cidr_free(toret);
		  return(NULL);
		}

	      	      while(isxdigit(addr[i]) && i<j)
		i++;

	      /*
	       * If i==j, we're back where we started.  So we've filled
	       * in all the leading stuff, and the struct is ready to
	       * return.
	       */
	      if(i==j)
		return(toret);

	      /*
	       * Else, there's more to come.  We better be pointing at
	       * a ':', else die.
	       */
	      if(addr[i]!=':')
		{
		  cidr_free(toret);
		  return(NULL);
		}

	      	      i++;

	      	      if(i==j)
		{
		  cidr_free(toret);
		  return(NULL);
		}

	      	    }
	}

            cidr_free(toret);
      return(NULL);
    }
  else
    {
            cidr_free(toret);
      return(NULL);
    }

  return(NULL);
}
