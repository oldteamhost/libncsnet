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

#ifndef NCSUTILSHDR
#define NCSUTILSHDR

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>

#include "mt19937.h"
#include "eth.h"
#include "inet.h"

#include "sys/types.h"
#include "sys/nethdrs.h"
#include "../ncsnet-config.h"

#define CIDR  0
#define IPv4  1
#define RANGE 2
#define _URL_ 3
#define DNS   4
#define IPv6  5
#define OUTRAGEOUS_SPEED 5
#define FIERCE_SPEED     4
#define FAST_SPEED       3
#define BALANCED_SPEED   2
#define NOT_SPEED        1

#define IS_NULL_OR_EMPTY(str)			\
  ((str == NULL) || (*str == '\0'))

#define U64_SEED() ({				\
      struct timeval t;				\
      gettimeofday(&t, NULL);			\
      ((u64)t.tv_sec << 32) | t.tv_usec;	\
    })

#ifndef MIN
#  define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#  define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define TIMEVAL_SUBTRACT(a, b)						\
  (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)

#define DEFAULT_DICTIONARY						\
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

#define to_ms(nanos)  ((nanos) / 1000000)
#define to_ns(millis) ((millis) * 1000000LL)

__BEGIN_DECLS

int this_is(const char *node);
int getipv4(const char *node, char *res, u8 reslen);
struct timeval timevalns(long long ns);
int   check_root_perms(void);
void  delayy(int ms);
void  get_current_date(char* formatted_date, size_t max_length);
int   calculate_timeout(double rtt, int speed);
int   calculate_threads(int speed, int len);
int   calculate_ping_timeout(int speed);
char *get_active_interface_name(char* buffer, size_t len);
int   get_gateway_ip(char* buf, size_t len);
int   get_local_mac(const char *dev, char *mac_address);
int   parse_ipopts(const char *txt, u8 *data, int datalen,
		   int* firsthopoff, int* lasthopoff, char *errstr,
		   size_t errstrlen);
char *mkstr(const char *start, const char *end);
void  parse_tcpopts(u8 *optp, int len, char *result, int bufsize);
u8   *hexbin(char *str, size_t *outlen);
int   find_word(const char* buffer, const char* word);
char *clean_url(const char* url);
void  remove_specials(char* buffer);
void  to_lower(char* str);
void to_lower_const(const char *input, char *output);
u32   random_num_u32(u32 min, u32 max);
u32   random_seed_u32(void);
char *random_str(int len, const char *dictionary);
u16   random_check(void);
long long delayconv(const char *txt);
u16   random_srcport(void);
u32   random_u32(void);
u16   random_u16(void);
u8    random_u8(void);
const char *random_ip4(void);
const char *get_time(void);
const char *get_this_is(int type);

__END_DECLS

#endif

