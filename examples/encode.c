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
#include <stdnoreturn.h>
#include <string.h>

#include "../ncsnet/sha256.h"
#include "../ncsnet/sha512.h"
#include "../ncsnet/sha1.h"
#include "../ncsnet/md5.h"
#include "../ncsnet/base64.h"
#include "../ncsnet/crc.h"
#include "../ncsnet/adler32.h"

#define SHA512M 1
#define SHA256M 2
#define MD5M    3
#define CRC8    4
#define CRC16   5
#define CRC32   6
#define CRC64   7
#define CRC64WE 8
#define ADLER32 9
#define BASE64  10
#define SHA1    11

noreturn void usage(char** argv)
{
  printf("Usage: %s <txt> <method 1 or 2 or ...,>\n", argv[0]);
  printf("Methods: [1](SHA512),    [2](SHA256), [3](MD5)\n");
  printf("         [4](CRC8),      [5](CRC16),  [6](CRC32)\n");
  printf("         [7](CRC64ECMA), [8](CRC64WE) [9](ADLER32)\n");
  printf("         [10](BASE64)    [11](SHA-1)\n");
  exit(0);
}

int main(int argc, char **argv)
{
  char *temp = NULL;
  bool numcrypt = false;
  u64 tmp1 = 0;
  
  if (argc < 2 + 1)
    usage(argv);
  if (atoi(argv[2]) > 11)
    usage(argv);

  switch (atoi(argv[2])) {
  case MD5M:
    temp = md5str(argv[1], strlen(argv[1]));
    break;
  case SHA256M:
    temp = sha256str(argv[1], strlen(argv[1]));
    break;
  case SHA512M:
    temp = sha512str(argv[1], strlen(argv[1]));
    break;
  case SHA1:
    temp = sha1str(argv[1], strlen(argv[1]));
    break;    
  case CRC8:
    tmp1 = (u64)crc8((u8*)argv[1], strlen(argv[1]), NULL);
    numcrypt = true;
    break;
  case CRC16:
    tmp1 = (u64)crc16((u8*)argv[1], strlen(argv[1]), NULL);
    numcrypt = true;
    break;
  case CRC32:
    tmp1 = (u64)crc32((u8*)argv[1], strlen(argv[1]), NULL);
    numcrypt = true;
    break;
  case CRC64:
    tmp1 = crc64ecma((u8*)argv[1], strlen(argv[1]), NULL);
    numcrypt = true;
    break;
  case CRC64WE:
    tmp1 = crc64we((u8*)argv[1], strlen(argv[1]), NULL);
    numcrypt = true;
    break;
  case ADLER32:
    tmp1 = adler32(1, (u8*)argv[1], strlen(argv[1]));
    numcrypt = true;
    break;
  case BASE64: {
    size_t encoded_len = base64encoded_len(strlen(argv[1]));
    temp = malloc(encoded_len + 1);
    if (temp) {
      base64encode(argv[1], strlen(argv[1]), temp, encoded_len + 1);
      temp[encoded_len] = '\0';
    }
    break;
  }
  default:
    temp = "failed";
    break;
  }
  
  if (!numcrypt && temp)
    printf("encoded: %s\n", temp);
  else
    printf("encoded: %ld\n", tmp1);

  if (!numcrypt && temp && (strcmp("failed", temp) != 0))
    free(temp);

  return 0;
}
