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

#include "ncsnet/ftp.h"
#include "ncsnet/socket.h"
#include <stdio.h>
#include "ncsnet/utils.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

 bool ftp_qprc_auth(int fd, const char* login, const char* pass)
{
  char command[CMD_BUFFER];
  int rescode = 0;
  u8 *recvbuf = NULL;

  snprintf(command, CMD_BUFFER, "%s %s\r\n", C_USER, login);
  recvbuf = sendproto_command(fd, command);
  if (!recvbuf)
    goto fail;
  rescode = atoi((char*)recvbuf);

  if (rescode == R_220 || rescode == R_230)
    goto ok;
  if (rescode != R_331)
    goto fail;

  memset(command, 0, CMD_BUFFER);
  memset(recvbuf, 0, CMD_BUFFER);
  snprintf(command, CMD_BUFFER, "%s %s\r\n", C_PASS, pass);

  recvbuf = sendproto_command(fd, command);
  if (!recvbuf)
    goto fail;
  rescode = atoi((char*)recvbuf);

  if (rescode == R_230 || rescode == R_200)
    goto ok;

  goto fail;

fail:
  if (recvbuf)
    free(recvbuf);
  return false;

ok:
  if (recvbuf)
    free(recvbuf);
  return true;

}
