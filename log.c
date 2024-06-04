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

/*
 * Copyright (c) 1993 [OpenBSD libc *err* *warn* code.]
 * The Regents of the University of California.
 * All rights reserved.
 */

#include "ncsnet/log.h"

noreturn void err(int eval, const char *fmt, ...)
{
  va_list ap;
  
  va_start(ap, fmt);
  if (fmt) {
    (void)vfprintf(stderr, fmt, ap);
    (void)fprintf(stderr, ": ");
  }
  va_end(ap);
  (void)fprintf(stderr, "%s\n", strerror(errno));
  
  exit(eval);
}

void warn(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  if (fmt) {
    (void)vfprintf(stderr, fmt, ap);
    (void)fprintf(stderr, ": ");
  }
  va_end(ap);
  
  (void)fprintf(stderr, "%s\n", strerror(errno));
}

noreturn void errx(int eval, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  if (fmt)
    (void)vfprintf(stderr, fmt, ap);
  (void)fputc('\n', stderr);
  va_end(ap);
  
  exit(eval);
}

void warnx(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  if (fmt)
    (void)vfprintf(stderr, fmt, ap);
  (void)fputc('\n', stderr);
  
  va_end(ap);
}
