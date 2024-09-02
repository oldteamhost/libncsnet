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

#include <ncsnet/icmp.h>

u8 *icmp6_msg_ndsol_build(ip6_t target, u8 *opts, size_t optslen, size_t *msglen)
{
  u8 *msg;

  msg=frmbuild(msglen, NULL, "u32(0),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),      \
    u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu),u8(%hhu), u8(%hhu),u8(%hhu), u8(%hhu), \
    u8(%hhu),u8(%hhu), u8(%hhu),u8(%hhu)",
    ip6t_getid(&target, 0), ip6t_getid(&target, 1),
    ip6t_getid(&target, 2), ip6t_getid(&target, 3),
    ip6t_getid(&target, 4), ip6t_getid(&target, 5),
    ip6t_getid(&target, 6), ip6t_getid(&target, 7),
    ip6t_getid(&target, 8), ip6t_getid(&target, 9),
    ip6t_getid(&target, 10), ip6t_getid(&target, 11),
    ip6t_getid(&target, 12), ip6t_getid(&target, 13),
    ip6t_getid(&target, 14), ip6t_getid(&target, 15));

  if (opts&&optslen)
    msg=frmbuild_addfrm(opts, optslen, msg, msglen, NULL);

  return msg;
}
