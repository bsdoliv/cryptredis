/*
 * Copyright (c) 2013 Andre Oliveira <me@andreldoliveira.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Andre Oliveira.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "encode.h"

size_t
cryptredis_encsiz(int len)
{
    int senclen = 
        (len * 2) +                     /* 2 chars to represent each byte */
        ((len / sizeof(u_int32_t)) * 2);/* for each block a "\x"
                                           separators */

    return senclen;
}

void
cryptredis_encode(char *dst, const u_int32_t *src, int len)
{
    const u_int32_t *ps = src;
    char *pd = dst;
    int step = (sizeof(*ps) * 2) + 2;
    int i = 0;
    for (i = 0; i < (len / sizeof(*ps)); ps++, i++) {
        sprintf(pd, "\\x%08x", *ps);
        pd += step;
    }
}

size_t
cryptredis_decode(const char *src, void *dst)
{
    int dstlen = 0;
#   define BLKSIZ 16
    char blkbuf[BLKSIZ];
    char *se = strndup(src, strlen(src));
    if (se == NULL)
        errx(1, "couldn't allocate memory for decoding operation");
    char *p = strtok(se, "\\x");
    u_int32_t *pd = (u_int32_t *)dst;
    for (; p != NULL; p = strtok(NULL, "\\x")) {
        bzero(blkbuf, BLKSIZ);
        snprintf(blkbuf, BLKSIZ, "0x%s", p);
        *pd = (u_int32_t)strtol(blkbuf, (char **)NULL, 16);
        pd++;
        dstlen += sizeof(*pd);
    }
    free(se);
    return dstlen;
#   undef BLKSIZ
}

/* vim: set ts=4 sw=4 et: */
