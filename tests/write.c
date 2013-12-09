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
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include "cryptwrap.h"
#include "diskio.h"
#include "encode.h"
#include "tools.h"

#define SIZBUF (8192 * 1024)
char src[SIZBUF];

int
main(int argc, char **argv)
{
    rediscrypt_key_t key[KEY_SIZE] = { 
        0xffaabbcc,
        0xaabbccdd,
        0xbbccddee,
        0xccddeeff
    };

#if 0
    fprintf(stderr, "=> key:");
    int i = 0;
    for (; i < KEY_SIZE; i++)
        fprintf(stderr, " 0x%x", key[i]);
    fprintf(stderr, "\n");
#endif

    if (argc < 2)
        errx(1, "missing parameter");

    bzero(src, SIZBUF);
#ifdef TESTSTR
    strncpy(src, "test hello world", SIZBUF);
#else
    if (fgets(src, SIZBUF, stdin) == NULL)
        errx(1, "failed to read from stdin");
#endif /* TESTSTR */

    size_t len = strlen(src);
    size_t dstlen = cryptredis_align64(len);
    fprintf(stderr, "=> len: %ld\n", len);
    fprintf(stderr, "=> make64align(dstlen): %ld\n", dstlen);

    u_int32_t *dst = (u_int32_t *)malloc(dstlen);
    bzero(dst, dstlen);

    fprintf(stderr, "==> test encrypt\n");
    encrypt_wrap(key, src, dst, dstlen);

    fprintf(stderr, "==> test encode\n");
    char *encbuf = (char *)malloc(cryptredis_encsiz(dstlen));
    bzero(encbuf, cryptredis_encsiz(dstlen));
    cryptredis_encode(encbuf, (u_int32_t *)dst, dstlen);
    fprintf(stderr, "==> test diskstore\n");
    disk_store("/tmp/temp_store", encbuf, strlen(encbuf));
    fprintf(stderr, "=> written to store: %s\n", encbuf);

    free(encbuf);
    free(dst);

    return 0;
}
