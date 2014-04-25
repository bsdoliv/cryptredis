/*
 * Copyright (c) 2013 Andre de Oliveira <deoliveirambx@googlemail.com>
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
 *      This product includes software developed by Andre de Oliveira.
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "cryptwrap.h"
#include "diskio.h"
#include "encode.h"

#define SIZBUF (8192 * 1024)
char deciphbuf[SIZBUF];
u_int32_t ciphbuf[SIZBUF];

void
test_disk_retrieve(rediscrypt_key_t *key)
{
    int senclen;
    char *senc;
    disk_retrieve("/tmp/temp_store", &senc, &senclen);
    fprintf(stderr, "=> read from store: %s\n", senc);

    size_t len = cryptredis_decode(senc, ciphbuf);
    decrypt_wrap(key, ciphbuf, deciphbuf, len);
    free(senc);
}

int
main(int argc, char **argv)
{
    rediscrypt_key_t key[KEY_SIZE] = { 
        0xffaabbcc,
        0xaabbccdd,
        0xbbccddee,
        0xccddeeff
    };

    char *src;
    int len;

    if (argc >= 2) {
        disk_retrieve(argv[1], (char **)&src, &len);
    } else {
        src = (char *)calloc(1, SIZBUF);
        if (fgets(src, SIZBUF, stdin) == NULL)
            errx(1, "failed to read from stdin");
    }

    fprintf(stderr, "=> read from store: %s\n", src);
    bzero(ciphbuf, SIZBUF);
    size_t declen = cryptredis_decode(src, ciphbuf);

    /* dump ciphbuf */
    int i = 0;
    fprintf(stderr, "=>");
    u_int32_t *p = ciphbuf;
    for (; i < declen; i += sizeof(u_int32_t))
        fprintf(stderr, " %d: x%08x", i, *(p++));
    fprintf(stderr, "\n");

    bzero(deciphbuf, SIZBUF);
    decrypt_wrap(key, ciphbuf, deciphbuf, declen);

    /* dump deciphbuf */
    fprintf(stderr, "=> deciphred buffer: %s", deciphbuf);
    fprintf(stderr, "\n=> buffer len: %ld\n", strlen(deciphbuf));

    free (src);
    return 0;
}

/* vim: set ts=4 sw=4 et: */
