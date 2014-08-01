/*
 * Copyright (c) 2013 Andre de Oliveira <deoliveirambx@googlemail.com>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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

    size_t len = cryptredis_decode(senc, ciphbuf, SIZBUF);
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
    size_t declen = cryptredis_decode(src, ciphbuf, SIZBUF);

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
