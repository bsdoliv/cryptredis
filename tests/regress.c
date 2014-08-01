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

#include <assert.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "cryptwrap.h"
#include "diskio.h"
#include "encode.h"
#include "tools.h"

#define SIZBUF 1024
char rawbuf[SIZBUF];
char encbuf[SIZBUF];
rediscrypt_key_t key[KEY_SIZE] = { 
    0xffaabbcc,
    0xaabbccdd,
    0xbbccddee,
    0xccddeeff
};

void
test_decrypt()
{
    fprintf(stderr, "==> begin test decrypt\n");
    bzero(rawbuf, SIZBUF);
    bzero(encbuf, SIZBUF);
    strncpy(rawbuf, "test hello world", SIZBUF);
    size_t buflen = cryptredis_align64(strlen(rawbuf));
    u_int32_t encrybuf[] = { 
        0xb4f8b91b, 0x051b3206, 0x29683e3a, 0xa3690f16 };

    char decrybuf[SIZBUF];
    bzero(decrybuf, SIZBUF);

//    decrypt_wrap(key,  (u_int32_t *)encrybuf, rawbuf, buflen);
    cryptredis_decrypt(key, encrybuf, decrybuf, sizeof(encrybuf));
    fprintf(stderr, "=> rawbuf: %s\n", rawbuf);
    fprintf(stderr, "=> decrybuf: %s\n", decrybuf);
    assert(strncmp(rawbuf, decrybuf, strlen(rawbuf)) == 0);
    fprintf(stderr, "==> end test decrypt\n");
}

void
test_encrypt()
{
    fprintf(stderr, "==> begin test make64align\n");
    bzero(rawbuf, SIZBUF);
    bzero(encbuf, SIZBUF);
    strncpy(rawbuf, "test hello world", SIZBUF);

    size_t buflen = cryptredis_align64(strlen(rawbuf));
    assert(buflen == 16);
    fprintf(stderr, "=> make64align(dstlen): %ld\n", buflen);
    fprintf(stderr, "==> end test make64align\n");

    fprintf(stderr, "==> begin test encrypt\n");
    u_int32_t encrybuf[] = { 
        0xb4f8b91b, 0x051b3206, 0x29683e3a, 0xa3690f16 };
    encrypt_wrap(key, rawbuf, (u_int32_t *)encbuf, buflen);
    cryptredis_dumphex32("=> encbuf", encbuf, buflen);
    assert(memcmp(encbuf, encrybuf, buflen) == 0);
    fprintf(stderr, "==> end test encrypt\n");


}

void
test_encode()
{
    char        *encoded_src = "YClYLQ5zCd78M2urDXiRcw==";
    u_int32_t    buf[] = { 0x2d582960, 0xde09730e, 0xab6b33fc, 0x7391780d };
    size_t       buflen = sizeof(buf);
    char        *encoded_dst;

    if ((encoded_dst = (char *)calloc(1, cryptredis_encsiz(buflen))) == NULL)
        return;

    fprintf(stderr, "==> begin test encode\n");
    cryptredis_encode(encoded_dst, cryptredis_encsiz(buflen), buf, buflen);
    fprintf(stderr, "=> encoded_src: %s\n", encoded_src);
    fprintf(stderr, "=> encoded_dst: %s\n", encoded_dst);
    fprintf(stderr, "=> strlen(encoded_src): %ld\n", strlen(encoded_src));
    fprintf(stderr, "=> strlen(encoded_dst): %ld\n", strlen(encoded_dst));
    assert(strlen(encoded_src) == strlen(encoded_dst));
    assert(strncmp(encoded_src, encoded_dst, strlen(encoded_src)) == 0);
    free(encoded_dst);
    encoded_dst = NULL;
    fprintf(stderr, "==> end test encode\n");
}

void
test_decode()
{
    fprintf(stderr, "==> begin test decode\n");
    u_int32_t decdbuf[SIZBUF];
    u_int32_t encrybuf[] = { 0x2d582960, 0xde09730e, 0xab6b33fc, 0x7391780d };
    char encds[] = "YClYLQ5zCd78M2urDXiRcw==";
    size_t buflen = sizeof(encrybuf);
    size_t len = cryptredis_decode(encds, decdbuf, SIZBUF);
    fprintf(stderr, "=> encrybuf: x%08x x%08x x%08x x%08x\n", 
            encrybuf[0], encrybuf[1], encrybuf[2], encrybuf[3]);
    fprintf(stderr, "=> decdbuf:  x%08x x%08x x%08x x%08x\n",
            decdbuf[0], decdbuf[1], decdbuf[2], decdbuf[3]);
    fprintf(stderr, "=> len: %ld\n", len);
    fprintf(stderr, "=> buflen: %ld\n", buflen);
    assert(buflen == len);
    assert(memcmp(decdbuf, encrybuf, buflen) == 0);
    fprintf(stderr, "==> end test decode\n");
}

int
main(int argc, char **argv)
{
    test_encode();
    test_decode();
    test_encrypt();
    test_decrypt();

    return 0;
}

/* vim: set ts=4 sw=4 et: */
