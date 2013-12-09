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
    fprintf(stderr, "==> begin test encode\n");
    char encdbufs[] = "\\x2d582960\\xde09730e\\xab6b33fc\\x7391780d";
    u_int32_t encrybuf[] = { 
            0x2d582960, 0xde09730e, 0xab6b33fc, 0x7391780d };
    size_t buflen = sizeof(encrybuf);
    char *encds = (char *)malloc(cryptredis_encsiz(buflen));
    bzero(encds, cryptredis_encsiz(buflen));
    cryptredis_encode(encds, (u_int32_t *)encrybuf, buflen);
    fprintf(stderr, "=> encdbufs: %s\n", encdbufs);
    fprintf(stderr, "=> encds: %s\n", encds);
    fprintf(stderr, "=> strlen(encdbufs): %ld\n", strlen(encdbufs));
    fprintf(stderr, "=> strlen(encds): %ld\n", strlen(encds));
    assert(strlen(encdbufs) == strlen(encds));
    assert(strncmp(encdbufs, encds, buflen) == 0);
    free(encds);
    fprintf(stderr, "==> end test encode\n");
}

void
test_decode()
{
    fprintf(stderr, "==> begin test decode\n");
    u_int32_t decdbuf[SIZBUF];
    u_int32_t encrybuf[] = { 
            0x2d582960, 0xde09730e, 0xab6b33fc, 0x7391780d };
    char encds[] = "\\x2d582960\\xde09730e\\xab6b33fc\\x7391780d";
    size_t buflen = sizeof(encrybuf);
    size_t len = cryptredis_decode(encds, decdbuf);
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
