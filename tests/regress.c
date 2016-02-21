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
rediscrypt_key_t key[KEY_SIZE] = { 
	0xffaabbcc,
	0xaabbccdd,
	0xbbccddee,
	0xccddeeff
};

void
test_decrypt()
{
	char		rawbuf[SIZBUF];
	size_t		rawbuflen;
	char		decrypted_buf[SIZBUF];
	u_int32_t	encrypted_buf[] = { 0xb4f8b91b, 0x051b3206, 0x29683e3a,
			    0xa3690f16 };

	fprintf(stderr, "==> begin test decrypt\n");

	bzero(rawbuf, SIZBUF);
	bzero(decrypted_buf, SIZBUF);

	strncpy(rawbuf, "test hello world", SIZBUF);
	rawbuflen = cryptredis_align64(strlen(rawbuf));

	cryptredis_decrypt(key, encrypted_buf, decrypted_buf,
	    sizeof(encrypted_buf));

	fprintf(stderr, "=> rawbuf: %s\n", rawbuf);
	fprintf(stderr, "=> decrybuf: %s\n", decrypted_buf);

	assert(strncmp(rawbuf, decrypted_buf, strlen(rawbuf)) == 0);

	fprintf(stderr, "==> end test decrypt\n");
}

void
test_encrypt()
{
	char		rawbuf[SIZBUF];
	char		decrypted_buf[SIZBUF];
	u_int32_t	encrypted_buf[] = { 0xb4f8b91b, 0x051b3206, 0x29683e3a,
			    0xa3690f16 };
	u_int32_t	dstencbuf[SIZBUF];
	size_t		buflen;

	fprintf(stderr, "==> begin test make64align\n");

	bzero(rawbuf, SIZBUF);
	strncpy(rawbuf, "test hello world", SIZBUF);
	buflen = cryptredis_align64(strlen(rawbuf));
	assert(buflen == 16);

	fprintf(stderr, "=> make64align(dstlen): %ld\n", buflen);
	fprintf(stderr, "==> end test make64align\n");
	fprintf(stderr, "==> begin test encrypt\n");

	memset(dstencbuf, 0, sizeof(dstencbuf));
	encrypt_wrap(key, rawbuf, (u_int32_t *)dstencbuf, buflen);
	cryptredis_dumphex32("=> dstencbuf", dstencbuf, buflen);
	cryptredis_dumphex32("=> encrypted_buf", encrypted_buf, sizeof(encrypted_buf));
	assert(memcmp(dstencbuf, encrypted_buf, buflen) == 0);

	fprintf(stderr, "==> end test encrypt\n");
}

void
test_encode()
{
	char		*encoded_src = "YClYLQ5zCd78M2urDXiRcw==";
	u_int32_t	 buf[] = { 0x2d582960, 0xde09730e, 0xab6b33fc,
			    0x7391780d };
	char		*encoded_dst;
	size_t		 buflen;

	fprintf(stderr, "==> begin test encode\n");

	buflen = sizeof(buf);
	if ((encoded_dst = (char *)calloc(1, cryptredis_encsiz(buflen))) ==
	    NULL) return;

	cryptredis_encode(encoded_dst, cryptredis_encsiz(buflen), buf, buflen);

	fprintf(stderr, "=> encoded_src: %s\n", encoded_src);
	fprintf(stderr, "=> encoded_dst: %s\n", encoded_dst);
	fprintf(stderr, "=> strlen(encoded_src): %ld\n", strlen(encoded_src));
	fprintf(stderr, "=> strlen(encoded_dst): %ld\n", strlen(encoded_dst));

	assert(strlen(encoded_src) == strlen(encoded_dst));
	assert(strncmp(encoded_src, encoded_dst, strlen(encoded_src)) == 0);

	free(encoded_dst);

	fprintf(stderr, "==> end test encode\n");
}

void
test_decode()
{
	char		*encodeds = "YClYLQ5zCd78M2urDXiRcw==";
	u_int32_t	 cryptbuf_src[] = { 0x2d582960, 0xde09730e, 0xab6b33fc,
			    0x7391780d };
	u_int32_t	 cryptbuf_dst[SIZBUF];
	size_t		 buflen, len;

	fprintf(stderr, "==> begin test decode\n");
	fprintf(stderr, "=> cryptbuf_src: x%08x x%08x x%08x x%08x\n",
	    cryptbuf_src[0], cryptbuf_src[1], cryptbuf_src[2],
	    cryptbuf_src[3]);
	fprintf(stderr, "=> cryptbuf_dst:  x%08x x%08x x%08x x%08x\n",
	    cryptbuf_dst[0], cryptbuf_dst[1], cryptbuf_dst[2],
	    cryptbuf_dst[3]);

	buflen = sizeof(cryptbuf_src);
	len = cryptredis_decode(encodeds, cryptbuf_dst, SIZBUF);

	fprintf(stderr, "=> len: %ld\n", len);
	fprintf(stderr, "=> buflen: %ld\n", buflen);

	assert(buflen == len);
	assert(memcmp(cryptbuf_dst, cryptbuf_src, buflen) == 0);

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
