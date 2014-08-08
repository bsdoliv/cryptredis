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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/param.h>

#include "encode.h"

size_t
cryptredis_encsiz(int len)
{
	return (len * 2 + 1);
}

void
cryptredis_encode(char *dst, size_t dlen, const void *src, size_t slen)
{
	unsigned char *p = (unsigned char *)src;

	if (b64_ntop(p, slen, dst, (dlen / sizeof(p[0]))) == -1)
		errx(1, "b64_ntop: error encoding base64");
}

size_t
cryptredis_decode(const char *src, void *dst, size_t dlen)
{
	unsigned char	*inbuf = (unsigned char *)src;
	size_t		 s;

	if ((s = b64_pton(inbuf, dst, dlen)) == -1)
		errx(1, "b64_pton: error decoding base64");

	return (s);
}
