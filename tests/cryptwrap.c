/*
 * Copyright (c) 2013-2016 Andre de Oliveira <deoliveirambx@googlemail.com>
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

#include <stdio.h>
#include <strings.h>
#include <string.h>

#include "cryptwrap.h"
#include "tools.h"

void
encrypt_wrap(const struct cryptredis_key *key, const char *src, u_int32_t *dst,
             int dstlen)
{
    fprintf(stderr, "=> string to encrypt: %s\n", src);
    cryptredis_encrypt(key, src, dst, dstlen);
    cryptredis_dumphex32("=> encrypted", dst, dstlen);
}

void 
decrypt_wrap(const struct cryptredis_key *key, const u_int32_t *src, char *dst,
             int len)
{
    cryptredis_decrypt(key, src, dst, len);
    fprintf(stderr, "=> dstlen: %d\n", len);
    fprintf(stderr, "=> decrypted: %s\n", dst);
    fprintf(stderr, "=> strlen(sdec): %ld\n", strlen(dst));
}
