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

#include <assert.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#include "cryptredis.h"
#include "cryptredis_test.h"

void
genrandstr(char *b, size_t bs, const char *p)
{
	char	buf[LINE_MAX];
	snprintf(b, bs, "%d_%s_%s", getpid(), p, randstr_r(buf, sizeof(buf)));
}

void
test_cryptredis_get_r(struct cryptredis *crp)
{
	char	entrykey[LINE_MAX];
	char	entryval[LINE_MAX];
	
	genrandstr(entrykey, sizeof(entrykey), __func__);
	genrandstr(entryval, sizeof(entryval), "foobar");

	assert(!cryptredis_set_r(crp, entrykey, entryval));
	assert(cryptredis_response_string(crp) != NULL);
	assert(!strcmp("OK", cryptredis_response_string(crp)));
	cryptredis_response_free(crp);
	assert(cryptredis_response_string(crp) == NULL);

	assert(!cryptredis_get_r(crp, entrykey));
	assert(cryptredis_response_string(crp) != NULL);
	assert(!strcmp(entryval, cryptredis_response_string(crp)));

	cryptredis_response_free(crp);
	assert(cryptredis_response_string(crp) == NULL);
	assert(!cryptredis_del_r(crp, entrykey));
}

void
test_cryptredis_set_r(struct cryptredis *crp)
{
	char	entrykey[LINE_MAX];
	char	entryval[LINE_MAX];

	genrandstr(entrykey, sizeof(entrykey), __func__);
	genrandstr(entryval, sizeof(entryval), "foobar");

	assert(!cryptredis_set_r(crp, entrykey, entryval));
	assert(cryptredis_response_string(crp) != NULL);
	assert(!strcmp("OK", cryptredis_response_string(crp)));
	cryptredis_response_free(crp);
	assert(cryptredis_response_string(crp) == NULL);

	if (crp->cr_crypt_enabled) {
		/*
		 * disable encryption, fetch value, should receive it encrypted
		 */
		assert(!cryptredis_config_encrypt(crp, 0));
		assert(!crp->cr_crypt_enabled);

		/*
		 * comparison to plain value should fail
		 */
		assert(!cryptredis_get_r(crp, entrykey));
		assert(cryptredis_response_string(crp) != NULL);
		assert(strcmp(entryval, cryptredis_response_string(crp)) != 0);
		cryptredis_response_free(crp);
		assert(cryptredis_response_string(crp) == NULL);

		assert(!cryptredis_config_encrypt(crp, 1));
		assert(crp->cr_crypt_enabled);
	}

	assert(!cryptredis_del_r(crp, entrykey));
}

void
test_cryptredis_ping_r(struct cryptredis *crp)
{
	assert(!cryptredis_ping_r(crp));
	assert(cryptredis_response_string(crp) != NULL);
	assert(!strcmp("PONG", cryptredis_response_string(crp)));

	cryptredis_response_free(crp);
	assert(cryptredis_response_string(crp) == NULL);
}

void
test_cryptredis_exists_r(struct cryptredis *crp)
{
	char	entrykey[LINE_MAX];
	char	entryval[LINE_MAX];
	
	genrandstr(entrykey, sizeof(entrykey), __func__);
	genrandstr(entryval, sizeof(entryval), "foobar");

	assert(!cryptredis_set_r(crp, entrykey, entryval));
	assert(cryptredis_response_string(crp) != NULL);
	assert(!strcmp("OK", cryptredis_response_string(crp)));
	cryptredis_response_free(crp);
	assert(cryptredis_response_string(crp) == NULL);

	assert(!cryptredis_exists_r(crp, entrykey));
	assert(cryptredis_response_string(crp) == NULL);

	assert(!cryptredis_del_r(crp, entrykey));
	assert(cryptredis_response_string(crp) == NULL);
	cryptredis_response_free(crp);
	assert(cryptredis_response_string(crp) == NULL);
}

void
test_cryptredis_del_r(struct cryptredis *crp)
{
	char	entrykey[LINE_MAX];
	char	entryval[LINE_MAX];

	genrandstr(entrykey, sizeof(entrykey), __func__);
	genrandstr(entryval, sizeof(entryval), "foobar");

	assert(!cryptredis_set_r(crp, entrykey, entryval));
	assert(cryptredis_response_string(crp) != NULL);
	assert(!strcmp("OK", cryptredis_response_string(crp)));
	cryptredis_response_free(crp);
	assert(cryptredis_response_string(crp) == NULL);

	assert(!cryptredis_del_r(crp, entrykey));
	assert(cryptredis_response_string(crp) == NULL);
}

#define TESTOPEN(crp)	do {						\
	assert((crp = cryptredis_open("localhost", 6379)) != NULL);	\
	assert(crp->cr_connected);					\
} while (0)

#define TESTCLOSE(crp)	do {				\
	assert(!cryptredis_close(c));			\
} while (0)

int
main(int argc, char **argv)
{
	struct cryptredis	*c;
	char	keyfile[LINE_MAX];
	char	buf[LINE_MAX];

	TESTOPEN(c);
	assert(!cryptredis_config_encrypt(c, 0));
	assert(!c->cr_crypt_enabled);

	test_cryptredis_ping_r(c);
	test_cryptredis_exists_r(c);
	test_cryptredis_set_r(c);
	test_cryptredis_get_r(c);
	test_cryptredis_del_r(c);
	TESTCLOSE(c);

	TESTOPEN(c);
	memset(buf, 0, sizeof(buf));
	snprintf(keyfile, sizeof(keyfile),
	    "CRYPTREDIS_KEYFILE=%s/../../obj/test.key", getcwd(buf,
	    sizeof(buf)));
	assert(!putenv(keyfile));
	assert(!cryptredis_config_encrypt(c, 1));
	assert(c->cr_crypt_enabled);

	test_cryptredis_exists_r(c);
	test_cryptredis_set_r(c);
	test_cryptredis_get_r(c);
	test_cryptredis_del_r(c);
	TESTCLOSE(c);

	return (0);
}
