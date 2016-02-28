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

#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>

#include "cryptredis.h"
#include "encode.h"
#include "apicrypt.h"

int
main(void)
{
	APICRYPT_LABEL("setCryptEnabled()");
	APICRYPT_OPEN();
	string	entrykey = "foo_" + saltstr();
	string	entryval = "bar_" + saltstr();
	size_t	encsiz;

	assert(putenv((char *)"CRYPTREDIS_KEYFILE=test.key") == 0);
	assert(crdb.setCryptEnabled(true) == 0);
	assert(crdb.cryptEnabled());
	assert(crdb.set(entrykey, entryval) == CryptRedisResult::Ok);

	crdb.get(entrykey, &crres);
	APICRYPT_REPORT("entryval %s", entryval.data());
	APICRYPT_REPORT("crres %s", crres.toString().data());
	assert(crres.status() == CryptRedisResult::Ok);
	assert(crres.toString() == entryval);
	crres.clear();

	/*
	 * retrieve the same key, disabling encrypt, shall get a ciphered
	 * buffer
	 */
	assert(crdb.setCryptEnabled(false) == 0);
	assert(!crdb.cryptEnabled());

	crdb.get(entrykey, &crres);
	APICRYPT_REPORT("key nok crdb.get()");
	APICRYPT_REPORT("entryval %s", entryval.data());
	APICRYPT_REPORT("crres %s", crres.toString().data());
	assert(crres.status() == CryptRedisResult::Ok);
	assert(crres.toString() != entryval);

	encsiz = cryptredis_encsiz(cryptredis_align64(entryval.size())) - 1;
	APICRYPT_REPORT("crres.size() %lu encsiz %lu",
	    crres.toString().size(), encsiz);
	assert(crres.toString().size() == encsiz);

	/* cleanup */
	assert(crdb.del(entrykey) == CryptRedisResult::Ok);
	crres.clear();
	assert(unsetenv((char *)"CRYPTREDIS_KEYFILE") == 0);

	return (0);
}
