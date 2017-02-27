/*
 * Copyright (c) 2016 Andre de Oliveira <deoliveirambx@googlemail.com>
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
#include <string.h>
#include <stdlib.h>
#include <pwd.h>

#include "cryptredisxx.h"
#include "apicrypt.h"

int
main(void)
{
	APICRYPT_LABEL("setCryptEnabled() (nokey)");
	APICRYPT_OPEN();
	string	entrykey = "foo_" + saltstr();
	string	entryval = "bar_" + saltstr();

	crdb.setCryptEnabled(true);
	assert(!crdb.cryptEnabled());

	APICRYPT_REPORT("lastError() '%s' lastError.size() %lu",
	    crdb.lastError().data(), crdb.lastError().size());
	assert(crdb.lastError().compare("CRYPTREDIS_KEYFILE environment "
	    "variable not set") == 0);

	APICRYPT_REPORT("entrykey %s", entrykey.data());
	assert(CryptRedisResult::Ok == crdb.set(entrykey, entryval));

	crdb.get(entrykey, &crres);
	APICRYPT_REPORT("entryval %s", entryval.data());
	APICRYPT_REPORT("result %s", crres.toString().data());

	assert(CryptRedisResult::Ok == crres.status());
	assert(crres.toString() == entryval);

	/* cleanup */
	assert(CryptRedisResult::Ok == crdb.del(entrykey));
	crres.clear();

	return (0);
}
