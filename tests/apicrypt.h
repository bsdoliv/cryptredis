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

#include <iostream>

using namespace std;

class APICryptLabel {
public:
	string label;
	APICryptLabel(string _label) :
	    label(_label)
	{
		cerr << "==> begin test " << label << endl;
	};
	~APICryptLabel()
	{
		cerr << "==> end test " << label << endl;
	};
};

#define APICRYPT_OPEN()			\
	CryptRedisDb		crdb;	\
	CryptRedisResult	crres;	\
	assert(crdb.open("127.0.0.1", 6379))

#define APICRYPT_CLOSE()	\
	assert(crdb.close())	\
	assert(!crdb.connected())

#define APICRYPT_LABEL(label)	APICryptLabel _acl(label);

#define APICRYPT_REPORT(...)		\
	fprintf(stderr,"=> ");		\
	fprintf(stderr, __VA_ARGS__);	\
	fprintf(stderr, "\n");

static inline string
saltstr(void)
{
    char saltbuf[33];
    strlcpy(saltbuf, bcrypt_gensalt(6), sizeof(saltbuf));
    return (string(saltbuf));
}
