cryptredis
==========
cryptredis is an experimental BSD licensed C and C++ client library for Redis
database, which also offers symmetric encryption (AES) of string values.

particularly useful for geo-distributed storage scenarios:
encrypt/decrypt with local key, store remotely encrypted.

it has been inspired by MIT's CryptDB [1], Google's encrypted_bigquery_client
[2] and concepts from OpenBSD's swap encryption and
cryptographic softraid(4) [3,4].

currently, only strings store are supported, plus commands get and set.

[1] http://people.csail.mit.edu/nickolai/papers/raluca-cryptdb.pdf

[2] https://github.com/google/encrypted-bigquery-client

[3] http://www.openbsd.org/papers/swapencrypt-slides.pdf

[4] http://www.openbsd.org/papers/swapencrypt.pdf


Build & Install
===============

	Bootstrap bmake

	% tools/bmakebuild.sh
	% alias bmake=~/.opt/bmake/bin/bmake

	Bitrig or OpenBSD
	--------------
	% bmake all runtests

	Linux
	-----
	dependencies: ksh, clang

	% bmake all runtests

	Install
	-------
	% DESTDIR=/opt sudo -E bmake install


Usage
=====
in C++ include cryptredisxx.h, then link libcryptredis.a statically to a given application.

please check tools/Makefile.template for building/linking hints.

API design aims for simplicity, find sample code on tests/apicrypt.cpp,
tests/rediscliget.cpp and tests/rediscliset.cpp.

sample code:

	...
	// simple.cpp
	#include "cryptredisxx.h"

	CryptRedisDb	crdb;

	if (!crdb.open("127.0.0.1", 6379))
		return (-1);

	crdb.setCryptEnabled(true);
	crdb.set("foo", "bar");
	cerr << crdb.get("foo").toString();
	crdb.close();
	...

	% CRYPTREDIS_KEYFILE="/etc/cryptredis/foobardb.key" ./simple
	bar

use the vanilla redis-client to inspect the stored value key:

	% redis-cli get foo
	"c2ihkiDk8bygSPYoGzFFJg=="

for C usage, one might integrate all .c file and all .h files to the
application building toolchain, exception to cryptredisxx.h, which is only
necessary for C++.

Key setup
=========

use openssl command to generate a reasonable key file.

	% openssl enc -aes-256-cbc -k"" -P -md sha512 > /etc/cryptredis.key

	% chmod 600 /etc/cryptredis.key
	% export CRYPTREDIS_KEYFILE=/etc/cryptredis.key


License
======
    check LICENSE file.
