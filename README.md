cryptredis
==========
cryptredis is an experimental BSD licensed c++ client library for Redis
database, which also offers encryption (AES) for string values.

It has been inspired in by projects such as MIT's CryptDB [1], and Google's
encrypted_bigquery_client [2], lots of concepts and code imported from
OpenBSD's swap encryption and cryptographic softraid(4) [3,4].

Currently only strings store is supported, commands get and set.

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
Include cryptredis.h, then link libcryptredis.a statically to your application.

Please check tools/Makefile.template for building/linking hints.

API design aims for simplicity, find sample code on tests/apicrypt.cpp,
tests/rediscliget.cpp and tests/rediscliset.cpp.

Sample code:

	...
	// simple.cpp
	#include "cryptredis.h"

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

Use the vanilla redis-client to inspect the stored value key:

	% redis-cli get foo
	"c2ihkiDk8bygSPYoGzFFJg=="


Key setup
=========

Use openssl command to generate a reasonable key file.

	% openssl enc -aes-256-cbc -k"" -P -md sha512 > /etc/cryptredis.key

	% chmod 600 /etc/cryptredis.key
	% export CRYPTREDIS_KEYFILE=/etc/cryptredis.key


License
======
    Check LICENSE file.
