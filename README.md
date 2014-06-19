cryptredis
==========

    ...
    // simple.cpp
    #include "cryptredis.h"

    CryptRedisDb redisdb;
    redisdb.open("127.0.0.1", 6379);
    redisdb.setCryptEnabled(true);
    redisdb.set("foo", "bar");
    std::cerr << redisdb.get("foo").toString();
    redisdb.close();
    ...

    % CRYPTREDISKEY="128bitslongenoughpassphrasekey12" ./simple
    bar

    % redis-cli get foo
    "\\xcb32fb1d\\xc3fb804d\\x49795a76\\x4efe2dad"

This is a thin C++ connector, able to transparently encrypts/decrypts (AES)
data while storing/retrieving it to/from Redis. It aims to offer some crypto,
still minimum latency impact.

Inspired by MIT's project CryptDB [1].

[1] http://people.csail.mit.edu/nickolai/papers/raluca-cryptdb.pdf

[2] http://www.openbsd.org/papers/swapencrypt-slides.pdf

[3] http://www.openbsd.org/papers/swapencrypt.pdf

Installation
============
	Bootstrap bmake

	% tools/bmakebuild.sh
	% alias bmake=~/.opt/bmake/bin/bmake

	OpenBSD
	-------
	% bmake all runtests

	Linux
	-----
	dependencies: ksh, g++, gcc

	% bmake all runtests

Install
=======
    % DESTDIR=/opt sudo -E bmake install

Usage
=====
    Simply include cryptredis.h, link it statically to your application.
    Check tools/Makefile.template for building/linking hints.
    The API is aimed to be simple and intuitive, find sample code on
    tests/api.cpp, tests/rediscliget.cpp and tests/rediscliset.cpp.

License
======
    Check LICENSE file.
