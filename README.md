CryptRedis
==========

CryptRedis brings OpenBSD lightweight VM encrypting mechanism to Redis.

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

    % CRYPTREDISKEY="passphrasekey" ./simple
    bar

    % redis-cli get foo
    "\\xcb32fb1d\\xc3fb804d\\x49795a76\\x4efe2dad"

CryptRedis is a thin C++ layer for encrypting (AES) data while storing to
Redis.  It is based in the same proven track-record kernel technology [1] from
OpenBSD VM, developed by Niels Provos [2], thus you can expect to have robust
crypto while minimum impact on latency.

CryptRedis has been inspired by MIT's project CryptDB [3].

References
----------
[1] http://cvs.openbsd.org/papers/swapencrypt-slides.pdf

[2] http://cvs.openbsd.org/papers/swapencrypt.pdf

[3] http://people.csail.mit.edu/nickolai/papers/raluca-cryptdb.pdf


Build
=====
    % tools/bmakebuild.sh
    % alias bmake=~/.opt/bmake/bin/bmake
    % bmake all runtests

Install
=======
    % DESTDIR=/opt bmake install

Usage
=====
    Simply include cryptredis.h, link it statically to your application.
    Check tools/Makefile.template for building/linking hints.
    The API is aimed to be simple and intuitive, find sample code on
    tests/api.cpp, tests/rediscliget.cpp and tests/rediscliset.cpp.

License
======
    Check LICENSE file.
