/*
 * Copyright (c) 2013 Andre de Oliveira <deoliveirambx@googlemail.com>
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

#include <iostream>

#include "cryptredisxx.h"
#include "encode.h"
#include "apicrypt.h"

void
setup(CryptRedisDb *rdb)
{
    rdb->setHost("127.0.0.1");
    rdb->setPort(6379);
    assert(rdb->open());
    assert(rdb->connected());
}

void
teardown(CryptRedisDb *rdb)
{
    rdb->close();
    assert(!rdb->connected());
}

void
test_ping()
{
    std::cerr << "==> begin test redisdb.ping()" << std::endl;
    CryptRedisDb redisdb;
    setup(&redisdb);

    // no result
    int res = redisdb.ping();
    std::cerr << "=> status " << CryptRedisResult::statusString(res) << std::endl;
    assert(res == CryptRedisResult::Ok);

    // result
    CryptRedisResult result;
    res = redisdb.ping(&result);
    std::cerr << "=> status " << CryptRedisResult::statusString(res) << std::endl;
    std::cerr << "=> status " << result.statusString() << std::endl;
    std::cerr << "=> result " << result.toString() << std::endl;
    assert(res == CryptRedisResult::Ok);
    assert(strncmp(result.statusString().data(), "CryptRedisResult::Ok", 4) == 0);
    assert(strncmp(result.toString().data(), "PONG", 4) == 0);

    teardown(&redisdb);
    std::cerr << "==> end test redisdb.ping()" << std::endl;
}

void
test_exists()
{
    std::cerr << "==> begin test redisdb.exists()" << std::endl;
    CryptRedisDb redisdb;
    setup(&redisdb);
    std::string key = "foo_" + saltstr();
    assert(CryptRedisResult::Ok == redisdb.set(key, "bar"));

    // no result
    int res = redisdb.exists(key);
    std::cerr << "=> key " << key << std::endl;
    std::cerr << "=> status " << CryptRedisResult::statusString(res) << std::endl;
    assert(res == CryptRedisResult::Ok);

    // result
    CryptRedisResult result;
    res = redisdb.exists(key, &result);
    std::cerr << "=> status " << CryptRedisResult::statusString(res) << std::endl;
    std::cerr << "=> status " << result.statusString() << std::endl;
    std::cerr << "=> result " << result.toInteger() << std::endl;
    assert(res == CryptRedisResult::Ok);
    assert(strncmp(result.statusString().data(), "CryptRedisResult::Ok", 4) == 0);
    assert(result.toInteger() == 1);

    // cleanup
    assert(CryptRedisResult::Ok == redisdb.del(key));
    teardown(&redisdb);
    std::cerr << "==> end test redisdb.exists()" << std::endl;
}

void
test_del()
{
    std::cerr << "==> begin test redisdb.del()" << std::endl;
    CryptRedisDb redisdb;
    setup(&redisdb);
    std::string key = "foo_" + saltstr();
    assert(CryptRedisResult::Ok == redisdb.set(key, "bar"));
    assert(CryptRedisResult::Ok == redisdb.exists(key));
    std::cerr << "=> key " << key << std::endl;

    // result
    int res = redisdb.del(key);
    std::cerr << "=> status " << CryptRedisResult::statusString(res) << std::endl;
    assert(res == CryptRedisResult::Ok);

    teardown(&redisdb);
    std::cerr << "==> end test redisdb.del()" << std::endl;
}

int
main(void)
{
    // setup
    CryptRedisDb redisdb;
    redisdb.setHost("127.0.0.1");
    redisdb.setPort(6379);

    std::cerr << "==> begin test redisdb.open()" << std::endl;
    assert(redisdb.open());
    assert(redisdb.connected());
    std::cerr << "==> end test redisdb.open()" << std::endl;

#define KEY "foo"
#define VAL "bar"

    // use case (set command)
    std::cerr << "==> begin test redisdb.set()" << std::endl;
    int res = redisdb.set(KEY, VAL);
    std::cerr << "=> result " << CryptRedisResult::statusString(res) << std::endl;
    assert(res == CryptRedisResult::Ok);
    std::cerr << "==> end test redisdb.set()" << std::endl;
    
    // use case (get command)
    std::cerr << "==> begin test redisdb.get()" << std::endl;
    CryptRedisResult result;
    redisdb.get(KEY, &result);
    std::cerr << "=> result " << result.statusString() << std::endl;
    std::cerr << "=> type " << result.type() << std::endl;
    std::cerr << "=> value " << result.toString() << std::endl;
    assert(result.status() == CryptRedisResult::Ok);
    assert(result.type() == CryptRedisResult::String);
    assert(strncmp(VAL, result.toString().data(), strlen(VAL)) == 0);
    std::cerr << "==> end test redisdb.get()" << std::endl;

    // cleanup
    assert(CryptRedisResult::Ok == redisdb.del(KEY));
#undef KEY
#undef VAL

    // close
    std::cerr << "==> begin test redisdb.close()" << std::endl;
    redisdb.close();
    assert(!redisdb.connected());
    std::cerr << "==> end test redisdb.close()" << std::endl;

    test_ping();
    test_exists();
    test_del();

    return 0;

    // XXX
#if 0
    // use case (get command)
    CryptRedisResultSet resultset;
    std::vector<std::string> keys;
    keys.push_back("keya");
    keys.push_back("keyb");
    keys.push_back("keyc");
    redisdb.mget(keys, &resultset);

    //std::cerr << "result status" << resultset.statusString();
    for (auto entry : resultset) {
        std::cerr << entry.toString() << std::endl;
        std::cerr << entry.toInteger() << std::endl;
    }

    // use case (check crypto)
    // - set step
    // - get step
#endif
}
