/*
 * Copyright (c) 2013 Andre Oliveira <me@andreldoliveira.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Andre Oliveira.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>

#include <unistd.h>
#include <assert.h>
#include <string.h>

#include <iostream>

#include "cryptredis.h"
#include "encode.h"

std::string random_nstr()
{
    uint64_t random_value = ::rand() % 1000000;
    return std::to_string(random_value);
}

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
test_crypt()
{
    std::cerr << "==> begin test redisdb.setCryptEnabled()" << std::endl;
    CryptRedisDb redisdb;
    assert(redisdb.open("127.0.0.1", 6379));

    // test without key set, encrypt should fail
    redisdb.setCryptEnabled(true);
    assert(! redisdb.cryptEnabled());

    CryptRedisResult result;
    std::string key = "foo" + random_nstr();
    std::string value = "bar" + random_nstr();

    assert(CryptRedisResult::Ok == redisdb.set(key, value));
    redisdb.get(key, &result);
    std::cerr << "=> value " << value << std::endl;
    std::cerr << "=> result " << result.toString() << std::endl;
    assert(CryptRedisResult::Ok == result.status());
    assert(result.toString() == value);
    // cleanup
    assert(CryptRedisResult::Ok == redisdb.del(key));
    result.clear();

    // test with key properly set, encrypt should works
    assert(putenv((char *)"CRYPTREDISKEY=41d962ad5479795a10de0a369dea3b1e") == 0);
    redisdb.setCryptEnabled(true);
    assert(redisdb.cryptEnabled());

    assert(CryptRedisResult::Ok == redisdb.set(key, value));
    redisdb.get(key, &result);
    std::cerr << "=> value " << value << std::endl;
    std::cerr << "=> result " << result.toString() << std::endl;
    assert(CryptRedisResult::Ok == result.status());
    assert(result.toString() == value);
    
    /*
     * retrieve the same key, disabling encrypt, should receive a ciphered
     * buffer
     */
    redisdb.setCryptEnabled(false);
    assert(! redisdb.cryptEnabled());

    redisdb.get(key, &result);
    std::cerr << "=> value " << value << std::endl;
    std::cerr << "=> result " << result.toString() << std::endl;
    assert(CryptRedisResult::Ok == result.status());
    assert(result.toString() != value);
    size_t encsiz = cryptredis_encsiz(cryptredis_align64(value.size()));
    assert(result.toString().size() == encsiz);

    // cleanup
    assert(CryptRedisResult::Ok == redisdb.del(key));
    result.clear();
    assert(unsetenv((char *)"CRYPTREDISKEY") == 0);

    // test key too small
    assert(putenv((char *)"CRYPTREDISKEY=41d962ad547") == 0);
    redisdb.setCryptEnabled(true);
    assert(! redisdb.cryptEnabled());
    std::cerr << "=> lasterror() " << redisdb.lastError() << std::endl;
    assert(strncmp(redisdb.lastError().data(),
                   "key is too small (less than 128bits)",
                   redisdb.lastError().size()) == 0);

    // cleanup
    assert(unsetenv((char *)"CRYPTREDISKEY") == 0);
    redisdb.close();
    assert(!redisdb.connected());

    std::cerr << "==> end test redisdb.setCryptEnabled()" << std::endl;
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
    std::string key = "foo" + random_nstr();
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
    std::string key = "foo" + random_nstr();
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
    ::srand(::time(NULL) + ::getpid());
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
    test_crypt();

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
