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

#include <sys/param.h>

#include <string.h>

#include "hiredis/hiredis.h"
#include "bsd-crypt.h"
#include "cryptredis.h"
#include "encode.h"
#include "tools.h"

CRPTRDS_BEGIN_NAMESPACE

struct CryptRedisDbPrivate {
    ::redisContext  *redis_context;
    bool            redis_connected;
    std::string     last_error;

    std::string     host;
    int             port;

    bool            crypt_enabled;
    rediscrypt_key_t cryptkey[KEY_SIZE];
    // crypt support buffers
    char            *deciph_buf;
    u_int32_t       *ciphrd_buf;
    size_t          bufsiz;

    void buildReply(::redisReply *, CryptRedisResult *,
                    bool decrypt = false);
    bool checkConnect(CryptRedisResult *reply);
    bool connect(const std::string &h, int p);
    void setKey(const std::string &keystr);
};

bool
CryptRedisDbPrivate::checkConnect(CryptRedisResult *reply)
{
    if (! connect(host, port)) {
        if (reply)
            reply->invalidate();
        return false;
    }
    return true;
}

void 
CryptRedisDbPrivate::setKey(const std::string &keystr)
{
    const char *p = keystr.data();
    u_int32_t *pk = cryptkey;
#   define BLKSIZ (sizeof(u_int32_t) * 2) /* each byte represented 
                                             by 2 chars */
    char blkbuf[BLKSIZ];
    for (int i = 0; i < KEY_SIZE; i++) {
        bzero(blkbuf, BLKSIZ);
        snprintf(blkbuf, BLKSIZ, "0x%s", p);
        *pk = (u_int32_t)strtol(blkbuf, (char **)NULL, 16);
        p +=  BLKSIZ;
    }
#   undef BLKSIZ
}

void 
CryptRedisDbPrivate::buildReply(::redisReply *redisrpl,
                                CryptRedisResult *rpl,
                                bool decrypt)
{
    if (! redisrpl) {
        rpl->invalidate();
        return;
    }

    char *str = redisrpl->str;
    size_t len = redisrpl->len;
    if (decrypt && crypt_enabled) {
        bzero(deciph_buf, bufsiz);
        bzero(ciphrd_buf, bufsiz);
        size_t declen = cryptredis_decode(str, ciphrd_buf);
        cryptredis_decrypt(cryptkey, ciphrd_buf,
                           deciph_buf, declen);
        str = deciph_buf;
        len = strlen(str);
    }

    switch (redisrpl->type) {
    case REDIS_REPLY_ERROR:
        rpl->setData(str);
        rpl->setStatus(CryptRedisResult::Fail);
        break;
    case REDIS_REPLY_STATUS:
    case REDIS_REPLY_STRING:
        rpl->setData(str);
        rpl->setStatus(CryptRedisResult::Ok);
        break;
    case REDIS_REPLY_INTEGER:
        rpl->setData(redisrpl->integer);
        rpl->setStatus(CryptRedisResult::Ok);
        break;
    case REDIS_REPLY_ARRAY:
        // TODO
        break;
    }

    rpl->setSize(len);
    rpl->setType(redisrpl->type);

    ::freeReplyObject(redisrpl);
    redisrpl = 0;
}

bool 
CryptRedisDbPrivate::connect(const std::string &h, int p)
{
    if (redis_connected)
        return redis_connected;

    redis_connected = false;
    redis_context = ::redisConnect(h.data(), p);
    
    if (! redis_context)
        return false;

    if (redis_context && redis_context->err) {
        last_error = redis_context->errstr;
        ::redisFree(redis_context);
        redis_context = 0;
        return false;
    }

    return (redis_connected = true);
}

bool
CryptRedisDb::open(const std::string &h, int p)
{
    if (! h.empty() && p > 0) {
        setHost(h);
        setPort(p);
    }
    return d->connect(d->host, d->port);
}

void 
CryptRedisDb::close()
{
    if (d->redis_context != 0) {
        ::redisFree(d->redis_context);
        d->redis_context = 0;
    }

    d->redis_connected = false;
}

CryptRedisDb::CryptRedisDb() :
    d(new CryptRedisDbPrivate)
{
    d->crypt_enabled = false;
    d->port = -1;
    d->redis_connected = false;
    d->redis_context = 0;
}

CryptRedisDb::~CryptRedisDb()
{
    close();
    delete d;
}  

bool CryptRedisDb::connected()
{
    return d->redis_connected;
}

CryptRedisResult
CryptRedisDb::get(const std::string &key)
{
    CryptRedisResult res;
    if (! d->checkConnect(&res))
        return res;

    ::redisReply *redisrpl= 0;
    redisrpl = (::redisReply *)::redisCommand(d->redis_context,
                                              "GET %s", 
                                              key.c_str());

    d->buildReply(redisrpl, &res, true);
    return res;
}

void 
CryptRedisDb::get(const std::string &key, CryptRedisResult *reply)
{
    if (! d->checkConnect(reply))
        return;

    ::redisReply *redisrpl= 0;
    redisrpl = (::redisReply *)::redisCommand(d->redis_context,
                                              "GET %s", 
                                              key.c_str());

    d->buildReply(redisrpl, reply, true);
}

int
CryptRedisDb::set(const std::string &key, const std::string &value,
                  CryptRedisResult *reply)
{
    if (! d->checkConnect(reply))
        return CryptRedisResult::Fail;

    const char *data = value.data();
    if (d->crypt_enabled) {
        bzero(d->deciph_buf, d->bufsiz);
        bzero(d->ciphrd_buf, d->bufsiz);
        size_t buflen = cryptredis_align64(value.size());
        cryptredis_encrypt(d->cryptkey, value.data(), d->ciphrd_buf,
                           buflen);
        cryptredis_encode(d->deciph_buf, d->ciphrd_buf, buflen);
        data = d->deciph_buf;
    }

    ::redisReply *redisrpl = 0;
    redisrpl = (::redisReply *)::redisCommand(d->redis_context,
                                              "SET %s %s",
                                              key.data(),
                                              data);

    if (! reply) {
        CryptRedisResult res;
        d->buildReply(redisrpl, &res);
        return res.status();
    }

    d->buildReply(redisrpl, reply);
    return reply->status();
}

int
CryptRedisDb::exists(const std::string &key, CryptRedisResult *reply)
{
    if (! d->checkConnect(reply))
        return CryptRedisResult::Fail;

    ::redisReply *redisrpl = 0;
    redisrpl = (::redisReply *)::redisCommand(d->redis_context,
                                              "EXISTS %s", 
                                              key.data());
    if (! reply) {
        CryptRedisResult res;
        d->buildReply(redisrpl, &res);
        return res.status();
    }

    d->buildReply(redisrpl, reply);
    return reply->status();
}

int
CryptRedisDb::ping(CryptRedisResult *reply)
{
    if (! d->checkConnect(reply))
        return CryptRedisResult::Fail;

    ::redisReply *redisrpl = 0;
    redisrpl = (::redisReply *)::redisCommand(d->redis_context, "PING");

    if (! reply) {
        CryptRedisResult res;
        d->buildReply(redisrpl, &res);
        return res.status();
    }

    d->buildReply(redisrpl, reply);
    return reply->status();
}

int
CryptRedisDb::del(const std::string &key, CryptRedisResult *reply)
{
    if (! d->checkConnect(reply))
        return CryptRedisResult::Fail;

    ::redisReply *redisrpl = 0;
    redisrpl = (::redisReply *)::redisCommand(d->redis_context,
                                              "DEL %s", 
                                              key.data());
    if (! reply) {
        CryptRedisResult res;
        d->buildReply(redisrpl, &res);
        return res.status();
    }

    d->buildReply(redisrpl, reply);
    return reply->status();
}

std::string
CryptRedisDb::lastError()
{ return d->last_error; }

void
CryptRedisDb::setHost(const std::string &h)
{ d->host = h; }

void
CryptRedisDb::setPort(int p)
{ d->port = p; }

void
CryptRedisDb::setCryptEnabled(bool b)
{
    memset(d->cryptkey, 0x0, sizeof(KEY_SIZE));
    d->crypt_enabled = false;
    if (!b)
        return;

    char *keystr = getenv("CRYPTREDISKEY");
    if (! keystr || (strlen(keystr) < (KEY_SIZE * sizeof(u_int32_t)))) {
        d->last_error = "key is too small (less than 128bits)";
        return;
    }

    d->setKey(keystr);

    d->bufsiz = CRYPTREDIS_MAXSIZBUF;
    d->ciphrd_buf = (u_int32_t *)malloc(d->bufsiz);
    d->deciph_buf = (char *)malloc(d->bufsiz);

    if (! d->ciphrd_buf ||
        ! d->deciph_buf) {
        d->last_error = "could not allocate crypto buffers";
        return;
    }

    d->crypt_enabled = true;
}

bool
CryptRedisDb::cryptEnabled()
{ return d->crypt_enabled; }

CRPTRDS_END_NAMESPACE

// vim: set ts=4 sw=4 et ai:
