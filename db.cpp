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
        explicit_bzero(blkbuf, sizeof(blkbuf));
        snprintf(blkbuf, BLKSIZ, "0x%s", p);
        *pk = (u_int32_t)strtol(blkbuf, (char **)NULL, 16);
        p +=  BLKSIZ;
    }
#   undef BLKSIZ
}

void 
CryptRedisDbPrivate::buildReply(::redisReply *redisrpl, CryptRedisResult *rpl,
    bool decrypt)
{
    char        *bufs;
    u_int32_t   *buf;
    char        *str = redisrpl->str;
    size_t       len = redisrpl->len, chlen;

    if (!redisrpl) {
        rpl->invalidate();
        return;
    }

    if (decrypt && crypt_enabled) {
        len = cryptredis_encsiz(len);
        if ((buf = (u_int32_t *)calloc(1, len)) == NULL)
            return;

        chlen = cryptredis_decode(str, buf, len);

        if ((bufs = (char *)calloc(1, chlen)) == NULL)
            return;

        cryptredis_decrypt(cryptkey, buf, bufs, chlen);

        str = bufs;
        len = strlen(str);
    }

    switch (redisrpl->type) {
    case REDIS_REPLY_ERROR:
        rpl->setStatus(CryptRedisResult::Fail);
        /* FALLTHROUGH */
    case REDIS_REPLY_STATUS:
    case REDIS_REPLY_STRING:
        if (redisrpl->type != REDIS_REPLY_ERROR)
            rpl->setStatus(CryptRedisResult::Ok);
        rpl->setData(str);
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
    if (decrypt && crypt_enabled) {
        free(buf);
        free(bufs);
    }
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
    if (d->crypt_enabled)
        setCryptEnabled(false);
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
    char        *bufs;
    u_int32_t   *buf;
    const char  *data = value.data();
    size_t       chlen, buflen = value.size();

    if (! d->checkConnect(reply))
        return CryptRedisResult::Fail;

    if (d->crypt_enabled) {
        buflen = cryptredis_align64(buflen);
        chlen = cryptredis_encsiz(buflen);

        if ((buf = (u_int32_t *)calloc(1, buflen)) == NULL)
            return CryptRedisResult::Fail;

        if ((bufs = (char *)calloc(1, chlen)) == NULL)
            return CryptRedisResult::Fail;

        cryptredis_encrypt(d->cryptkey, value.data(), buf, buflen);
        cryptredis_encode(bufs, chlen, buf, buflen);
        data = bufs;
    }

    ::redisReply *redisrpl = 0;
    redisrpl = (::redisReply *)::redisCommand(d->redis_context, "SET %s %s",
        key.data(), data);

    if (!reply) {
        CryptRedisResult res;
        d->buildReply(redisrpl, &res);
        return res.status();
    }
    if (d->crypt_enabled) {
        free(buf);
        free(bufs);
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

int
CryptRedisDb::resetKey()
{
    char *keystr = getenv("CRYPTREDISKEY");

    if (keystr == NULL) {
        d->last_error = "invalid key";
        return (-1);
    } else if ((strlen(keystr) < (KEY_SIZE * sizeof(u_int32_t)))) {
        d->last_error = "key is too small (less than 128bits)";
        return (-1);
    }
    d->setKey(keystr);
}

int
CryptRedisDb::setCryptEnabled(bool enable)
{
    explicit_bzero(d->cryptkey, sizeof(d->cryptkey));
    d->crypt_enabled = false;
    if (!enable)
        return (0);

    if (resetKey() == -1)
        return (-1);

    d->crypt_enabled = true;
    return (0);
}

bool
CryptRedisDb::cryptEnabled()
{ return d->crypt_enabled; }

CRPTRDS_END_NAMESPACE

// vim: set ts=4 sw=4 et ai:
