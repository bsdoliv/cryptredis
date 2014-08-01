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
        explicit_bzero(blkbuf, sizeof(blkbuf));
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
        explicit_bzero(deciph_buf, bufsiz);
        explicit_bzero(ciphrd_buf, bufsiz);
        size_t declen = cryptredis_decode(str, ciphrd_buf, bufsiz);
        cryptredis_decrypt(cryptkey, ciphrd_buf, deciph_buf, declen);
        str = deciph_buf;
        len = strlen(str);
    }

    switch (redisrpl->type) {
    case REDIS_REPLY_ERROR:
        rpl->setStatus(CryptRedisResult::Fail);
        if (0)
            /* FALLTHROUGH */
    case REDIS_REPLY_STATUS:
    case REDIS_REPLY_STRING:
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
    if (! d->checkConnect(reply))
        return CryptRedisResult::Fail;

    const char *data = value.data();
    if (d->crypt_enabled) {
        explicit_bzero(d->deciph_buf, d->bufsiz);
        explicit_bzero(d->ciphrd_buf, d->bufsiz);
        size_t buflen = cryptredis_align64(value.size());
        cryptredis_encrypt(d->cryptkey, value.data(), d->ciphrd_buf, buflen);
        cryptredis_encode(d->deciph_buf, cryptredis_encsiz(buflen),
                          d->ciphrd_buf, buflen);
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
    if (!enable) {
        if (d->ciphrd_buf) {
            free(d->ciphrd_buf);
            d->ciphrd_buf = NULL;
        }
        if (d->deciph_buf) {
            free(d->deciph_buf);
            d->deciph_buf = NULL;
        }
        return (0);
    }

    if (resetKey() == -1)
        return (-1);

    d->bufsiz = CRYPTREDIS_MAXSIZBUF;
    d->ciphrd_buf = (u_int32_t *)calloc(1, d->bufsiz);
    d->deciph_buf = (char *)calloc(1, d->bufsiz);

    if (d->ciphrd_buf == NULL || d->deciph_buf == NULL) {
        d->last_error = "could not allocate crypto buffers";
        return (-1);
    }

    d->crypt_enabled = true;
    return (0);
}

bool
CryptRedisDb::cryptEnabled()
{ return d->crypt_enabled; }

CRPTRDS_END_NAMESPACE

// vim: set ts=4 sw=4 et ai:
