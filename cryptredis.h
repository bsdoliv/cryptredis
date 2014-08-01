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

#ifndef CRYPTREDIS_H
#define CRYPTREDIS_H

#include <string>
#include <list>
#include <vector>

#define CRPTRDS_NAMESPACE CrptRds
#define CRPTRDS_USE_NAMESPACE using namespace ::CRPTRDS_NAMESPACE;
#define CRPTRDS_BEGIN_NAMESPACE namespace CRPTRDS_NAMESPACE {
#define CRPTRDS_END_NAMESPACE }

CRPTRDS_BEGIN_NAMESPACE

class CryptRedisResultPrivate;
class CryptRedisResult
{
public:
    // hiredis mimic type codes
    static const int Status;
    static const int Error;
    static const int Integer;
    static const int Nil;
    static const int String;
    static const int Array;

    // status codes
    enum {
        Ok = 0,
        Fail = -1 
    };

    explicit CryptRedisResult();
    virtual ~CryptRedisResult();

    void setStatus(int d);
    int status();
    std::string statusString();
    static inline std::string statusString(int s)
    {
        CryptRedisResult r;
        r.setStatus(s);
        return r.statusString();
    };

    int error();
    std::string errorString();

    void setData(const std::string &d);
    void setData(long long d);

    std::string toString() const;
    int toInteger() const;

    void setType(int t);
    int type() const;

    void setSize(int s);
    int size() const;
    void invalidate() {  clear(); };
    void clear();

private:
    CryptRedisResultPrivate *d;
};

class CryptRedisResultSet : public std::list<CryptRedisResult> 
{
public:
    std::string statusString() { };
};

class CryptRedisDbPrivate;
class CryptRedisDb
{
public:
    explicit CryptRedisDb();
    virtual ~CryptRedisDb();

    void setHost(const std::string &h);
    std::string host();
    void setPort(int p);
    int port();

    bool open(const std::string &h = std::string(), int p = -1);
    void close();
    bool connected();

    int setCryptEnabled(bool);
    bool cryptEnabled();
    int resetKey();

    // Redis commands
    void get(const std::string &k, CryptRedisResult *rpl);
    CryptRedisResult get(const std::string &k);
    void mget(const std::vector<std::string> &keys,
              CryptRedisResultSet *rpl) { return; };
    int set(const std::string &k, const std::string &v,
             CryptRedisResult *rpl = 0);
    int del(const std::string &k, CryptRedisResult *rpl = 0);
    int exists(const std::string &k, CryptRedisResult *rpl = 0);
    int ping(CryptRedisResult *rpl = 0);

    std::string lastError();

private:
    CryptRedisDbPrivate *d;
};

#define CRYPTREDIS_MAXSIZBUF (8192 * 1024)

CRPTRDS_END_NAMESPACE

namespace CRPTRDS_NAMESPACE {}
CRPTRDS_USE_NAMESPACE

#endif //! CRYPTREDIS_H
// vim: set ts=4 sw=4 et:
