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

#ifndef CRYPTREDIS_H
#define CRYPTREDIS_H

#include <string>
#include <list>
#include <vector>

#if 1
#define CRPTRDS_NAMESPACE CrptRds
#define CRPTRDS_USE_NAMESPACE using namespace ::CRPTRDS_NAMESPACE;
#define CRPTRDS_BEGIN_NAMESPACE namespace CRPTRDS_NAMESPACE {
#define CRPTRDS_END_NAMESPACE }

CRPTRDS_BEGIN_NAMESPACE
#endif

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

    void setCryptEnabled(bool);
    bool cryptEnabled();

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
