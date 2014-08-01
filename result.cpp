/*
 * Copyright (c) 2013 Andre de Oliveira <deoliveirambx@googlemail.com>
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
 *      This product includes software developed by Andre de Oliveira.
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

#include "hiredis/hiredis.h"
#include "cryptredis.h"

CRPTRDS_BEGIN_NAMESPACE

const int CryptRedisResult::Status  = REDIS_REPLY_STATUS;
const int CryptRedisResult::Error   = REDIS_REPLY_ERROR;
const int CryptRedisResult::Integer = REDIS_REPLY_INTEGER;
const int CryptRedisResult::Nil     = REDIS_REPLY_NIL;
const int CryptRedisResult::String  = REDIS_REPLY_STRING;
const int CryptRedisResult::Array   = REDIS_REPLY_ARRAY;

struct CryptRedisResultPrivate {
    std::string data_s;
    long long data_i;
    int type;
    int size;
    int status;
};

CryptRedisResult::CryptRedisResult() :
    d(new CryptRedisResultPrivate) 
{ 
    clear();
}

CryptRedisResult::~CryptRedisResult()
{ delete d; }

void 
CryptRedisResult::setData(const std::string &data) 
{ d->data_s = data; }

std::string 
CryptRedisResult::toString() const 
{ return d->data_s; }

void 
CryptRedisResult::setData(long long data) 
{ d->data_i = data; }

int 
CryptRedisResult::toInteger() const 
{ return d->data_i; }

void 
CryptRedisResult::setType(int t) 
{ d->type = t; }

int 
CryptRedisResult::type() const 
{ return d->type; }

void 
CryptRedisResult::setSize(int s) 
{ d->size = s; }

int 
CryptRedisResult::size() const 
{ return d->size; }

void 
CryptRedisResult::clear()
{
    d->size = 0;
    d->data_i = -1;
    d->type = Nil;
    d->data_s.clear();
    d->status = CryptRedisResult::Fail;
}

void
CryptRedisResult::setStatus(int s)
{ d->status = s; }

int
CryptRedisResult::status()
{ return d->status; }

std::string
CryptRedisResult::errorString()
{ return d->data_s; }

std::string
CryptRedisResult::statusString()
{
    switch (d->status) {
    case CryptRedisResult::Ok:
        return "CryptRedisResult::Ok";
    case CryptRedisResult::Fail: 
        return "CryptRedisResult::Fail";
    default:
        return "No such status";
    }
}

CRPTRDS_END_NAMESPACE

// vim: set ts=4 sw=4 et ai:
