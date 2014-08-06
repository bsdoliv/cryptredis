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
	string		data_s;
	long long	data_i;
	int		type;
	int		size;
	int		status;
};

CryptRedisResult::CryptRedisResult() :
	d(new CryptRedisResultPrivate)
{
	clear();
}

CryptRedisResult::~CryptRedisResult()
{
	delete d;
}

void
CryptRedisResult::setData(const string &data)
{
	d->data_s = data;
}

string
CryptRedisResult::toString() const
{
	return (d->data_s);
}

void
CryptRedisResult::setData(long long data)
{
	d->data_i = data;
}

int
CryptRedisResult::toInteger() const
{
	return (d->data_i);
}

void
CryptRedisResult::setType(int t)
{
	d->type = t;
}

int
CryptRedisResult::type() const
{
	return (d->type);
}

void
CryptRedisResult::setSize(int s)
{
	d->size = s;
}

int
CryptRedisResult::size() const
{
	return (d->size);
}

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
{
	d->status = s;
}

int
CryptRedisResult::status()
{
	return (d->status);
}

string
CryptRedisResult::errorString()
{
	return (d->data_s);
}

string
CryptRedisResult::statusString()
{
	switch (d->status) {
	case CryptRedisResult::Ok:
		return ("CryptRedisResult::Ok");
	case CryptRedisResult::Fail:
		return ("CryptRedisResult::Fail");
	default:
		return ("No such status");
	}
}

CRPTRDS_END_NAMESPACE
