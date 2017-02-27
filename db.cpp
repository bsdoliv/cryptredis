/*
 * Copyright (c) 2013-2016 Andre de Oliveira <deoliveirambx@googlemail.com>
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
#include "cryptredisxx.h"

CRPTRDS_BEGIN_NAMESPACE

struct CryptRedisDbPrivate {
	struct cryptredis	*cryptredis;
	string			 host;
	int			 port;
	string			 errmsg;

	void buildReply(CryptRedisResult *);
};

void 
CryptRedisDbPrivate::buildReply(CryptRedisResult *rpl)
{
	int type;

	rpl->invalidate();

	type = cryptredis_response_type(cryptredis);
	rpl->setStatus(CryptRedisResult::Ok);
	rpl->setType(cryptredis_response_type(cryptredis));

	switch (type) {
	case REDIS_REPLY_ERROR:
		rpl->setStatus(CryptRedisResult::Fail);
		/* FALLTHROUGH */
	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_STRING:
		rpl->setData(cryptredis_response_string(cryptredis));
		break;
		break;
	case REDIS_REPLY_ARRAY:
		// TODO
		break;
	}

	cryptredis_response_free(cryptredis);
}

bool
CryptRedisDb::open(const string &h, int p)
{
	setHost("localhost");
	setPort(6379);

	if (!h.empty())
		setHost(h);

	if (p > 0)
		setPort(p);

	if ((d->cryptredis = cryptredis_open(d->host.data(), d->port)) == NULL)
		return (false);

	return (d->cryptredis->cr_connected);
}

void 
CryptRedisDb::close()
{
	if (d->cryptredis) {
		cryptredis_close(d->cryptredis);
		d->cryptredis = NULL;
	}
}

CryptRedisDb::CryptRedisDb() :
	d(new CryptRedisDbPrivate)
{
	d->port = -1;
	d->cryptredis = NULL;
}

CryptRedisDb::~CryptRedisDb()
{
	if (d->cryptredis && d->cryptredis->cr_crypt_enabled)
		setCryptEnabled(false);
	close();
	delete d;
}

bool CryptRedisDb::connected()
{
	if (d->cryptredis && d->cryptredis->cr_connected)
		return (true);

	return (false);
}

CryptRedisResult
CryptRedisDb::get(const string &key)
{
	CryptRedisResult	 res;

	cryptredis_get_r(d->cryptredis, key.data());

	d->buildReply(&res);
	return (res);
}

void 
CryptRedisDb::get(const string &key, CryptRedisResult *reply)
{
	if (cryptredis_get_r(d->cryptredis, key.data()) == -1)
		return;

	d->buildReply(reply);
}

int
CryptRedisDb::set(const string &key, const string &value,
	CryptRedisResult *reply)
{
	int res;

	res = cryptredis_set_r(d->cryptredis, key.data(), value.data());

	if (reply) {
		d->buildReply(reply);
		reply->setData(res);
	}

	return (res);
}

int
CryptRedisDb::exists(const string &key, CryptRedisResult *reply)
{
	int res;

	res = cryptredis_exists_r(d->cryptredis, key.data());

	if (reply) {
		d->buildReply(reply);
		if (!res)
			reply->setData(1);
	}

	return (res);
}

int
CryptRedisDb::ping(CryptRedisResult *reply)
{
	int res;

	res = cryptredis_ping_r(d->cryptredis);

	if (reply) {
		d->buildReply(reply);
		reply->setData(res);
	}

	return (res);
}

int
CryptRedisDb::del(const string &key, CryptRedisResult *reply)
{
	int res;

	res = cryptredis_del_r(d->cryptredis, key.data());

	if (reply) {
		d->buildReply(reply);
		reply->setData(res);
	}

	return (res);
}

void
CryptRedisDb::setHost(const string &h)
{
	d->host = h;
}

void
CryptRedisDb::setPort(int p)
{
	d->port = p;
}

int
CryptRedisDb::resetKey()
{
	return (cryptredis_config_encrypt(d->cryptredis, cryptEnabled() ? 1 :
	    0));
}

int
CryptRedisDb::setCryptEnabled(bool enable)
{
	int res;

	if ((res = cryptredis_config_encrypt(d->cryptredis, enable ? 1 : 0)) ==
	    -1)
		d->errmsg = "CRYPTREDIS_KEYFILE environment variable not set";

	return (res);
}

bool
CryptRedisDb::cryptEnabled()
{
	return (d->cryptredis->cr_crypt_enabled);
}

string
CryptRedisDb::lastError()
{
	return (d->errmsg);
}

CRPTRDS_END_NAMESPACE
