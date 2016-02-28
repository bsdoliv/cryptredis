/*
 * Copyright (c) 2013-2016 Andre de Oliveira <deoliveirambx@googlemail.com>
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

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

#include <iostream>

#include "hiredis/hiredis.h"
#include "bsd-crypt.h"
#include "cryptredis.h"
#include "encode.h"
#include "tools.h"

CRPTRDS_BEGIN_NAMESPACE

#if 0
#define DPRINTF fprintf
#else
#define DPRINTF(x...) do {} while (0)
#endif

struct CryptRedisDbPrivate {
	redisContext		*redis_context;
	bool			 redis_connected;
	string			 last_error;

	string			 host;
	int			 port;

	bool			 crypt_enabled;
	struct cryptredis_key	 crkey;

	void	buildReply(redisReply *, CryptRedisResult *, bool decrypt =
		    false);
	bool	checkConnect(CryptRedisResult *reply);
	bool	connect(const string &h, int p);
	int	setKey(const string &keyfilename);
	void	loadhexbin(void *, const char *, size_t);
};

void
CryptRedisDbPrivate::loadhexbin(void *pk, const char *value, size_t pksize)
{
	char	 	 tmpv[3];
	const char	*vp = value;
	u_int8_t	*pkp = (u_int8_t *)pk;
	int		 i;
	int		 vlen;

	vlen = strlen(value);

	for (i = 0; i < pksize; i++) {
		memset(tmpv, 0, sizeof(tmpv));
		memcpy(tmpv, vp, 2);
		pkp[i] = (u_int8_t)strtol(tmpv, (char **)NULL, 16);

		DPRINTF(stderr, "i %d tmpv %s pkp[i] %02x\n", i, tmpv, pkp[i]);

		if ((vlen -= 2) <= 0)
			break;

		vp += 2;
	}
}

bool
CryptRedisDbPrivate::checkConnect(CryptRedisResult *reply)
{
	if (!connect(host, port)) {
		if (reply)
			reply->invalidate();
		return (false);
	}
	return (true);
}

int
CryptRedisDbPrivate::setKey(const string &keyfilename)
{
	FILE		*stream;
	int	 	 i;
	char	 	 line[LINE_MAX], *kp, *vp;
	char		 tmpkey[LINE_MAX];

	if ((stream = fopen(keyfilename.data(), "r")) == NULL) {
		last_error = "fail to open file";
		last_error += keyfilename;
		std::cerr << last_error;
		return (-1);
	}

	/* no more than 3 lines */
	for (i = 0; i < 3; i++) {
		memset(line, 0, sizeof(line));
		if (fgets(line, LINE_MAX, stream) == NULL)
			break;
		if (strlen(line) == 0)
			break;
		kp = line;
		vp = strchr(kp, '=');

		if (vp == NULL)
			continue;

		if (*vp == '=') {
			*vp++ = '\0';
			vp += strspn(vp, " \t\r\n");
		} else {
			*vp++ = '\0';
		}

		if (vp == NULL)
			continue;

		kp[strcspn(kp, "\r\n\t ")] = '\0';
		vp[strcspn(vp, "\r\n\t ")] = '\0';

		DPRINTF(stderr, "key %s value %s\n", kp, vp);
		if (!strncmp(kp, "salt", 5)) {
			loadhexbin(crkey.salt, vp, sizeof(crkey.salt));
		} else if (!strncmp(kp, "key", 3)) {
			memcpy(tmpkey, vp, sizeof(tmpkey));
		} else if (!strncmp(kp, "iv", 2)) {
			loadhexbin(crkey.iv, vp, sizeof(crkey.iv));
		}

		kp = NULL;
		vp = NULL;
	}
	fclose(stream);

	pkcs5_pbkdf2(tmpkey, strlen(tmpkey), crkey.salt, sizeof(crkey.salt),
	    crkey.key, sizeof(crkey.key), 1000);

	return 0;
}

void 
CryptRedisDbPrivate::buildReply(redisReply *redisrpl, CryptRedisResult *rpl,
	bool decrypt)
{
	char		*bufs;
	u_int32_t	*buf;
	char		*str = redisrpl->str;
	size_t		 len = redisrpl->len, bufslen;

	if (!redisrpl) {
		rpl->invalidate();
		return;
	}

	if (decrypt && crypt_enabled) {
		if ((buf = (u_int32_t *)calloc(1, len)) == NULL)
			return;

		bufslen = cryptredis_decode(str, buf, len);

		if ((bufs = (char *)calloc(1, bufslen)) == NULL)
			return;

		cryptredis_decrypt(&crkey, buf, bufs, bufslen);

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

	freeReplyObject(redisrpl);
	if (decrypt && crypt_enabled) {
		free(buf);
		free(bufs);
	}
	redisrpl = 0;
}

bool 
CryptRedisDbPrivate::connect(const string &h, int p)
{
	if (redis_connected)
		return (redis_connected);

	redis_connected = false;
	redis_context = redisConnect(h.data(), p);
	
	if (!redis_context)
		return (false);

	if (redis_context && redis_context->err) {
		last_error = redis_context->errstr;
		redisFree(redis_context);
		redis_context = 0;
		return (false);
	}

	return (redis_connected = true);
}

bool
CryptRedisDb::open(const string &h, int p)
{
	if (! h.empty() && p > 0) {
		setHost(h);
		setPort(p);
	}
	return (d->connect(d->host, d->port));
}

void 
CryptRedisDb::close()
{
	if (d->redis_context) {
		redisFree(d->redis_context);
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
	explicit_bzero(&d->crkey, sizeof(d->crkey));
}

CryptRedisDb::~CryptRedisDb()
{
	if (d->crypt_enabled)
		setCryptEnabled(false);
	close();
	explicit_bzero(&d->crkey, sizeof(d->crkey));
	delete d;
}

bool CryptRedisDb::connected()
{
	return (d->redis_connected);
}

CryptRedisResult
CryptRedisDb::get(const string &key)
{
	CryptRedisResult	 res;
	redisReply		*redisrpl= 0;

	if (!d->checkConnect(&res))
		return (res);

	redisrpl = (redisReply *)redisCommand(d->redis_context, "GET %s",
	    key.c_str());

	d->buildReply(redisrpl, &res, true);
	return (res);
}

void 
CryptRedisDb::get(const string &key, CryptRedisResult *reply)
{
	redisReply	*redisrpl= 0;

	if (!d->checkConnect(reply))
		return;

	redisrpl = (redisReply *)redisCommand(d->redis_context, "GET %s",
	    key.c_str());

	d->buildReply(redisrpl, reply, true);
}

int
CryptRedisDb::set(const string &key, const string &value,
	CryptRedisResult *reply)
{
	char		*bufs;
	u_int32_t	*buf;
	const char	*data = value.data();
	size_t		 buflen = value.size(), bufslen;
	redisReply	*redisrpl = 0;

	if (! d->checkConnect(reply))
		return CryptRedisResult::Fail;

	if (d->crypt_enabled) {
		buflen = cryptredis_align64(buflen);
		bufslen = cryptredis_encsiz(buflen);

		if ((buf = (u_int32_t *)calloc(1, buflen)) == NULL)
			return CryptRedisResult::Fail;

		if ((bufs = (char *)calloc(1, bufslen)) == NULL)
			return CryptRedisResult::Fail;

		cryptredis_encrypt(&d->crkey, value.data(), buf, buflen);
		cryptredis_encode(bufs, bufslen, buf, buflen);
		data = bufs;
	}

	redisrpl = (redisReply *)redisCommand(d->redis_context, "SET %s %s",
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
	return (reply->status());
}

int
CryptRedisDb::exists(const string &key, CryptRedisResult *reply)
{
	redisReply	*redisrpl = 0;

	if (!d->checkConnect(reply))
		return CryptRedisResult::Fail;

	redisrpl = (redisReply *)redisCommand(d->redis_context, "EXISTS %s",
	    key.data());

	if (!reply) {
		CryptRedisResult res;
		d->buildReply(redisrpl, &res);
		return res.status();
	}

	d->buildReply(redisrpl, reply);
	return (reply->status());
}

int
CryptRedisDb::ping(CryptRedisResult *reply)
{
	redisReply	*redisrpl = 0;

	if (!d->checkConnect(reply))
		return (CryptRedisResult::Fail);

	redisrpl = (redisReply *)redisCommand(d->redis_context, "PING");

	if (!reply) {
		CryptRedisResult res;
		d->buildReply(redisrpl, &res);
		return (res.status());
	}

	d->buildReply(redisrpl, reply);
	return (reply->status());
}

int
CryptRedisDb::del(const string &key, CryptRedisResult *reply)
{
	redisReply	*redisrpl = 0;
	if (!d->checkConnect(reply))
		return (CryptRedisResult::Fail);

	redisrpl = (redisReply *)redisCommand(d->redis_context, "DEL %s",
	    key.data());

	if (!reply) {
		CryptRedisResult res;
		d->buildReply(redisrpl, &res);
		return (res.status());
	}

	d->buildReply(redisrpl, reply);
	return (reply->status());
}

string
CryptRedisDb::lastError()
{
	return (d->last_error);
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
	char *keyfile;

	if ((keyfile = getenv("CRYPTREDIS_KEYFILE")) == NULL) {
		d->last_error = "CRYPTREDIS_KEYFILE environment variable not "
		    "set";
		return (-1);
	}

	return (d->setKey(keyfile));
}

int
CryptRedisDb::setCryptEnabled(bool enable)
{
	d->crypt_enabled = false;
	explicit_bzero(&d->crkey, sizeof(d->crkey));

	if (!enable)
		return (0);

	if (resetKey() == -1)
		return (-1);

	d->crypt_enabled = true;
	return (0);
}

bool
CryptRedisDb::cryptEnabled()
{
	return (d->crypt_enabled);
}

CRPTRDS_END_NAMESPACE
