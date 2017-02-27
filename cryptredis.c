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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <util.h>

#include "cryptredis.h"
#include "encode.h"
#include "bsd-crypt.h"
#include "hiredis/hiredis.h"

struct cryptredis_context {
	struct redisContext		*cc_hiredis_context;
#define hiredis_ctx			 cc_hiredis_context
#define hiredis_errnum			 cc_hiredis_context->err
#define hiredis_errstr			 cc_hiredis_context->errstr
	struct redisReply		*cc_hiredis_reply;
	int				 cc_errnum;
	char				 cc_errmsg[LINE_MAX];
};

static int	cryptredis_reset_key(struct cryptredis *);
static void	cryptredis_load_hexbin(void *pk, const char *, size_t);
static int	cryptredis_set_error(struct cryptredis *, const char *);

#if 0
#define DPRINTF fprintf
#else
#define DPRINTF(x...) do {} while (0)
#endif

struct cryptredis *
cryptredis_open(const char *host, int port)
{
	struct cryptredis *c;

	if ((c = calloc(1, sizeof(*c))) == NULL) {
		(void)fprintf(stderr, "%s: calloc %s\n", __func__,
		    strerror(errno));
		return (NULL);
	}

	if ((c->cr_context = calloc(1, sizeof(*(c->cr_context)))) == NULL) {
		(void)fprintf(stderr, "%s: calloc %s\n", __func__,
		    strerror(errno));
		goto err;
	}

	if ((c->cr_context->hiredis_ctx = redisConnect(host, port)) == NULL) {
		(void)fprintf(stderr, "%s: redisConnect\n", __func__);
		goto err;
	}

	if (c->cr_context->hiredis_errnum != REDIS_OK) {
		if (c->cr_context->hiredis_errnum == REDIS_ERR_IO)
			(void)fprintf(stderr, "%s: redisConnect %s\n",
			    __func__, strerror(errno));
		else
			(void)fprintf(stderr, "%s: redisConnect %d\n",
			    __func__, c->cr_context->hiredis_errnum);

		goto err;
	}

	c->cr_connected = 1;
	return (c);

 err:
	if (c->cr_context != NULL)
		free(c->cr_context);
	free(c);

	return (NULL);
}

int
cryptredis_close(struct cryptredis *cr)
{
	redisFree(cr->cr_context->hiredis_ctx);
	free(cr->cr_context);
	free(cr);
	cr = NULL;

	return (0);
}

int
cryptredis_config_encrypt(struct cryptredis *crp, int enable)
{
	crp->cr_crypt_enabled = 0;

	if (crp->cr_key != NULL) {
		free(crp->cr_key);
		crp->cr_key = NULL;
	}

	if (!enable)
		return (0);

	if (cryptredis_reset_key(crp) == -1) {
		(void)fprintf(stderr, "%s: cryptredis_reset_key\n", __func__);
		return (-1);
	}
	crp->cr_crypt_enabled = 1;

	return (0);
}

static int
cryptredis_reset_key(struct cryptredis *crp)
{
	char		*filenamep;
	FILE		*f;
	int	 	 i;
	char	 	 line[LINE_MAX], *kp, *vp;
	char		 tmpkey[LINE_MAX];
	struct cryptredis_key
			*ckp;
	int		 ret = -1;

	if ((filenamep = getenv("CRYPTREDIS_KEYFILE")) == NULL) {
		(void)fprintf(stderr, "%s: getenv\n", __func__);
		return (-1);
	}

	if ((f = fopen(filenamep, "r")) == NULL) {
		(void)fprintf(stderr, "%s: fopen %s\n", __func__, filenamep);
		return (-1);
	}

	if ((crp->cr_key = calloc(1, sizeof(*(crp->cr_key)))) == NULL) {
		(void)fprintf(stderr, "%s: calloc\n", __func__);
		goto err;
	}
	ckp = crp->cr_key;

	/* no more than 3 lines */
	for (i = 0; i < 3; i++) {
		memset(line, 0, sizeof(line));
		if (fgets(line, LINE_MAX, f) == NULL)
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

		DPRINTF(stderr, "%s: key %s value %s\n", __func__, kp, vp);
		if (!strncmp(kp, "salt", 5)) {
			cryptredis_load_hexbin(ckp->salt, vp,
			    sizeof(ckp->salt));
		} else if (!strncmp(kp, "key", 3)) {
			memcpy(tmpkey, vp, sizeof(tmpkey));
		} else if (!strncmp(kp, "iv", 2)) {
			cryptredis_load_hexbin(ckp->iv, vp,
			    sizeof(ckp->iv));
		}

		kp = NULL;
		vp = NULL;
	}

	if (bcrypt_pbkdf(tmpkey, strlen(tmpkey), ckp->salt, sizeof(ckp->salt),
	    ckp->key, sizeof(ckp->key), 16) == -1) {
		(void)fprintf(stderr, "%s: pkcs5_pbkdf2\n", __func__);
		goto err;
	}
	ret = 0;

 err:
	fclose(f);

	return (ret);
}

static void
cryptredis_load_hexbin(void *pk, const char *value, size_t pksize)
{
	char	 	 tmpv[3];
	const char	*vp = value;
	u_int8_t	*pkp = (u_int8_t *)pk;
	unsigned int	 i;
	int		 vlen;

	vlen = strlen(value);

	for (i = 0; i < pksize; i++) {
		memset(tmpv, 0, sizeof(tmpv));
		memcpy(tmpv, vp, 2);
		pkp[i] = (u_int8_t)strtol(tmpv, (char **)NULL, 16);

		DPRINTF(stderr, "%s: i %d tmpv %s pkp[i] %02x\n", __func__, i,
		    tmpv, pkp[i]);

		if ((vlen -= 2) <= 0)
			break;

		vp += 2;
	}
}

int
cryptredis_set_r(struct cryptredis *crp, const char *key, const char *value)
{
	char		*bufs;
	u_int32_t	*buf;
	const char	*data = value;
	size_t		 buflen, bufslen;
	struct cryptredis_context *cp = crp->cr_context;
	int		 ret = -1;

	buflen = strlen(value);
	if (crp->cr_crypt_enabled) {
		buflen = cryptredis_align64(buflen);
		bufslen = cryptredis_encsiz(buflen);

		if ((buf = (u_int32_t *)calloc(1, buflen)) == NULL) {
			(void)fprintf(stderr, "%s: calloc", __func__);
			return (-1);
		}

		if ((bufs = (char *)calloc(1, bufslen)) == NULL) {
			(void)fprintf(stderr, "%s: calloc", __func__);
			return (-1);
		}

		cryptredis_encrypt(crp->cr_key, data, buf, buflen);
		cryptredis_encode(bufs, bufslen, buf, buflen);
		data = bufs;
	}

	if ((cp->cc_hiredis_reply = redisCommand(cp->cc_hiredis_context, "SET "
	    "%s %s", key, data)) == NULL) {
		(void)fprintf(stderr, "%s: redisCommand", __func__);
		goto err;
	}

	ret = 0;

 err:
	if (crp->cr_crypt_enabled) {
		free(buf);
		free(bufs);
	}

	return (ret);
}

int
cryptredis_get_r(struct cryptredis *crp, const char *key)
{
	char		*bufs = NULL;
	u_int32_t	*buf = NULL;
	size_t		 bufslen;
	redisReply	*rreply = NULL;
	int		 ret = -1;

	if ((rreply = redisCommand(crp->cr_context->cc_hiredis_context, "GET "
	    "%s", key)) == NULL) {
		(void)fprintf(stderr, "%s: redisCommand\n", __func__);
		goto err;
	}
	
	if (crp->cr_crypt_enabled) { 
		if ((buf = (u_int32_t *)calloc(1, rreply->len)) == NULL) {
			(void)fprintf(stderr, "%s: calloc\n", __func__);
			goto err;
		}

		bufslen = cryptredis_decode(rreply->str, buf, rreply->len);

		if ((bufs = calloc(1, bufslen)) == NULL) {
			(void)fprintf(stderr, "%s: calloc\n", __func__);
			goto err;
		}

		cryptredis_decrypt(crp->cr_key, buf, bufs, bufslen);
		memset(rreply->str, 0, rreply->len);
		memcpy(rreply->str, bufs, bufslen);
		rreply->len = bufslen;
	}

	crp->cr_context->cc_hiredis_reply = rreply;
	ret = 0;

 err:
	if (ret == -1 && rreply)
		freeReplyObject(rreply);

	if (crp->cr_crypt_enabled) {
		if (buf)
			free(buf);
		if (bufs)
			free(bufs);
	}

	return (ret);
}

static int
cryptredis_set_error(struct cryptredis *crp, const char *errmsg)
{
	struct cryptredis_context *ccp = crp->cr_context;

	if (strlcpy(ccp->cc_errmsg, errmsg, sizeof(ccp->cc_errmsg)) == -1) {
		(void)fprintf(stderr, "%s: strlcpy truncated", __func__);
		return (-1);
	}
	ccp->cc_errnum = errno;
	return (0);
}

int
cryptredis_del_r(struct cryptredis *crp, const char *key)
{
	redisReply	*rreply = NULL;

	if ((rreply = redisCommand(crp->cr_context->cc_hiredis_context,
	    "DEL %s", key)) == NULL) {
		(void)fprintf(stderr, "%s: redisCommand\n", __func__);
		freeReplyObject(rreply);
		return (-1);
	}
	crp->cr_context->cc_hiredis_reply = rreply;

	return (0);
}

int
cryptredis_ping_r(struct cryptredis *crp)
{
	struct cryptredis_context *cp = crp->cr_context;

	if ((cp->cc_hiredis_reply = redisCommand(cp->cc_hiredis_context,
	    "PING")) == NULL) {
		(void)fprintf(stderr, "%s: redisCommand", __func__);
		return (-1);
	}

	DPRINTF(stderr, "%s: reply %s\n", __func__,
	    cp->cc_hiredis_reply->str);

	return (0);
}

int
cryptredis_exists_r(struct cryptredis *crp, const char *key)
{
	struct cryptredis_context *cp = crp->cr_context;

	if ((cp->cc_hiredis_reply = redisCommand(cp->cc_hiredis_context,
	    "EXISTS %s", key)) == NULL) {
		(void)fprintf(stderr, "%s: redisCommand", __func__);
		return (-1);
	}

	DPRINTF(stderr, "%s: %s\n", __func__,
	    crp->cr_context->cc_hiredis_reply->str);

	return (0);
}

const char *
cryptredis_response_string(const struct cryptredis *crp)
{
	if (crp->cr_context->cc_hiredis_reply != NULL)
		return (crp->cr_context->cc_hiredis_reply->str);

	return (NULL);
}

void
cryptredis_response_free(struct cryptredis *crp)
{
	switch (crp->cr_context->cc_hiredis_reply->type) {
	case REDIS_REPLY_ARRAY:
		/* TODO */
		break;
	}
	freeReplyObject(crp->cr_context->cc_hiredis_reply);
	crp->cr_context->cc_hiredis_reply = NULL;
}

int
cryptredis_response_type(const struct cryptredis *crp)
{
	return (crp->cr_context->cc_hiredis_reply->type);
}
