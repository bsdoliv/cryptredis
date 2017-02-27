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

#ifndef CRYPTREDIS_H
#define CRYPTREDIS_H

#ifdef __cplusplus
extern "C" {
#endif

struct cryptredis {
	struct cryptredis_context	*cr_context;
	struct cryptredis_key		*cr_key;
	int				 cr_connected;
	int			 	 cr_crypt_enabled;
	uint32_t			 cr_flags;
};

struct cryptredis *
	 cryptredis_open(const char *, int);
int	 cryptredis_close(struct cryptredis *);
int	 cryptredis_config_encrypt(struct cryptredis *, int);

int	 cryptredis_set(const char *, const char *);
char	*cryptredis_get(const char *);

int	 cryptredis_set_r(struct cryptredis *, const char *, const char *);
int	 cryptredis_get_r(struct cryptredis *, const char *);
int	 cryptredis_ping_r(struct cryptredis *);
int	 cryptredis_exists_r(struct cryptredis *, const char *);
int	 cryptredis_del_r(struct cryptredis *, const char *);

const char
	*cryptredis_response_string(const struct cryptredis *);
int	 cryptredis_response_type(const struct cryptredis *);
void	 cryptredis_response_free(struct cryptredis *);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTREDIS_H */
