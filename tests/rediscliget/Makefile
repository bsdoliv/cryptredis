# Copyright (c) 2013 Andre de Oliveira <deoliveirambx@googlemail.com>
# All rights reserved.
#
# Permission to use, copy, modify, and distribute this software for any purpose
# with or without fee is hereby granted, provided that the above copyright
# notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

PROG=		get

.PATH:		${.CURDIR}/..
SRCS=		rediscliget.cpp

CPPFLAGS+=	-ggdb3
LDADD+=		-lstdc++
LDADD+=		${.CURDIR}/../../lib/libcryptredis.a

run: .PHONY
	CRYPTREDISKEY=41d962ad5479795a10de0a369dea3b1e ${.CURDIR}/${PROG} \
		      $${key}

.include "${.CURDIR}/../perf.mk"
.include <bsd.prog.mk>

# vim: set ts=8 sw=8 noet:
