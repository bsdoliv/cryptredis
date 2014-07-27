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

SUBDIR=		cryptread
SUBDIR+=	cryptwrite
SUBDIR+=	cryptregress
SUBDIR+=	api
SUBDIR+=	rediscliget
SUBDIR+=	rediscliset

TESTS=		api/apitest
TESTS+=		cryptregress/regress
TESTS+=		"cryptwrite/cryptwrite.sh 8"
TESTS+=		cryptread/cryptread.sh
TESTS+=		"cryptwrite/cryptwrite.sh 16"
TESTS+=		cryptread/cryptread.sh
#TESTS+=	"cryptwrite/cryptwrite.sh 8mb"
TESTS+=		cryptread/cryptread.sh

run: .PHONY
	@for t in ${TESTS}; do \
		printf "=> running %s %s" $${t}; \
		eval ./$${t} >/dev/null 2>&1; \
		if [ $$? = 0 ]; then \
			printf " success"; \
		else \
			printf " fail"; \
		fi; \
		printf "\n"; \
	done

run-exectests:
	cd ${.CURDIR}/rediscliset && ${.MAKE} run key="foo" value="bar"
	cd ${.CURDIR}/rediscliget && ${.MAKE} run key="foo"

run-perftests: .PHONY
	cd ${.CURDIR}/rediscliset && ${.MAKE} run-perftests
	cd ${.CURDIR}/rediscliget && ${.MAKE} run-perftests

.include <bsd.subdir.mk>
