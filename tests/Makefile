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
#SUBDIR+=	cryptwrite
#SUBDIR+=	cryptregress
SUBDIR+=	api
SUBDIR+=	apicrypt_nokey
SUBDIR+=	apicrypt
SUBDIR+=	rediscliget
SUBDIR+=	rediscliset

TESTS=		api/apitest
TESTS+=		apicrypt/apicrypttest
TESTS+=		apicrypt_nokey/apicrypt_nokeytest
#TESTS+=		cryptregress/regress
#TESTS+=		"cryptwrite/cryptwrite.sh 8"
#TESTS+=		cryptread/cryptread.sh
#TESTS+=		"cryptwrite/cryptwrite.sh 16"
#TESTS+=		cryptread/cryptread.sh
#TESTS+=		"cryptwrite/cryptwrite.sh 8kb"
#TESTS+=		cryptread/cryptread.sh
#TESTS+=		"cryptwrite/cryptwrite.sh 8mb"
#TESTS+=		cryptread/cryptread.sh
TESTS+=		"make run-exectests"

run: .PHONY
	@for t in ${TESTS}; do \
		printf "=> running %s %s" $${t}; \
		${MAKE} test.key 2>/dev/null >/dev/null; \
		eval $${t} >regress.log 2>&1; \
		if [ $$? = 0 ]; then \
			printf " success"; \
		else \
			printf " fail"; \
		fi; \
		printf "\n"; \
	done

test.key:
	openssl enc -aes-256-cbc -k "" -P -md sha512 > ${.TARGET}

run-exectests:
	cd ${.CURDIR}/rediscliset && ${.MAKE} run key="foo" value="bar"
	cd ${.CURDIR}/rediscliget && ${.MAKE} run key="foo"
	redis-cli del foo

run-perftests: .PHONY
	cd ${.CURDIR}/rediscliset && ${.MAKE} run-perftests
	cd ${.CURDIR}/rediscliget && ${.MAKE} run-perftests

CLEANFILES+=	*.core regress.log test.key

.include <bsd.prog.mk>
.include <bsd.subdir.mk>
