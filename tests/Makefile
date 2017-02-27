# Copyright (c) 2013-2016 Andre de Oliveira <deoliveirambx@googlemail.com>
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
SUBDIR+=	cryptredis_client_r

TESTS=		cryptredis_client_r
TESTS+=		api
TESTS+=		apicrypt
TESTS+=		apicrypt_nokey
#TESTS+=		cryptregress/regress
#TESTS+=		"cryptwrite/cryptwrite.sh 8"
#TESTS+=		cryptread/cryptread.sh
#TESTS+=		"cryptwrite/cryptwrite.sh 16"
#TESTS+=		cryptread/cryptread.sh
#TESTS+=		"cryptwrite/cryptwrite.sh 8kb"
#TESTS+=		cryptread/cryptread.sh
#TESTS+=		"cryptwrite/cryptwrite.sh 8mb"
#TESTS+=		cryptread/cryptread.sh
#TESTS+=		"make run-exectests"

run: .PHONY
	@for t in ${TESTS}; do \
		cd ${.CURDIR} && ${MAKE} test.key; \
		printf "=> running %s %s" $${t}; \
		cd ${.CURDIR}/$${t}/obj && eval $${t}; \
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

resetdb: .PHONY
	@echo 'keys *' | redis-cli | cut -d' ' -f2 |	\
		while read k; do			\
			redis-cli del "$k";		\
		done

CLEANFILES+=	*core regress.log test.key

.include <bsd.prog.mk>
.include <bsd.subdir.mk>
