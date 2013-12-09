# Copyright (c) 2013 Andre Oliveira <me@andreldoliveira.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#      This product includes software developed by Andre Oliveira.
# 4. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SUBDIR= cryptread
SUBDIR+= cryptwrite
SUBDIR+= cryptregress
SUBDIR+= api
SUBDIR+= rediscliget
SUBDIR+= rediscliset

TESTS= api/apitest
TESTS+= cryptregress/regress
TESTS+= "cryptwrite/cryptwrite.sh 8"
TESTS+= cryptread/cryptread.sh
TESTS+= "cryptwrite/cryptwrite.sh 16"
TESTS+= cryptread/cryptread.sh
TESTS+= "cryptwrite/cryptwrite.sh 8mb"
TESTS+= cryptread/cryptread.sh

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
	cd rediscliset && ${.MAKE} run key="foo" value="bar"
	cd rediscliget && ${.MAKE} run key="foo"

.include <bsd.subdir.mk>

# vim: set ts=8 sw=8 noet:
