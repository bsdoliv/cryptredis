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

.include <bsd.own.mk>

CXXFLAGS+= -std=c++0x
LDSTATIC= -static
LIB= cryptredis

MKPICLIB=       no # disables build of lib*_pic.a
MKPICINSTALL=   no # disables install of lib*_pic.a
MKMAN=          no # disables manpages build
NOGCCERROR=     1 # removes -Werror

.PATH: ${.CURDIR}/..
SRCS= cryptredisdb.cpp cryptredisresult.cpp bsd-rijndael.c bsd-crypt.c
SRCS+= encode.c tools.c

.include "${.CURDIR}/../hiredis/hiredis.mk"
#.PATH: ${.CURDIR}/../hiredis
#SRCS+= async.c dict.c hiredis.c net.c sds.c

# install instructions
.ifmake install || cleaninstall # {
FILES= redis_client.hpp
DESTDIR= /opt/cryptredis
LIBDIR= /lib
FILESDIR= /include

.ifmake install # {
.BEGIN: createdirs
	@${.MAKE}

createdirs: .PHONY
	sudo mkdir -p ${DESTDIR}${LIBDIR}
	sudo mkdir -p ${DESTDIR}${FILESDIR}
	sudo chown -R `id -u -n` ${DESTDIR}
.endif # } install

.ifmake cleaninstall # {
cleaninstall:
	rm -rfv ${DESTDIR}${LIBDIR}
	rm -rfv ${DESTDIR}${FILESDIR}
	if [ -d ${DESTDIR} ]; then \
		sudo rmdir ${DESTDIR}; \
	fi
.endif # } cleaninstall
.endif # } install || cleaninstall

.include <bsd.lib.mk>

# vim: ts=8 sw=8 noet:
