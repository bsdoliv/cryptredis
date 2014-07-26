# Copyright (c) 2013, 2014 Andre de Oliveira <deoliveirambx@googlemail.com>
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

#CPPFLAGS+=	-DDEBUG_RIJNDAEL_CTXT
LDSTATIC=	-static
LIB=		cryptredis

MKLINT=		no
NOPROFILE=	1
NOPIC=		1
NOMAN=		1

.PATH:		${.CURDIR}/..
SRCS=		cryptredisdb.cpp cryptredisresult.cpp bsd-rijndael.c \
		bsd-crypt.c encode.c tools.c

.PATH:		${.CURDIR}/../hiredis
SRCS+=		async.c dict.c hiredis.c net.c sds.c

# install instructions
.ifmake install || cleaninstall # {

.include <bsd.own.mk>

FILES=		cryptredis.h
DESTDIR=	/opt/cryptredis
LIBDIR=		/lib
FILESDIR=	/include

.ifmake install # {
.BEGIN: createdirs
	@${.MAKE}

createdirs: .PHONY
	mkdir -p ${DESTDIR}${LIBDIR}
	mkdir -p ${DESTDIR}${FILESDIR}
	chown -R `id -u -n` ${DESTDIR}
.endif # } install

.ifmake cleaninstall # {
cleaninstall:
	rm -rfv ${DESTDIR}${LIBDIR}
	rm -rfv ${DESTDIR}${FILESDIR}
	if [ -d ${DESTDIR} ]; then \
		rmdir ${DESTDIR}; \
	fi
.endif # } cleaninstall
.endif # } install || cleaninstall

.include <bsd.lib.mk>
