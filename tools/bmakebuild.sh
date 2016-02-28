#!/bin/sh

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

# In order to be sure everything will work fine, preceed the execution of this
# script by the following commands:
#
#   % mkdir /opt/bmake
#   % sudo chown `whoami` /opt/bmake
#
# You can also adjust the pkgsrc version

pkgsrc_version=2013Q1
prefix=${HOME}/.opt/bmake

die()
{
    echo "==> ${@}" >&2 
    exit 1
}

runcmd()
{
    echo "==> running: $@"
    eval "$@"
    ret=$?
        if [ $ret -ne 0 ]; then
        echo "==> exited with status $ret"
        die "aborted."
    fi
}

bootstrap_bmake() 
{
    bmakexenv="MAKE=pmake"
    bmakexargs=

    echo "==> Bootstrapping bmake"
    runcmd "(cd ${builddir}/${bmakesrc} && env $bmakexenv $shprog \
                ./boot-strap $configure_quiet_flags -q \
                -o $opsys --prefix=$prefix \
                --sysconfdir=$sysconfdir --mksrc none \
                --with-default-sys-path="$prefix/mk" $bmakexargs)"
    runcmd "install -c -o $user -g $group -m 755 ${builddir}/${bmakesrc}/$opsys/bmake $prefix/bin/bmake"
}

bootstrap_mkfiles()
{
    echo "==> Bootstrapping mk-files"
    runcmd "(cd ${builddir}/${mkfilessrc} && \
                env OPSYS=${opsys} \
                MK_DST=${prefix}/mk ROOT_GROUP=${group} \
                ROOT_USER=${user} SYSCONFDIR=${sysconfdir} \
                $shprog ./bootstrap.sh)"
}

loadvars()
{
    export builddir=$(mktemp -d /tmp/bmake-XXXXXX)

    export shprog="sh"
    export opsys=`uname -s | tr -d /-`
    export group=`id -gn`
    export user=`whoami`

    export bootstrapdir=`dirname "${0}"`
    export bootstrapdir=`cd "${bootstrapdir}" && pwd`

    export sysconfdir=${prefix}/etc

    export mkfilessrc="pkgsrc/pkgtools/bootstrap-mk-files/files"
    export bmakesrc="pkgsrc/devel/bmake/files"

    export configure_quiet_flags="--quiet"
    export make_quiet_flags="-s"
}

main()
{
    loadvars
    mkdir -p ${builddir}
    mkdir -p ${prefix}/bin
    mkdir -p ${prefix}/etc
    mkdir -p ${prefix}/mk

    cd ${builddir}

    echo "==> Working on ${builddir}"

    echo "==> Retrieving bmake"
    runcmd "cvs -q -z2 -d anoncvs@anoncvs.NetBSD.org:/cvsroot checkout -r \
        pkgsrc-${pkgsrc_version} -P ${bmakesrc}"

    echo "==> Retrieving mk-files"
    runcmd "cvs -q -z2 -d anoncvs@anoncvs.NetBSD.org:/cvsroot checkout -r \
        pkgsrc-${pkgsrc_version} -P ${mkfilessrc}"

    bootstrap_bmake
    bootstrap_mkfiles
}

main "${@}"
