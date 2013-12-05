#!/bin/sh

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
#        This product includes software developed by Andre Oliveira.
# 4. Neither the name of the author nor the names of its contributors may be
#    used to endorse or promote products derived from this software without
#    specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# In order to be sure everything is goin to work fine, preceed the execution of
# this script by the following commands:
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
#    copy_src ${builddir}/bin/bmake ${builddir}/bmake
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
    export builddir=$(mktemp -d /tmp/bmake-XXX)

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
