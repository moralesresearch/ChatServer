# ChatServer for FreeBSD: jabberd2 with Apple's ChatServer additions.
# License: GPL-2.0-or-later, like jabberd2 (see COPYING).
# BSD make; see README.md. Build dependencies:
#   pkg install autoconf automake libtool pkgconf gmake expat libidn udns \
#     gsasl sqlite3 openldap26-client
# The build runs as any user; install runs as root. DESTDIR, if set, must
# be a whole FreeBSD root (an image being built): the jabber user and the
# chat group are added to its password database with pw -R, and files are
# installed owned by the jabber group.

PREFIX?=	/usr/local
LOCALBASE?=	/usr/local
DESTDIR?=
GMAKE?=		gmake
# event loop: kqueue (as Apple built it) or poll
MIO?=		kqueue

JABBER_USER=	jabber
JABBER_UID=	93
JABBER_GROUP=	jabber
JABBER_GID=	93
# only members of this group may sign in (freebsd/pam.d/jabberd)
CHAT_GROUP=	chat

BUILDDIR=	${.CURDIR}/build
LIBEXECDIR=	${PREFIX}/libexec/jabberd
ETCDIR=		${PREFIX}/etc/jabberd
DATADIR=	${PREFIX}/share/jabberd

CONFIGURE_ARGS=	--prefix=${PREFIX} \
		--bindir=${LIBEXECDIR} \
		--sysconfdir=${ETCDIR} \
		--localstatedir=/var \
		--mandir=${PREFIX}/share/man \
		--enable-sqlite --enable-pam --enable-pipe --enable-ldap \
		--disable-mysql --disable-pgsql --disable-db --disable-oracle \
		--enable-ssl --enable-mio=${MIO} --disable-tests \
		--with-extra-include-path=${LOCALBASE}/include \
		--with-extra-library-path=${LOCALBASE}/lib
# OpenSSL is in the base system, which has no pkg-config file for it
# CC: the system compiler, even when a gcc package is installed, which
# configure would otherwise prefer
CONFIGURE_ENV=	CC=${CC} SSL_CFLAGS="-I/usr/include" SSL_LIBS="-lssl -lcrypto"

SUBDIRS=	pamauth jabber_autobuddy

.PHONY: all configure jabberd2 tools install install-user clean

all: jabberd2 tools

${.CURDIR}/jabberd2/configure:
	cd ${.CURDIR}/jabberd2 && autoreconf -fi

${BUILDDIR}/config.status: ${.CURDIR}/jabberd2/configure
	mkdir -p ${BUILDDIR}
	cd ${BUILDDIR} && env ${CONFIGURE_ENV} ${.CURDIR}/jabberd2/configure ${CONFIGURE_ARGS}

configure: ${BUILDDIR}/config.status

jabberd2: configure
	${GMAKE} -C ${BUILDDIR}

tools:
.for d in ${SUBDIRS}
	${MAKE} -C ${.CURDIR}/${d} PREFIX=${PREFIX} LOCALBASE=${LOCALBASE}
.endfor

# The jabber user and group of FreeBSD's ports (UIDs/GIDs: 93), and the
# chat group, which starts empty: nobody can sign in until an administrator
# adds members (pw groupmod chat -m user)
install-user:
	@if ! pw -R ${DESTDIR}/ groupshow ${CHAT_GROUP} >/dev/null 2>&1; then \
		echo "Creating group ${CHAT_GROUP}"; \
		pw -R ${DESTDIR}/ groupadd ${CHAT_GROUP}; \
	fi
	@if ! pw -R ${DESTDIR}/ groupshow ${JABBER_GROUP} >/dev/null 2>&1; then \
		echo "Creating group ${JABBER_GROUP}"; \
		pw -R ${DESTDIR}/ groupadd ${JABBER_GROUP} -g ${JABBER_GID}; \
	fi
	@if ! pw -R ${DESTDIR}/ usershow ${JABBER_USER} >/dev/null 2>&1; then \
		echo "Creating user ${JABBER_USER}"; \
		pw -R ${DESTDIR}/ useradd ${JABBER_USER} -u ${JABBER_UID} \
		    -g ${JABBER_GROUP} -c "Jabber Daemon" -d /nonexistent \
		    -s /usr/sbin/nologin; \
	fi

install: all install-user
	# The configuration holds the router secret (a placeholder until the
	# service first starts): it is installed root:jabber 640, never
	# with a wider mode first
	${GMAKE} -C ${BUILDDIR} install DESTDIR=${DESTDIR} \
	    CONFIG_INSTALL_FLAGS="-m 640 -o root -g ${JABBER_GROUP}"
	# libtool archives and the Perl launcher are not used
	rm -f ${DESTDIR}${PREFIX}/lib/jabberd/*.la ${DESTDIR}${LIBEXECDIR}/jabberd
.for d in ${SUBDIRS}
	${MAKE} -C ${.CURDIR}/${d} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}
.endfor
	install -d -m 755 ${DESTDIR}${DATADIR} ${DESTDIR}${PREFIX}/etc/pam.d \
	    ${DESTDIR}${PREFIX}/etc/rc.d
	install -m 444 ${.CURDIR}/jabberd2/tools/db-setup.sqlite ${DESTDIR}${DATADIR}/
	# the rc.d script is written for /usr/local
	sed -e 's,/usr/local,${PREFIX},g' ${.CURDIR}/freebsd/rc.d/chatserver \
	    > ${BUILDDIR}/chatserver.rc
	install -m 555 ${BUILDDIR}/chatserver.rc \
	    ${DESTDIR}${PREFIX}/etc/rc.d/chatserver
	@if [ ! -f ${DESTDIR}${PREFIX}/etc/pam.d/jabberd ]; then \
		echo "install -m 644 freebsd/pam.d/jabberd ${DESTDIR}${PREFIX}/etc/pam.d/"; \
		install -m 644 ${.CURDIR}/freebsd/pam.d/jabberd ${DESTDIR}${PREFIX}/etc/pam.d/; \
	fi

clean:
	rm -rf ${BUILDDIR}
.for d in ${SUBDIRS}
	${MAKE} -C ${.CURDIR}/${d} clean cleandepend
.endfor
