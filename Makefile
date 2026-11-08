# ChatServer for FreeBSD: jabberd2 with Apple's ChatServer additions.
# BSD make; see README.md. Build dependencies:
#   pkg install autoconf automake libtool pkgconf gmake expat libidn udns \
#     gsasl sqlite3 openldap26-client
# The build runs as any user; install runs as root.

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
CONFIGURE_ENV=	SSL_CFLAGS="-I/usr/include" SSL_LIBS="-lssl -lcrypto"

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

# The jabber user and group of FreeBSD's ports (UIDs/GIDs: 93)
install-user:
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

install: install-user
	${GMAKE} -C ${BUILDDIR} install DESTDIR=${DESTDIR}
	# libtool archives and the Perl launcher are not used
	rm -f ${DESTDIR}${PREFIX}/lib/jabberd/*.la ${DESTDIR}${LIBEXECDIR}/jabberd
.for d in ${SUBDIRS}
	${MAKE} -C ${.CURDIR}/${d} install PREFIX=${PREFIX} DESTDIR=${DESTDIR}
.endfor
	# The configuration holds the router secret
	chown root:${JABBER_GROUP} ${DESTDIR}${ETCDIR}/*.xml ${DESTDIR}${ETCDIR}/*.cfg \
	    ${DESTDIR}${ETCDIR}/*.dist
	chmod 640 ${DESTDIR}${ETCDIR}/*.xml ${DESTDIR}${ETCDIR}/*.cfg \
	    ${DESTDIR}${ETCDIR}/*.dist
	install -d -m 755 ${DESTDIR}${DATADIR} ${DESTDIR}${PREFIX}/etc/pam.d \
	    ${DESTDIR}${PREFIX}/etc/rc.d
	install -m 444 ${.CURDIR}/jabberd2/tools/db-setup.sqlite ${DESTDIR}${DATADIR}/
	install -m 555 ${.CURDIR}/freebsd/rc.d/chatserver ${DESTDIR}${PREFIX}/etc/rc.d/
	@if [ ! -f ${DESTDIR}${PREFIX}/etc/pam.d/jabberd ]; then \
		echo "install -m 644 freebsd/pam.d/jabberd ${DESTDIR}${PREFIX}/etc/pam.d/"; \
		install -m 644 ${.CURDIR}/freebsd/pam.d/jabberd ${DESTDIR}${PREFIX}/etc/pam.d/; \
	fi

clean:
	rm -rf ${BUILDDIR}
.for d in ${SUBDIRS}
	${MAKE} -C ${.CURDIR}/${d} clean cleandepend
.endfor
