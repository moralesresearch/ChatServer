PROG=	jabber_autobuddy
MAN=	jabber_autobuddy.8
PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/sbin
MANDIR?=	${PREFIX}/share/man/man
CFLAGS+=	-I${LOCALBASE}/include
LDFLAGS+=	-L${LOCALBASE}/lib
LDADD=	-lsqlite3
LOCALBASE?=	/usr/local
WARNS?=	6
MK_WERROR=	no
MK_DEBUG_FILES=	no

.include <bsd.prog.mk>
