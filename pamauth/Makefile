PROG=	pamauth
MAN=	pamauth.8
LIBADD=	pam
BINDIR?=	${PREFIX}/libexec/jabberd
MANDIR?=	${PREFIX}/share/man/man
PREFIX?=	/usr/local
WARNS?=	6
MK_WERROR=	no
MK_DEBUG_FILES=	no

# setuid root, executable by the jabber group only (c2s runs as jabber)
BINOWN=	root
BINGRP=	jabber
BINMODE=	4750

.include <bsd.prog.mk>
