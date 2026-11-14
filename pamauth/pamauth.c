/*
 * pamauth - PAM authenticator for jabberd2's pipe authreg module
 * Copyright (c) 2026 Morales Research Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

/*
 * c2s starts this program and talks to it over stdin and stdout, one
 * request per line (see jabberd2/storage/authreg_pipe.c):
 *
 *   USER-EXISTS <user> <realm>               -> OK | NO
 *   CHECK-PASSWORD <user> <base64> <realm>   -> OK | NO
 *   FREE                                     -> exits
 *
 * It replaces Apple's Open Directory authentication (jabber_od_auth): users
 * sign in with their system account, checked by the PAM service "jabberd".
 * pam_unix(8) can only check passwords as root, so this program is installed
 * setuid root and executable by the jabber group only, and c2s runs as the
 * jabber user. The realm is ignored.
 *
 * Only accounts with a uid of MIN_UID or more are answered for: root and
 * the system accounts cannot sign in to chat, whatever the PAM policy says,
 * so the chat port is no place to guess their passwords.
 *
 * There is no delay after a failed check: c2s waits for each answer. c2s
 * limits attempts per stream and connections per address instead.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/resource.h>

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SERVICE     "jabberd"
#define LINE_MAX_LEN    2048
#define PASSWORD_MAX    256
/* the lowest uid that may sign in; FreeBSD gives users uids from 1001 */
#ifndef MIN_UID
#define MIN_UID         1000
#endif

extern char **environ;

/* a plausible user name: letters, digits, . _ -, not starting with - */
static int
valid_user(const char *user)
{
	size_t i, len;

	len = strlen(user);
	if (len == 0 || len >= MAXLOGNAME || user[0] == '-')
		return (0);
	for (i = 0; i < len; i++)
		if (!isalnum((unsigned char)user[i]) && user[i] != '.' &&
		    user[i] != '_' && user[i] != '-')
			return (0);
	return (1);
}

static int
b64val(int c)
{
	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	if (c >= 'a' && c <= 'z')
		return (c - 'a' + 26);
	if (c >= '0' && c <= '9')
		return (c - '0' + 52);
	if (c == '+')
		return (62);
	if (c == '/')
		return (63);
	return (-1);
}

/* decode standard base64 into out (NUL-terminated); -1 on bad input */
static int
b64decode(const char *in, char *out, size_t outlen)
{
	size_t n = 0;
	unsigned int acc = 0;
	int bits = 0, v;

	for (; *in != '\0' && *in != '='; in++) {
		if ((v = b64val((unsigned char)*in)) < 0)
			return (-1);
		acc = (acc << 6) | (unsigned int)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (n + 1 >= outlen)
				return (-1);
			out[n++] = (char)((acc >> bits) & 0xff);
		}
	}
	out[n] = '\0';
	/* a NUL inside the password cannot be passed on to PAM */
	return (strlen(out) == n ? 0 : -1);
}

static int
conv(int nmsg, const struct pam_message **msg, struct pam_response **res,
    void *appdata)
{
	struct pam_response *reply;
	int i;

	if (nmsg <= 0 || nmsg > PAM_MAX_NUM_MSG)
		return (PAM_CONV_ERR);
	if ((reply = calloc(nmsg, sizeof(*reply))) == NULL)
		return (PAM_BUF_ERR);

	for (i = 0; i < nmsg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			/* the password prompt, the only question answered */
			if ((reply[i].resp = strdup(appdata)) == NULL)
				goto fail;
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			break;
		case PAM_PROMPT_ECHO_ON:
			/* never hand the password to a visible prompt */
		default:
			goto fail;
		}
	}
	*res = reply;
	return (PAM_SUCCESS);

fail:
	for (i = 0; i < nmsg; i++)
		if (reply[i].resp != NULL) {
			explicit_bzero(reply[i].resp, strlen(reply[i].resp));
			free(reply[i].resp);
		}
	free(reply);
	return (PAM_CONV_ERR);
}

static int
check_password(const char *user, char *password)
{
	struct pam_conv pc = { conv, password };
	pam_handle_t *pamh;
	int ret;

	if ((ret = pam_start(PAM_SERVICE, user, &pc, &pamh)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_start: %s", pam_strerror(NULL, ret));
		return (0);
	}
	if ((ret = pam_authenticate(pamh, PAM_SILENT |
	    PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS)
		goto out;
	ret = pam_acct_mgmt(pamh, PAM_SILENT);
out:
	if (ret != PAM_SUCCESS)
		syslog(LOG_NOTICE, "authentication failed for %s: %s", user,
		    pam_strerror(pamh, ret));
	else
		syslog(LOG_INFO, "authenticated %s", user);
	pam_end(pamh, ret);
	return (ret == PAM_SUCCESS);
}

/* an account that may use chat: it exists and is not a system account */
static int
chat_user(const char *user)
{
	struct passwd *pw;

	if ((pw = getpwnam(user)) == NULL)
		return (0);
	return (pw->pw_uid >= MIN_UID);
}

static void
reply(int ok)
{
	const char *msg = ok ? "OK\n" : "NO\n";

	if (write(STDOUT_FILENO, msg, 3) != 3)
		exit(1);
}

/*
 * Read one request line into line, without its newline, straight from the
 * descriptor: stdio would keep passwords in a buffer of its own. Returns 1
 * for a line, 0 for a line that must be refused (too long, or with a NUL
 * in it; it is read up to its newline, so the next request is read from
 * its start), and -1 at end of input.
 */
static int
read_line(char *line, size_t size)
{
	size_t len = 0;
	int good = 1;
	ssize_t n;
	char c;

	for (;;) {
		n = read(STDIN_FILENO, &c, 1);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		if (c == '\n')
			break;
		if (c == '\0' || len + 1 >= size)
			good = 0;
		else
			line[len++] = c;
	}
	line[len] = '\0';
	return (good);
}

int
main(int argc, char *argv[])
{
	static char *empty_env[] = { NULL };
	static const char greeting[] = "OK USER-EXISTS CHECK-PASSWORD FREE\n";
	struct rlimit norlimit = { 0, 0 };
	char line[LINE_MAX_LEN], password[PASSWORD_MAX + 1];
	char *p, *cmd, *user, *pass;
	int r;

	(void)argv;
	environ = empty_env;
	/* no core files: they would hold passwords */
	(void)setrlimit(RLIMIT_CORE, &norlimit);
	/* c2s's other descriptors (client connections) are not ours */
	closefrom(STDERR_FILENO + 1);
	openlog("jabberd/pamauth", LOG_PID, LOG_AUTH);

	if (argc != 1 || isatty(STDIN_FILENO)) {
		fprintf(stderr, "usage: pamauth\n"
		    "pamauth is started by jabberd's c2s (authreg module pipe)\n");
		return (1);
	}
	signal(SIGPIPE, SIG_DFL);

	if (write(STDOUT_FILENO, greeting, sizeof(greeting) - 1) !=
	    (ssize_t)sizeof(greeting) - 1)
		return (1);

	while ((r = read_line(line, sizeof(line))) >= 0) {
		if (r == 0) {
			explicit_bzero(line, sizeof(line));
			reply(0);
			continue;
		}

		p = line;
		cmd = strsep(&p, " ");
		if (strcmp(cmd, "FREE") == 0)
			break;

		user = strsep(&p, " ");
		if (user == NULL || !valid_user(user) || !chat_user(user)) {
			explicit_bzero(line, sizeof(line));
			reply(0);
			continue;
		}

		if (strcmp(cmd, "USER-EXISTS") == 0) {
			reply(1);
		} else if (strcmp(cmd, "CHECK-PASSWORD") == 0) {
			pass = strsep(&p, " ");
			if (pass == NULL ||
			    b64decode(pass, password, sizeof(password)) != 0 ||
			    password[0] == '\0')
				r = 0;
			else
				r = check_password(user, password);
			explicit_bzero(password, sizeof(password));
			explicit_bzero(line, sizeof(line));
			reply(r);
			continue;
		} else {
			reply(0);
		}
		explicit_bzero(line, sizeof(line));
	}

	explicit_bzero(line, sizeof(line));
	closelog();
	return (0);
}
