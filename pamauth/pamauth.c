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
 */

#include <sys/param.h>
#include <sys/types.h>

#include <ctype.h>
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
		case PAM_PROMPT_ECHO_ON:
			if ((reply[i].resp = strdup(appdata)) == NULL)
				goto fail;
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			break;
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

static void
reply(int ok)
{
	fputs(ok ? "OK\n" : "NO\n", stdout);
	fflush(stdout);
}

int
main(int argc, char *argv[])
{
	static char *empty_env[] = { NULL };
	char line[LINE_MAX_LEN], password[PASSWORD_MAX + 1];
	char *p, *cmd, *user, *pass;

	(void)argv;
	environ = empty_env;
	openlog("jabberd/pamauth", LOG_PID, LOG_AUTH);

	if (argc != 1 || isatty(STDIN_FILENO)) {
		fprintf(stderr, "usage: pamauth\n"
		    "pamauth is started by jabberd's c2s (authreg module pipe)\n");
		return (1);
	}
	signal(SIGPIPE, SIG_DFL);

	fputs("OK USER-EXISTS CHECK-PASSWORD FREE\n", stdout);
	fflush(stdout);

	while (fgets(line, sizeof(line), stdin) != NULL) {
		if ((p = strchr(line, '\n')) == NULL) {
			/* overlong line: drop the rest of it */
			int c;
			while ((c = getchar()) != EOF && c != '\n')
				;
			reply(0);
			continue;
		}
		*p = '\0';

		p = line;
		cmd = strsep(&p, " ");
		if (strcmp(cmd, "FREE") == 0)
			break;

		user = strsep(&p, " ");
		if (user == NULL || !valid_user(user)) {
			reply(0);
			continue;
		}

		if (strcmp(cmd, "USER-EXISTS") == 0) {
			reply(getpwnam(user) != NULL);
		} else if (strcmp(cmd, "CHECK-PASSWORD") == 0) {
			pass = strsep(&p, " ");
			if (pass == NULL ||
			    b64decode(pass, password, sizeof(password)) != 0 ||
			    password[0] == '\0')
				reply(0);
			else
				reply(check_password(user, password));
			explicit_bzero(password, sizeof(password));
		} else {
			reply(0);
		}
		explicit_bzero(line, sizeof(line));
	}

	closelog();
	return (0);
}
