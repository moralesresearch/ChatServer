/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/*
 * this is the fabled pipe authenticator. it forks and executes a
 * script, and talks to it via stdio. this is a great way to take
 * advantage of existing code (in any language) to do authentication and
 * registration.
 *
 * there is an example script, tools/pipe-auth.pl, which can be used to
 * get started writing a pipe module. the protocol is documented in
 * docs/dev/c2s-pipe-authenticator
 */

/*
 * ChatServer: the request and reply handling was rewritten for the FreeBSD
 * port, where this module carries every sign-in to the setuid pamauth
 * helper. The rules, all of them failing closed (the user is not signed in):
 *
 * - a request is one line and a reply is one line. User names and realms
 *   are checked before anything is written, so that no request can hold a
 *   space or a newline of the client's choosing; a request that does not
 *   fit the line buffer is not sent at all.
 * - a reply is read up to its newline, with a time limit and a size limit.
 * - after any error (write error, timeout, EOF, overlong or unexpected
 *   reply) the helper is killed and its pipes are closed, so no stale reply
 *   can ever answer a later request. The next request starts a new helper.
 * - only the exact line "OK" is a yes.
 */

#include "c2s.h"
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

/** longest request or reply line, including the newline */
#define PIPE_LINE_MAX       1024
/** how long the helper may take to answer, in milliseconds */
#define PIPE_TIMEOUT_MS     10000
/** longest user name: MAXLOGNAME - 1 on FreeBSD, and pamauth's limit */
#define PIPE_USER_MAX       32

/** internal structure, holds our data */
typedef struct moddata_st {
    const char    *exec;

    /** the helper's pid, or 0 when no helper is running */
    pid_t   child;

    int     in, out;
} *moddata_t;

/** a user name the helper can take: letters, digits, . _ -, not starting with - */
static int _ar_pipe_valid_user(const char *username)
{
    size_t i, len;

    if(username == NULL)
        return 0;

    len = strlen(username);
    if(len == 0 || len > PIPE_USER_MAX || username[0] == '-')
        return 0;

    for(i = 0; i < len; i++) {
        char c = username[i];
        if(!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }

    return 1;
}

/** a realm that cannot break the line protocol: no spaces, no control characters; may be empty */
static int _ar_pipe_valid_realm(const char *realm)
{
    const unsigned char *c;

    if(realm == NULL)
        return 0;

    for(c = (const unsigned char *) realm; *c != '\0'; c++)
        if(*c <= ' ' || *c == 0x7f)
            return 0;

    return 1;
}

/** kill the helper and forget its pipes; the SIGCHLD handler reaps it */
static void _ar_pipe_stop(moddata_t data)
{
    if(data->child <= 0)
        return;

    kill(data->child, SIGKILL);
    close(data->in);
    close(data->out);

    data->child = 0;
    data->in = data->out = -1;
}

/** read one line from the helper, without its newline; -1 on timeout, EOF, error or an overlong line */
static int _ar_pipe_read_line(authreg_t ar, char *buf, size_t buflen)
{
    moddata_t data = (moddata_t) ar->private;
    struct pollfd pfd;
    time_t deadline = time(NULL) + PIPE_TIMEOUT_MS / 1000, left;
    size_t len = 0;
    ssize_t ret;
    char c;

    /* one byte at a time, so that nothing after the newline is taken;
     * the time limit is for the whole line */
    for(;;) {
        pfd.fd = data->in;
        pfd.events = POLLIN;
        pfd.revents = 0;

        left = deadline - time(NULL);
        ret = left > 0 ? poll(&pfd, 1, (int) left * 1000) : 0;
        if(ret < 0 && errno == EINTR)
            continue;
        if(ret == 0) {
            log_write(ar->c2s->log, LOG_ERR, "pipe: no reply from the authenticator in time");
            return -1;
        }
        if(ret < 0) {
            log_write(ar->c2s->log, LOG_ERR, "pipe: poll failed: %s", strerror(errno));
            return -1;
        }

        ret = read(data->in, &c, 1);
        if(ret < 0 && errno == EINTR)
            continue;
        if(ret < 0) {
            log_write(ar->c2s->log, LOG_ERR, "pipe: read from pipe failed: %s", strerror(errno));
            return -1;
        }
        if(ret == 0) {
            log_write(ar->c2s->log, LOG_ERR, "pipe: got EOF from pipe");
            return -1;
        }

        if(c == '\n') {
            buf[len] = '\0';
            return 0;
        }

        if(c == '\0' || len + 1 >= buflen) {
            log_write(ar->c2s->log, LOG_ERR, "pipe: malformed reply from the authenticator");
            return -1;
        }

        buf[len++] = c;
    }
}

/** start the helper and read its greeting line into greeting (PIPE_LINE_MAX bytes); 0 on success */
static int _ar_pipe_start(authreg_t ar, char *greeting)
{
    moddata_t data = (moddata_t) ar->private;
    int to[2], from[2];
    pid_t child;

    if(pipe(to) < 0) {
        log_write(ar->c2s->log, LOG_ERR, "pipe: failed to create pipe: %s", strerror(errno));
        return 1;
    }

    if(pipe(from) < 0) {
        log_write(ar->c2s->log, LOG_ERR, "pipe: failed to create pipe: %s", strerror(errno));
        close(to[0]);
        close(to[1]);
        return 1;
    }

    child = fork();
    if(child < 0) {
        log_write(ar->c2s->log, LOG_ERR, "pipe: failed to fork: %s", strerror(errno));
        close(to[0]);
        close(to[1]);
        close(from[0]);
        close(from[1]);
        return 1;
    }

    /* child */
    if(child == 0) {
        if(dup2(to[0], STDIN_FILENO) < 0 || dup2(from[1], STDOUT_FILENO) < 0)
            _exit(1);

        close(to[0]);
        close(to[1]);
        close(from[0]);
        close(from[1]);

        execl(data->exec, data->exec, (char *) NULL);

        _exit(1);
    }

    /* parent */
    close(to[0]);
    close(from[1]);

    /* the helper must not inherit these when it is started again later,
     * nor should anything else c2s may start */
    fcntl(to[1], F_SETFD, FD_CLOEXEC);
    fcntl(from[0], F_SETFD, FD_CLOEXEC);

    data->child = child;
    data->in = from[0];
    data->out = to[1];

    /* the greeting is "OK", followed by the requests the helper knows */
    if(_ar_pipe_read_line(ar, greeting, PIPE_LINE_MAX) != 0 ||
       (strcmp(greeting, "OK") != 0 && strncmp(greeting, "OK ", 3) != 0)) {
        log_write(ar->c2s->log, LOG_ERR, "pipe: pipe authenticator %s failed to initialise", data->exec);
        _ar_pipe_stop(data);
        return 1;
    }

    log_write(ar->c2s->log, LOG_NOTICE, "pipe authenticator %s running (pid %d)", data->exec, (int) child);

    return 0;
}

/** has the helper exited, or sent something nobody asked for? */
static int _ar_pipe_unusable(moddata_t data)
{
    struct pollfd pfd;

    pfd.fd = data->in;
    pfd.events = POLLIN;
    pfd.revents = 0;

    /* between requests there is nothing to read from a healthy helper */
    return poll(&pfd, 1, 0) != 0;
}

/**
 * send one request line (the format must end in a newline) and read the
 * one-line reply into reply (PIPE_LINE_MAX bytes). 0 on success. On any
 * failure the helper is stopped and nothing of its output is kept.
 */
static int _ar_pipe_request(authreg_t ar, char *reply, const char *msgfmt, ...)
{
    moddata_t data = (moddata_t) ar->private;
    va_list args;
    char buf[PIPE_LINE_MAX], greeting[PIPE_LINE_MAX];
    int len;
    ssize_t ret;

    reply[0] = '\0';

    va_start(args, msgfmt);
    len = vsnprintf(buf, sizeof(buf), msgfmt, args);
    va_end(args);

    /* a cut-off request would have no newline: do not send any of it */
    if(len < 0 || (size_t) len >= sizeof(buf)) {
        log_write(ar->c2s->log, LOG_NOTICE, "pipe: request too long, not sent");
        return 1;
    }

    /* a helper that exited is replaced before it is needed */
    if(data->child > 0 && _ar_pipe_unusable(data)) {
        log_write(ar->c2s->log, LOG_ERR, "pipe: the authenticator exited or is out of step, restarting it");
        _ar_pipe_stop(data);
    }

    if(data->child <= 0 && _ar_pipe_start(ar, greeting) != 0)
        return 1;

    /* a line is far smaller than PIPE_BUF, so it is written whole or not
     * at all; SIGPIPE is ignored by c2s */
    do {
        ret = write(data->out, buf, len);
    } while(ret < 0 && errno == EINTR);

    if(ret != len) {
        log_write(ar->c2s->log, LOG_ERR, "pipe: write to pipe failed: %s", ret < 0 ? strerror(errno) : "short write");
        _ar_pipe_stop(data);
        return 1;
    }

    if(_ar_pipe_read_line(ar, reply, PIPE_LINE_MAX) != 0) {
        reply[0] = '\0';
        _ar_pipe_stop(data);
        return 1;
    }

    return 0;
}

/** base64 for a request line; 0 on success */
static int _ar_pipe_encode(const char *password, char *buf, size_t buflen)
{
    int plen = strlen(password);

    if(apr_base64_encode_len(plen) >= (int) buflen)
        return 1;

    apr_base64_encode(buf, password, plen);

    return 0;
}

static int _ar_pipe_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    char reply[PIPE_LINE_MAX];

    if(!_ar_pipe_valid_user(username) || !_ar_pipe_valid_realm(realm))
        return 0;

    if(_ar_pipe_request(ar, reply, "USER-EXISTS %s %s\n", username, realm) != 0)
        return 0;

    return strcmp(reply, "OK") == 0;
}

static int _ar_pipe_get_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    char reply[PIPE_LINE_MAX];

    if(!_ar_pipe_valid_user(username) || !_ar_pipe_valid_realm(realm))
        return 1;

    if(_ar_pipe_request(ar, reply, "GET-PASSWORD %s %s\n", username, realm) != 0)
        return 1;

    /* "OK <base64 password>" */
    if(strncmp(reply, "OK ", 3) != 0 || reply[3] == '\0')
        return 1;

    if(apr_base64_decode_len(&reply[3], strlen(&reply[3])) >= 256) {
        log_debug(ZONE, "decoded password longer than buffer");
        return 1;
    }

    apr_base64_decode(password, &reply[3], strlen(&reply[3]));

    return 0;
}

static int _ar_pipe_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    char reply[PIPE_LINE_MAX], b64[PIPE_LINE_MAX];
    int ret;

    if(!_ar_pipe_valid_user(username) || !_ar_pipe_valid_realm(realm))
        return 1;

    if(_ar_pipe_encode(password, b64, sizeof(b64)) != 0)
        return 1;

    ret = _ar_pipe_request(ar, reply, "CHECK-PASSWORD %s %s %s\n", username, b64, realm);
    memset(b64, 0, sizeof(b64));
    if(ret != 0)
        return 1;

    return strcmp(reply, "OK") == 0 ? 0 : 1;
}

static int _ar_pipe_set_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    char reply[PIPE_LINE_MAX], b64[PIPE_LINE_MAX];
    int ret;

    if(!_ar_pipe_valid_user(username) || !_ar_pipe_valid_realm(realm))
        return 1;

    if(_ar_pipe_encode(password, b64, sizeof(b64)) != 0)
        return 1;

    ret = _ar_pipe_request(ar, reply, "SET-PASSWORD %s %s %s\n", username, b64, realm);
    memset(b64, 0, sizeof(b64));
    if(ret != 0)
        return 1;

    return strcmp(reply, "OK") == 0 ? 0 : 1;
}

static int _ar_pipe_create_user(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    char reply[PIPE_LINE_MAX];

    if(!_ar_pipe_valid_user(username) || !_ar_pipe_valid_realm(realm))
        return 1;

    if(_ar_pipe_request(ar, reply, "CREATE-USER %s %s\n", username, realm) != 0)
        return 1;

    return strcmp(reply, "OK") == 0 ? 0 : 1;
}

static int _ar_pipe_delete_user(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    char reply[PIPE_LINE_MAX];

    if(!_ar_pipe_valid_user(username) || !_ar_pipe_valid_realm(realm))
        return 1;

    if(_ar_pipe_request(ar, reply, "DELETE-USER %s %s\n", username, realm) != 0)
        return 1;

    return strcmp(reply, "OK") == 0 ? 0 : 1;
}

static void _ar_pipe_free(authreg_t ar)
{
    moddata_t data = (moddata_t) ar->private;

    if(data->child > 0) {
        /* ask the helper to exit; closing its stdin does the same */
        if(write(data->out, "FREE\n", 5) < 0)
            log_debug(ZONE, "write to pipe failed: %s", strerror(errno));
        close(data->in);
        close(data->out);
    }

    free(data);
    ar->private = NULL;
}

/** reap helpers that exited or were killed */
static void _ar_pipe_signal(int signum)
{
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0)
        ;

    errno = saved_errno;
}

/** start me up */
int ar_init(authreg_t ar)
{
    moddata_t data;
    char greeting[PIPE_LINE_MAX], *tok, *c;

    data = (moddata_t) calloc(1, sizeof(struct moddata_st));
    data->in = data->out = -1;

    data->exec = config_get_one(ar->c2s->config, "authreg.pipe.exec", 0);
    if(data->exec == NULL)
    {
        log_write(ar->c2s->log, LOG_ERR, "pipe: no executable specified in config file");
        free(data);
        return 1;
    }

    ar->private = (void *) data;

    signal(SIGCHLD, _ar_pipe_signal);

    if(_ar_pipe_start(ar, greeting) != 0)
    {
        ar->private = NULL;
        free(data);
        return 1;
    }

    /* the greeting was checked to start with OK; the rest are the
     * requests the helper answers */
    c = strchr(greeting, ' ');
    while(c != NULL)
    {
        tok = ++c;

        c = strchr(c, ' ');
        if(c != NULL)
            *c = '\0';

        log_debug(ZONE, "module feature: %s", tok);

        if(strcmp(tok, "USER-EXISTS") == 0)
            ar->user_exists = _ar_pipe_user_exists;
        else if(strcmp(tok, "GET-PASSWORD") == 0)
            ar->get_password = _ar_pipe_get_password;
        else if(strcmp(tok, "CHECK-PASSWORD") == 0)
            ar->check_password = _ar_pipe_check_password;
        else if(strcmp(tok, "SET-PASSWORD") == 0)
            ar->set_password = _ar_pipe_set_password;
        else if(strcmp(tok, "CREATE-USER") == 0)
            ar->create_user = _ar_pipe_create_user;
        else if(strcmp(tok, "DELETE-USER") == 0)
            ar->delete_user = _ar_pipe_delete_user;
        else if(strcmp(tok, "FREE") == 0)
            ar->free = _ar_pipe_free;
    }

    return 0;
}
