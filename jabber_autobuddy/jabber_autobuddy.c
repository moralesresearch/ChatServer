/*
 * jabber_autobuddy - buddy management for the ChatServer XMPP service
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
 * A FreeBSD version of the jabber_autobuddy tool from Apple's ChatServer,
 * with the same commands. It edits jabberd2's SQLite database directly.
 * Groups are system groups (getgrnam(3)) instead of Open Directory groups,
 * and group IDs are numeric GIDs instead of GUIDs.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define VERSION		"2.7.0-chatserver"
#define DEFAULT_DB	"/var/db/jabberd/sqlite.db"
#define MAXJIDS		256

static sqlite3 *db;
static int verbose;

/* the active users: bare JIDs from the "active" table */
static char **active;
static int nactive;

static void
logmsg(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
	if (verbose || pri <= LOG_WARNING) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
		va_end(ap);
	}
}

static void
dbfail(const char *what)
{
	logmsg(LOG_ERR, "%s: %s", what, sqlite3_errmsg(db));
	sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
	sqlite3_close(db);
	exit(1);
}

static sqlite3_stmt *
prepare(const char *sql)
{
	sqlite3_stmt *st;

	if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
		dbfail(sql);
	return (st);
}

/* run a statement with text parameters; returns the number of rows changed */
static int
run(const char *sql, int n, ...)
{
	sqlite3_stmt *st = prepare(sql);
	va_list ap;
	int i, rc;

	va_start(ap, n);
	for (i = 1; i <= n; i++)
		sqlite3_bind_text(st, i, va_arg(ap, const char *), -1,
		    SQLITE_TRANSIENT);
	va_end(ap);
	while ((rc = sqlite3_step(st)) == SQLITE_ROW)
		;
	if (rc != SQLITE_DONE)
		dbfail(sql);
	sqlite3_finalize(st);
	return (sqlite3_changes(db));
}

/* count the rows a SELECT COUNT(*) with text parameters returns */
static int
count(const char *sql, int n, ...)
{
	sqlite3_stmt *st = prepare(sql);
	va_list ap;
	int i, c = 0;

	va_start(ap, n);
	for (i = 1; i <= n; i++)
		sqlite3_bind_text(st, i, va_arg(ap, const char *), -1,
		    SQLITE_TRANSIENT);
	va_end(ap);
	if (sqlite3_step(st) == SQLITE_ROW)
		c = sqlite3_column_int(st, 0);
	else
		dbfail(sql);
	sqlite3_finalize(st);
	return (c);
}

/* jabberd stores JIDs lower case; accept user@domain only */
static char *
check_jid(const char *arg)
{
	char *jid, *at, *p;

	if ((jid = strdup(arg)) == NULL)
		err(1, "strdup");
	for (p = jid; *p != '\0'; p++)
		*p = tolower((unsigned char)*p);
	at = strchr(jid, '@');
	if (at == NULL || at == jid || at[1] == '\0' ||
	    strchr(at + 1, '@') != NULL || strchr(jid, '/') != NULL)
		errx(1, "%s: not a JID of the form user@domain", arg);
	return (jid);
}

static const char *
jid_domain(const char *jid)
{
	return (strchr(jid, '@') + 1);
}

/* the node of a JID, in a static buffer */
static const char *
jid_node(const char *jid)
{
	static char buf[1024];
	size_t n = strcspn(jid, "@");

	if (n >= sizeof(buf))
		n = sizeof(buf) - 1;
	memcpy(buf, jid, n);
	buf[n] = '\0';
	return (buf);
}

static void
load_active(void)
{
	sqlite3_stmt *st;
	int rc;

	st = prepare("SELECT \"collection-owner\" FROM \"active\" "
	    "ORDER BY \"collection-owner\"");
	while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
		const char *o = (const char *)sqlite3_column_text(st, 0);

		if (o == NULL || strchr(o, '@') == NULL)
			continue;
		active = reallocarray(active, nactive + 1, sizeof(char *));
		if (active == NULL || (active[nactive] = strdup(o)) == NULL)
			err(1, "malloc");
		nactive++;
	}
	if (rc != SQLITE_DONE)
		dbfail("reading active users");
	sqlite3_finalize(st);
}

static int
is_active(const char *jid)
{
	return (count("SELECT COUNT(*) FROM \"active\" "
	    "WHERE \"collection-owner\" = ?", 1, jid) > 0);
}

static void
need_active(const char *jid)
{
	if (!is_active(jid)) {
		logmsg(LOG_ERR, "%s is not in the jabberd database; "
		    "run jabber_autobuddy --inituser %s first", jid, jid);
		exit(1);
	}
}

/* a system group, copied out of getgrnam()'s static storage */
struct group_info {
	char	*name;
	gid_t	 gid;
	char	**members;
};

static struct group_info *
group_lookup(const char *name, int by_gid)
{
	struct group_info *g;
	struct group *gr;
	const char *ep;
	long long gid;
	int n, i;

	if (by_gid) {
		gid = strtonum(name, 0, UINT32_MAX - 1, &ep);
		if (ep != NULL)
			errx(1, "%s: group ID is %s", name, ep);
		gr = getgrgid((gid_t)gid);
	} else
		gr = getgrnam(name);
	if (gr == NULL)
		errx(1, "%s: no such group", name);

	for (n = 0; gr->gr_mem[n] != NULL; n++)
		;
	if ((g = calloc(1, sizeof(*g))) == NULL ||
	    (g->name = strdup(gr->gr_name)) == NULL ||
	    (g->members = calloc(n + 1, sizeof(char *))) == NULL)
		err(1, "malloc");
	g->gid = gr->gr_gid;
	for (i = 0; i < n; i++)
		if ((g->members[i] = strdup(gr->gr_mem[i])) == NULL)
			err(1, "malloc");
	return (g);
}

/* listed members, and users whose primary group it is */
static int
group_has(const struct group_info *g, const char *user)
{
	struct passwd *pw;
	char **m;

	for (m = g->members; *m != NULL; m++)
		if (strcmp(*m, user) == 0)
			return (1);
	pw = getpwnam(user);
	return (pw != NULL && pw->pw_gid == g->gid);
}

/* the full name from the GECOS field, or NULL */
static char *
full_name(const char *user)
{
	static char buf[256];
	struct passwd *pw;
	size_t n;

	if ((pw = getpwnam(user)) == NULL || pw->pw_gecos == NULL)
		return (NULL);
	n = strcspn(pw->pw_gecos, ",");
	if (n == 0)
		return (NULL);
	if (n >= sizeof(buf))
		n = sizeof(buf) - 1;
	memcpy(buf, pw->pw_gecos, n);
	buf[n] = '\0';
	return (buf);
}

/* put buddy in owner's roster with subscription both, in group if given */
static void
add_item(const char *owner, const char *buddy, const char *group)
{
	if (count("SELECT COUNT(*) FROM \"roster-items\" "
	    "WHERE \"collection-owner\" = ? AND \"jid\" = ?", 2,
	    owner, buddy) > 0) {
		run("UPDATE \"roster-items\" SET \"to\" = 1, \"from\" = 1, "
		    "\"ask\" = 0 WHERE \"collection-owner\" = ? AND \"jid\" = ?",
		    2, owner, buddy);
	} else {
		const char *name = full_name(jid_node(buddy));

		run("INSERT INTO \"roster-items\" (\"collection-owner\", "
		    "\"jid\", \"name\", \"to\", \"from\", \"ask\") "
		    "VALUES (?, ?, ?, 1, 1, 0)", 3, owner, buddy, name);
	}
	if (group != NULL && count("SELECT COUNT(*) FROM \"roster-groups\" "
	    "WHERE \"collection-owner\" = ? AND \"jid\" = ? AND \"group\" = ?",
	    3, owner, buddy, group) == 0)
		run("INSERT INTO \"roster-groups\" (\"collection-owner\", "
		    "\"jid\", \"group\") VALUES (?, ?, ?)", 3, owner, buddy,
		    group);
}

static void
pair(const char *a, const char *b, const char *group)
{
	if (verbose)
		fprintf(stderr, "buddies: %s and %s\n", a, b);
	add_item(a, b, group);
	add_item(b, a, group);
}

static void
unpair(const char *a, const char *b)
{
	const char *x = a, *y = b;
	int i;

	if (verbose)
		fprintf(stderr, "no longer buddies: %s and %s\n", a, b);
	for (i = 0; i < 2; i++) {
		run("DELETE FROM \"roster-items\" WHERE "
		    "\"collection-owner\" = ? AND \"jid\" = ?", 2, x, y);
		run("DELETE FROM \"roster-groups\" WHERE "
		    "\"collection-owner\" = ? AND \"jid\" = ?", 2, x, y);
		x = b;
		y = a;
	}
}

/* buddies are only made within one domain */
static int
same_domain(const char *a, const char *b)
{
	return (strcmp(a, b) != 0 &&
	    strcmp(jid_domain(a), jid_domain(b)) == 0);
}

/* the tables that hold per-user data (they have a collection-owner column) */
static char **
owner_tables(int *n)
{
	sqlite3_stmt *st;
	char **t = NULL;

	*n = 0;
	st = prepare("SELECT m.name FROM sqlite_master m, "
	    "pragma_table_info(m.name) c WHERE m.type = 'table' AND "
	    "c.name = 'collection-owner' ORDER BY m.name");
	while (sqlite3_step(st) == SQLITE_ROW) {
		t = reallocarray(t, *n + 1, sizeof(char *));
		if (t == NULL || (t[*n] = strdup((const char *)
		    sqlite3_column_text(st, 0))) == NULL)
			err(1, "malloc");
		(*n)++;
	}
	sqlite3_finalize(st);
	return (t);
}

static int
has_column(const char *table, const char *column)
{
	return (count("SELECT COUNT(*) FROM pragma_table_info(?) "
	    "WHERE name = ?", 2, table, column) > 0);
}

/* "table" quoted as an SQL identifier */
static char *
quote(const char *id)
{
	char *q = sqlite3_mprintf("\"%w\"", id);

	if (q == NULL)
		err(1, "malloc");
	return (q);
}

static void
cmd_inituser(const char *jid)
{
	if (is_active(jid)) {
		logmsg(LOG_INFO, "%s is already initialized", jid);
		return;
	}
	run("INSERT INTO \"active\" (\"collection-owner\", \"time\") "
	    "VALUES (?, strftime('%s', 'now'))", 1, jid);
	logmsg(LOG_NOTICE, "initialized %s", jid);
}

static void
cmd_deleteuser(const char *jid)
{
	char **tables, *q, *sql;
	int n, i;

	need_active(jid);
	tables = owner_tables(&n);
	for (i = 0; i < n; i++) {
		q = quote(tables[i]);
		sql = sqlite3_mprintf("DELETE FROM %s WHERE "
		    "\"collection-owner\" = ?", q);
		run(sql, 1, jid);
		sqlite3_free(sql);
		sqlite3_free(q);
		free(tables[i]);
	}
	free(tables);
	run("DELETE FROM \"roster-items\" WHERE \"jid\" = ?", 1, jid);
	run("DELETE FROM \"roster-groups\" WHERE \"jid\" = ?", 1, jid);
	logmsg(LOG_NOTICE, "deleted %s", jid);
}

static void
cmd_addbuddy(const char *jid)
{
	int i;

	need_active(jid);
	for (i = 0; i < nactive; i++)
		if (same_domain(jid, active[i]))
			pair(jid, active[i], NULL);
	logmsg(LOG_NOTICE, "made %s a buddy of all users", jid);
}

static void
cmd_removebuddy(const char *jid)
{
	int i;

	need_active(jid);
	for (i = 0; i < nactive; i++)
		if (same_domain(jid, active[i]))
			unpair(jid, active[i]);
	logmsg(LOG_NOTICE, "removed %s from the buddy lists of all users",
	    jid);
}

static void
cmd_all(void)
{
	int i, j;

	for (i = 0; i < nactive; i++)
		for (j = i + 1; j < nactive; j++)
			if (same_domain(active[i], active[j]))
				pair(active[i], active[j], NULL);
	logmsg(LOG_NOTICE, "made all users buddies");
}

static void
cmd_group(const char *arg, int by_gid)
{
	struct group_info *g = group_lookup(arg, by_gid);
	int i, j;

	/* mod_autobuddy adds members who sign in later */
	run("INSERT OR IGNORE INTO \"autobuddy-groups\" (\"group\") "
	    "VALUES (?)", 1, g->name);
	for (i = 0; i < nactive; i++) {
		if (!group_has(g, jid_node(active[i])))
			continue;
		for (j = i + 1; j < nactive; j++)
			if (same_domain(active[i], active[j]) &&
			    group_has(g, jid_node(active[j])))
				pair(active[i], active[j], g->name);
	}
	logmsg(LOG_NOTICE, "made the members of group %s buddies", g->name);
}

static void
cmd_ungroup(const char *arg, int by_gid)
{
	struct group_info *g = group_lookup(arg, by_gid);
	int i, j;

	run("DELETE FROM \"autobuddy-groups\" WHERE \"group\" = ?", 1,
	    g->name);
	for (i = 0; i < nactive; i++) {
		if (!group_has(g, jid_node(active[i])))
			continue;
		for (j = i + 1; j < nactive; j++)
			if (same_domain(active[i], active[j]) &&
			    group_has(g, jid_node(active[j])))
				unpair(active[i], active[j]);
	}
	logmsg(LOG_NOTICE, "removed the buddy pairings of group %s", g->name);
}

static void
cmd_move_domain(const char *from, const char *to)
{
	static const char *columns[] = { "collection-owner", "jid" };
	char **tables, *q, *sql;
	int n, i, c, moved = 0;

	tables = owner_tables(&n);
	for (i = 0; i < n; i++) {
		q = quote(tables[i]);
		for (c = 0; c < 2; c++) {
			char *col;

			if (!has_column(tables[i], columns[c]))
				continue;
			col = quote(columns[c]);
			/* user@from -> user@to; no LIKE, as domains contain _ */
			sql = sqlite3_mprintf("UPDATE %s SET %s = "
			    "substr(%s, 1, length(%s) - length(?1)) || ?2 "
			    "WHERE length(%s) > length(?1) + 1 AND "
			    "substr(%s, -length(?1) - 1) = '@' || ?1",
			    q, col, col, col, col, col);
			moved += run(sql, 2, from, to);
			sqlite3_free(sql);
			sqlite3_free(col);
		}
		sqlite3_free(q);
		free(tables[i]);
	}
	free(tables);
	logmsg(LOG_NOTICE, "moved %s to %s (%d rows)", from, to, moved);
}

static void
check_domain(const char *d)
{
	const char *p;

	if (*d == '\0')
		errx(1, "empty domain");
	for (p = d; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' &&
		    *p != '_')
			errx(1, "%s: not a domain name", d);
}

/*
 * Open the database as its owner, so that files SQLite creates next to it
 * (the -wal and -shm files) stay usable by the jabber user.
 */
static void
open_db(const char *path)
{
	struct stat sb;

	if (stat(path, &sb) == -1)
		err(1, "%s", path);
	if (geteuid() == 0 && sb.st_uid != 0) {
		if (setgroups(1, &sb.st_gid) == -1 || setgid(sb.st_gid) == -1 ||
		    setuid(sb.st_uid) == -1)
			err(1, "cannot switch to the owner of %s", path);
	}
	if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) !=
	    SQLITE_OK)
		errx(1, "%s: %s", path, sqlite3_errmsg(db));
	sqlite3_busy_timeout(db, 10000);
	if (count("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' "
	    "AND name IN ('active', 'roster-items', 'roster-groups', "
	    "'autobuddy-groups')", 0) != 4)
		errx(1, "%s: not a ChatServer (jabberd2) database", path);
}

static void
usage(int status)
{
	FILE *f = status == 0 ? stdout : stderr;

	fprintf(f,
"usage: jabber_autobuddy [-V] [-f database] command ...\n"
"\n"
"Manages buddies (roster entries) in ChatServer's jabberd2 database.\n"
"JIDs are user@domain; buddies are only made between users of one domain.\n"
"\n"
"commands:\n"
"  -i, --inituser JID         add JID to the database\n"
"  -d, --deleteuser JID       delete JID and all of its data\n"
"  -a, --addbuddy JID         make JID a buddy of every user\n"
"  -r, --removebuddy JID      take JID off every user's buddy list\n"
"  -m, --all                  make every user a buddy of every other user\n"
"  -g, --group GROUP          make the members of GROUP buddies, now and\n"
"                             whenever members sign in\n"
"  -G, --group-by-id GID      the same, by numeric group ID\n"
"  -u, --ungroup GROUP        undo --group\n"
"  -U, --ungroup-by-id GID    undo --group-by-id\n"
"  -M, --move-domain FROM TO  move all users from domain FROM to TO\n"
"\n"
"options:\n"
"  -f, --database PATH        the SQLite database (default %s)\n"
"  -V, --verbose              report each change on standard error\n"
"  -v, --version              show the version\n"
"  -h, --help                 show this help\n"
"\n"
"Commands may be repeated, and run in this order: --deleteuser,\n"
"--inituser, --removebuddy, --addbuddy, then one of --all, --group or\n"
"--ungroup. Users who are signed in see the changes when they next sign in.\n",
	    DEFAULT_DB);
	exit(status);
}

int
main(int argc, char *argv[])
{
	/* Apple's spellings (--i, --m, ...) are accepted as well */
	static const struct option longopts[] = {
		{ "inituser",		required_argument, NULL, 'i' },
		{ "deleteuser",		required_argument, NULL, 'd' },
		{ "addbuddy",		required_argument, NULL, 'a' },
		{ "removebuddy",	required_argument, NULL, 'r' },
		{ "all",		no_argument,	   NULL, 'm' },
		{ "group",		required_argument, NULL, 'g' },
		{ "group-by-id",	required_argument, NULL, 'G' },
		{ "ungroup",		required_argument, NULL, 'u' },
		{ "ungroup-by-id",	required_argument, NULL, 'U' },
		{ "move-domain",	required_argument, NULL, 'M' },
		{ "database",		required_argument, NULL, 'f' },
		{ "verbose",		no_argument,	   NULL, 'V' },
		{ "version",		no_argument,	   NULL, 'v' },
		{ "help",		no_argument,	   NULL, 'h' },
		{ "i", required_argument, NULL, 'i' },
		{ "d", required_argument, NULL, 'd' },
		{ "a", required_argument, NULL, 'a' },
		{ "r", required_argument, NULL, 'r' },
		{ "m", no_argument,	  NULL, 'm' },
		{ "g", required_argument, NULL, 'g' },
		{ "G", required_argument, NULL, 'G' },
		{ "u", required_argument, NULL, 'u' },
		{ "U", required_argument, NULL, 'U' },
		{ "M", required_argument, NULL, 'M' },
		{ NULL, 0, NULL, 0 }
	};
	char *init[MAXJIDS], *del[MAXJIDS], *add[MAXJIDS], *rem[MAXJIDS];
	int ninit = 0, ndel = 0, nadd = 0, nrem = 0;
	const char *dbpath = DEFAULT_DB, *group = NULL, *mfrom = NULL;
	const char *mto = NULL;
	int ch, all = 0, ungroup = 0, by_gid = 0, bulk = 0, help = 0, ver = 0;
	int i;

	openlog("jabber_autobuddy", LOG_PID, LOG_DAEMON);

	if (argc == 1)
		usage(1);

	while ((ch = getopt_long(argc, argv, "i:d:a:r:mg:G:u:U:M:f:Vvh?",
	    longopts, NULL)) != -1) {
		switch (ch) {
		case 'i':
		case 'd':
		case 'a':
		case 'r': {
			char **list = ch == 'i' ? init : ch == 'd' ? del :
			    ch == 'a' ? add : rem;
			int *n = ch == 'i' ? &ninit : ch == 'd' ? &ndel :
			    ch == 'a' ? &nadd : &nrem;

			if (*n == MAXJIDS)
				errx(1, "too many JIDs");
			list[(*n)++] = check_jid(optarg);
			break;
		}
		case 'm':
			all = 1;
			break;
		case 'g':
		case 'G':
		case 'u':
		case 'U':
			if (group != NULL && strcmp(group, optarg) != 0)
				errx(1, "only one group per run");
			group = optarg;
			ungroup = (ch == 'u' || ch == 'U');
			by_gid = (ch == 'G' || ch == 'U');
			break;
		case 'M':
			if (optind >= argc)
				errx(1, "--move-domain needs FROM-DOMAIN "
				    "and TO-DOMAIN");
			mfrom = optarg;
			mto = argv[optind++];
			check_domain(mfrom);
			check_domain(mto);
			break;
		case 'f':
			dbpath = optarg;
			break;
		case 'V':
			verbose = 1;
			break;
		case 'v':
			ver = 1;
			break;
		case 'h':
			help = 1;
			break;
		case '?':
			help = 2;
			break;
		default:
			usage(1);
		}
	}
	if (optind != argc)
		usage(1);
	if (help)
		usage(help == 1 ? 0 : 1);
	if (ver) {
		printf("jabber_autobuddy %s\n", VERSION);
		return (0);
	}
	bulk = all + (group != NULL);
	if (bulk > 1)
		errx(1, "--all, --group and --ungroup cannot be combined");

	open_db(dbpath);
	if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
		dbfail("BEGIN");

	for (i = 0; i < ndel; i++)
		cmd_deleteuser(del[i]);
	for (i = 0; i < ninit; i++)
		cmd_inituser(init[i]);
	load_active();
	for (i = 0; i < nrem; i++)
		cmd_removebuddy(rem[i]);
	for (i = 0; i < nadd; i++)
		cmd_addbuddy(add[i]);
	if (all)
		cmd_all();
	else if (group != NULL && ungroup)
		cmd_ungroup(group, by_gid);
	else if (group != NULL)
		cmd_group(group, by_gid);
	if (mfrom != NULL)
		cmd_move_domain(mfrom, mto);

	if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
		dbfail("COMMIT");
	sqlite3_close(db);
	return (0);
}
