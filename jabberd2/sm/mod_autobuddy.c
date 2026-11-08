/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2008 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris, Tomasz Sterna
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/** @file sm/mod_autobuddy.c
  * @brief automatic buddies for members of the same group
  *
  * The FreeBSD version of Apple's ChatServer mod_autobuddy. When a user is
  * loaded, every other active user of the same domain who shares one of the
  * groups listed in the "autobuddy-groups" table becomes a buddy (subscription
  * both), filed under a roster group named after that group. Apple's module
  * used Open Directory group GUIDs; this one uses the system's groups
  * (getgrnam(3)), so it covers local groups and any directory the name
  * service switch reaches, such as LDAP through nss-pam-ldapd.
  *
  * Groups are added and removed with jabber_autobuddy(8) --group/--ungroup.
  * Roster items the user already has are left alone, so renamed or
  * regrouped buddies stay as the user set them.
  *
  * This module must come before "roster" in the user-load chain, and needs a
  * storage driver with custom SQL support (sqlite).
  */

#include "sm.h"

#include <grp.h>
#include <pwd.h>

#define AB_GROUPS_SQL   "SELECT \"group\" FROM \"autobuddy-groups\""
#define AB_ACTIVE_SQL   "SELECT \"collection-owner\" FROM \"active\""

typedef struct ab_group_st {
    char    *name;
    gid_t   gid;
    char    **members;  /* NULL-terminated */
} *ab_group_t;

static void _ab_group_free(ab_group_t g) {
    char **m;

    if(g == NULL) return;
    if(g->members != NULL) {
        for(m = g->members; *m != NULL; m++)
            free(*m);
        free(g->members);
    }
    free(g->name);
    free(g);
}

/** copy what we need out of getgrnam()'s static buffer */
static ab_group_t _ab_group_load(const char *name) {
    struct group *gr;
    ab_group_t g;
    int n, i;

    if((gr = getgrnam(name)) == NULL)
        return NULL;

    for(n = 0; gr->gr_mem[n] != NULL; n++);

    g = (ab_group_t) calloc(1, sizeof(struct ab_group_st));
    g->name = strdup(gr->gr_name);
    g->gid = gr->gr_gid;
    g->members = (char **) calloc(n + 1, sizeof(char *));
    for(i = 0; i < n; i++)
        g->members[i] = strdup(gr->gr_mem[i]);

    return g;
}

/** members are listed in the group, or have it as their primary group */
static int _ab_is_member(ab_group_t g, const char *user) {
    struct passwd *pw;
    char **m;

    for(m = g->members; *m != NULL; m++)
        if(strcmp(*m, user) == 0)
            return 1;

    pw = getpwnam(user);
    return (pw != NULL && pw->pw_gid == g->gid);
}

/** the user's full name, from the first field of the GECOS field */
static void _ab_full_name(const char *user, char *buf, size_t len) {
    struct passwd *pw;
    size_t n;

    buf[0] = '\0';
    if((pw = getpwnam(user)) == NULL || pw->pw_gecos == NULL)
        return;

    n = strcspn(pw->pw_gecos, ",");
    if(n >= len) n = len - 1;
    memcpy(buf, pw->pw_gecos, n);
    buf[n] = '\0';
}

static void _ab_add_buddy(user_t user, jid_t buddy, ab_group_t *groups, int ngroups) {
    char filter[4096], name[256];
    const char *bjid = jid_user(buddy);
    int count = 0, i, yes = 1, no = 0;
    os_t os;
    os_object_t o;

    snprintf(filter, sizeof(filter), "(jid=%zu:%s)", strlen(bjid), bjid);

    /* leave existing roster items alone */
    if(storage_count(user->sm->st, "roster-items", jid_user(user->jid), filter, &count) != st_SUCCESS || count > 0)
        return;

    log_debug(ZONE, "autobuddy: adding %s to the roster of %s", bjid, jid_user(user->jid));

    _ab_full_name(buddy->node, name, sizeof(name));

    os = os_new();
    o = os_object_new(os);
    os_object_put(o, "jid", bjid, os_type_STRING);
    if(name[0] != '\0')
        os_object_put(o, "name", name, os_type_STRING);
    os_object_put(o, "to", &yes, os_type_BOOLEAN);
    os_object_put(o, "from", &yes, os_type_BOOLEAN);
    os_object_put(o, "ask", &no, os_type_INTEGER);
    storage_put(user->sm->st, "roster-items", jid_user(user->jid), os);
    os_free(os);

    os = os_new();
    for(i = 0; i < ngroups; i++) {
        if(!_ab_is_member(groups[i], buddy->node))
            continue;
        o = os_object_new(os);
        os_object_put(o, "jid", bjid, os_type_STRING);
        os_object_put(o, "group", groups[i]->name, os_type_STRING);
    }
    if(os_count(os) > 0)
        storage_put(user->sm->st, "roster-groups", jid_user(user->jid), os);
    os_free(os);
}

static int _autobuddy_user_load(mod_instance_t mi, user_t user) {
    ab_group_t *groups = NULL;
    int ngroups = 0, i;
    os_t os = NULL;
    os_object_t o;
    char *str;
    jid_t buddy;

    if(user->jid->node == NULL || user->jid->node[0] == '\0')
        return 0;

    /* the autobuddy groups this user is in */
    if(storage_get_custom_sql(user->sm->st, AB_GROUPS_SQL, &os, NULL) != st_SUCCESS)
        return 0;

    groups = (ab_group_t *) calloc(os_count(os), sizeof(ab_group_t));
    if(os_iter_first(os))
        do {
            ab_group_t g;

            o = os_iter_object(os);
            if(!os_object_get_str(os, o, "group", &str))
                continue;

            if((g = _ab_group_load(str)) == NULL) {
                log_write(user->sm->log, LOG_NOTICE, "autobuddy: no such group: %s", str);
                continue;
            }

            if(_ab_is_member(g, user->jid->node))
                groups[ngroups++] = g;
            else
                _ab_group_free(g);
        } while(os_iter_next(os));
    os_free(os);
    os = NULL;

    if(ngroups == 0)
        goto done;

    /* the other active users of this domain who share one of those groups */
    if(storage_get_custom_sql(user->sm->st, AB_ACTIVE_SQL, &os, NULL) != st_SUCCESS)
        goto done;

    if(os_iter_first(os))
        do {
            o = os_iter_object(os);
            if(!os_object_get_str(os, o, "collection-owner", &str))
                continue;

            if((buddy = jid_new(str, -1)) == NULL)
                continue;

            if(buddy->node[0] != '\0' &&
               strcmp(buddy->domain, user->jid->domain) == 0 &&
               strcmp(buddy->node, user->jid->node) != 0) {
                for(i = 0; i < ngroups; i++)
                    if(_ab_is_member(groups[i], buddy->node)) {
                        _ab_add_buddy(user, buddy, groups, ngroups);
                        break;
                    }
            }

            jid_free(buddy);
        } while(os_iter_next(os));
    os_free(os);

done:
    for(i = 0; i < ngroups; i++)
        _ab_group_free(groups[i]);
    free(groups);

    /* never stop the user from loading */
    return 0;
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->user_load = _autobuddy_user_load;

    return 0;
}
