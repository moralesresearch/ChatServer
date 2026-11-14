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
  * The name and the roster groups of an item the user already has are left
  * alone, so renamed or regrouped buddies stay as the user set them; its
  * subscription is put back to "both" if it is anything else.
  *
  * Both sides are done at once. The user being loaded gets the item in
  * storage, where mod_roster reads it next. If the buddy is loaded as well,
  * the buddy's roster in memory gets the matching item (and the buddy's
  * clients a roster push): otherwise the buddy's sm would not know the new
  * user, would answer the user's presence probe with "unsubscribed", and
  * that answer would turn the new item into a one-way one for good.
  *
  * Group membership comes from the name service, which can be slow (LDAP),
  * and users are loaded often (for every stanza sent to a user who is not
  * signed in), so it is cached for AB_CACHE_TTL seconds. A change to the
  * autobuddy-groups table is seen at once.
  *
  * This module must come before "roster" in the user-load chain, and needs a
  * storage driver with custom SQL support (sqlite).
  */

#include "sm.h"

#include <grp.h>
#include <pwd.h>

#define AB_GROUPS_SQL   "SELECT \"group\" FROM \"autobuddy-groups\" ORDER BY \"group\""
#define AB_ACTIVE_SQL   "SELECT \"collection-owner\" FROM \"active\""

/** how long group membership is believed, in seconds */
#define AB_CACHE_TTL    60

typedef struct ab_group_st {
    char    *name;
    gid_t   gid;
    char    **members;  /* NULL-terminated */
} *ab_group_t;

/** module data: what the name service said, for AB_CACHE_TTL seconds */
typedef struct ab_cache_st {
    time_t      loaded;     /**< when it was filled */
    char        *table;     /**< the autobuddy-groups table it was filled for, one name per line */
    ab_group_t  *groups;    /**< the groups of the table that exist */
    int         ngroups;
    xht         gids;       /**< user name -> primary gid (gid_t *), or &_ab_no_user */
} *ab_cache_t;

/** cached answer for a user the name service does not know */
static gid_t _ab_no_user;

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

static void _ab_cache_clear(ab_cache_t cache) {
    int i;

    for(i = 0; i < cache->ngroups; i++)
        _ab_group_free(cache->groups[i]);
    free(cache->groups);
    cache->groups = NULL;
    cache->ngroups = 0;

    free(cache->table);
    cache->table = NULL;

    if(cache->gids != NULL)
        xhash_free(cache->gids);
    cache->gids = NULL;

    cache->loaded = 0;
}

/**
 * the groups of the autobuddy-groups table, with their members. The table
 * is read every time (one cheap query); the name service is only asked
 * when the table changed or the cache is older than AB_CACHE_TTL.
 */
static ab_cache_t _ab_cache_get(module_t mod, sm_t sm) {
    ab_cache_t cache = (ab_cache_t) mod->private;
    os_t os = NULL;
    os_object_t o;
    char *str, *table;
    size_t len = 0, n;
    time_t now = time(NULL);
    ab_group_t g;

    /* the table, as one string */
    table = strdup("");
    if(storage_get_custom_sql(sm->st, AB_GROUPS_SQL, &os, NULL) == st_SUCCESS) {
        if(os_iter_first(os))
            do {
                o = os_iter_object(os);
                if(!os_object_get_str(os, o, "group", &str))
                    continue;
                n = strlen(str);
                table = (char *) realloc(table, len + n + 2);
                memcpy(table + len, str, n);
                table[len + n] = '\n';
                table[len + n + 1] = '\0';
                len += n + 1;
            } while(os_iter_next(os));
        os_free(os);
    }

    if(cache->table != NULL && strcmp(cache->table, table) == 0 &&
       now >= cache->loaded && now - cache->loaded < AB_CACHE_TTL) {
        free(table);
        return cache;
    }

    _ab_cache_clear(cache);
    cache->table = table;
    cache->loaded = now;
    cache->gids = xhash_new(101);

    /* count the lines, then load each group */
    for(n = 0, str = table; *str != '\0'; str++)
        if(*str == '\n')
            n++;
    cache->groups = (ab_group_t *) calloc(n + 1, sizeof(ab_group_t));

    table = strdup(cache->table);
    for(str = strtok(table, "\n"); str != NULL; str = strtok(NULL, "\n")) {
        if((g = _ab_group_load(str)) == NULL) {
            log_write(sm->log, LOG_NOTICE, "autobuddy: no such group: %s", str);
            continue;
        }
        cache->groups[cache->ngroups++] = g;
    }
    free(table);

    return cache;
}

/** members are listed in the group, or have it as their primary group */
static int _ab_is_member(ab_cache_t cache, ab_group_t g, const char *user) {
    struct passwd *pw;
    gid_t *gid;
    char **m;

    for(m = g->members; *m != NULL; m++)
        if(strcmp(*m, user) == 0)
            return 1;

    /* the primary group: asked once per user and cache lifetime */
    gid = (gid_t *) xhash_get(cache->gids, user);
    if(gid == NULL) {
        if((pw = getpwnam(user)) == NULL)
            gid = &_ab_no_user;
        else {
            gid = (gid_t *) pmalloc(xhash_pool(cache->gids), sizeof(gid_t));
            *gid = pw->pw_gid;
        }
        xhash_put(cache->gids, pstrdup(xhash_pool(cache->gids), user), (void *) gid);
    }

    return (gid != &_ab_no_user && *gid == g->gid);
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

/**
 * make sure the stored roster of owner has buddy with subscription both.
 * A missing item is added, named after the buddy and filed under the
 * groups (of the ngroups given) the buddy is in. An item that is there
 * keeps its name and groups. Returns 1 if the item was added, 2 if its
 * subscription was repaired, 0 if it was fine, -1 on a storage error.
 */
static int _ab_store_item(sm_t sm, ab_cache_t cache, const char *owner, jid_t buddy, ab_group_t *groups, int ngroups) {
    char filter[4096], name[256];
    const char *bjid = jid_user(buddy);
    int i, yes = 1, no = 0, to = 0, from = 0, added;
    os_t os = NULL;
    os_object_t o;
    char *str;
    st_ret_t ret;

    snprintf(filter, sizeof(filter), "(jid=%zu:%s)", strlen(bjid), bjid);
    name[0] = '\0';

    ret = storage_get(sm->st, "roster-items", owner, filter, &os);
    if(ret == st_SUCCESS) {
        added = 0;
        if(os_iter_first(os)) {
            o = os_iter_object(os);
            os_object_get_bool(os, o, "to", &to);
            os_object_get_bool(os, o, "from", &from);
            if(os_object_get_str(os, o, "name", &str) && str != NULL)
                snprintf(name, sizeof(name), "%s", str);
        }
        os_free(os);

        if(to && from)
            return 0;

        log_debug(ZONE, "autobuddy: repairing %s in the roster of %s", bjid, owner);
    } else if(ret == st_NOTFOUND) {
        added = 1;
        _ab_full_name(buddy->node, name, sizeof(name));

        log_debug(ZONE, "autobuddy: adding %s to the roster of %s", bjid, owner);
    } else
        return -1;

    /* replace, not put: there is never more than one row for a buddy */
    os = os_new();
    o = os_object_new(os);
    os_object_put(o, "jid", bjid, os_type_STRING);
    if(name[0] != '\0')
        os_object_put(o, "name", name, os_type_STRING);
    os_object_put(o, "to", &yes, os_type_BOOLEAN);
    os_object_put(o, "from", &yes, os_type_BOOLEAN);
    os_object_put(o, "ask", &no, os_type_INTEGER);
    ret = storage_replace(sm->st, "roster-items", owner, filter, os);
    os_free(os);
    if(ret != st_SUCCESS)
        return -1;

    if(!added)
        return 2;

    os = os_new();
    for(i = 0; i < ngroups; i++) {
        if(!_ab_is_member(cache, groups[i], buddy->node))
            continue;
        o = os_object_new(os);
        os_object_put(o, "jid", bjid, os_type_STRING);
        os_object_put(o, "group", groups[i]->name, os_type_STRING);
    }
    if(os_count(os) > 0)
        storage_replace(sm->st, "roster-groups", owner, filter, os);
    os_free(os);

    return 1;
}

/** send the roster item to the user's sessions that have asked for their roster, as mod_roster does */
static void _ab_roster_push(user_t user, item_t item) {
    module_t roster = (module_t) xhash_get(user->sm->mm->modules, "roster");
    sess_t scan;
    pkt_t pkt;
    int ns, elem, i;

    if(roster == NULL || user->sessions == NULL)
        return;

    pkt = pkt_create(user->sm, "iq", "set", NULL, NULL);
    pkt_id_new(pkt);
    ns = nad_add_namespace(pkt->nad, uri_ROSTER, NULL);
    elem = nad_append_elem(pkt->nad, ns, "query", 3);

    /* the item is built exactly as mod_roster's _roster_insert_item does */
    ns = nad_add_namespace(pkt->nad, uri_CLIENT, NULL);
    elem = nad_insert_elem(pkt->nad, elem, ns, "item", NULL);
    nad_set_attr(pkt->nad, elem, -1, "jid", jid_full(item->jid), 0);
    nad_set_attr(pkt->nad, elem, -1, "subscription", "both", 4);
    if(item->name != NULL)
        nad_set_attr(pkt->nad, elem, -1, "name", item->name, 0);
    for(i = 0; i < item->ngroups; i++)
        nad_insert_elem(pkt->nad, elem, NAD_ENS(pkt->nad, elem), "group", item->groups[i]);

    for(scan = user->sessions; scan != NULL; scan = scan->next)
        if(scan->module_data[roster->index] != NULL)
            pkt_sess(pkt_dup(pkt, jid_full(scan->jid), NULL), scan);

    pkt_free(pkt);
}

/**
 * the buddy is loaded: give its roster in memory (and in storage) the item
 * for the user, so that the two agree from now on
 */
static void _ab_reciprocate(ab_cache_t cache, user_t buddy, jid_t user, ab_group_t *groups, int ngroups) {
    item_t item;
    char name[256];
    int i;

    if(buddy->roster == NULL)
        return;

    item = (item_t) xhash_get(buddy->roster, jid_user(user));
    if(item != NULL && item->to && item->from)
        return;

    if(_ab_store_item(buddy->sm, cache, jid_user(buddy->jid), user, groups, ngroups) < 0)
        return;

    if(item == NULL) {
        /* allocated as mod_roster does, which frees it */
        item = (item_t) calloc(1, sizeof(struct item_st));
        item->jid = jid_new(jid_user(user), -1);
        if(item->jid == NULL) {
            free(item);
            return;
        }

        _ab_full_name(user->node, name, sizeof(name));
        if(name[0] != '\0')
            item->name = strdup(name);

        for(i = 0; i < ngroups; i++) {
            if(!_ab_is_member(cache, groups[i], user->node))
                continue;
            item->groups = realloc(item->groups, sizeof(char *) * (item->ngroups + 1));
            item->groups[item->ngroups++] = strdup(groups[i]->name);
        }

        xhash_put(buddy->roster, jid_full(item->jid), (void *) item);
    }

    item->to = item->from = 1;
    item->ask = 0;

    log_debug(ZONE, "autobuddy: %s now has %s, both ways", jid_user(buddy->jid), jid_user(user));

    _ab_roster_push(buddy, item);
}

static int _autobuddy_user_load(mod_instance_t mi, user_t user) {
    ab_cache_t cache;
    ab_group_t *groups = NULL;
    int ngroups = 0, i;
    os_t os = NULL;
    os_object_t o;
    char *str;
    jid_t buddy;
    user_t loaded;

    if(user->jid->node == NULL || user->jid->node[0] == '\0')
        return 0;

    cache = _ab_cache_get(mi->mod, user->sm);
    if(cache->ngroups == 0)
        return 0;

    /* the autobuddy groups this user is in */
    groups = (ab_group_t *) calloc(cache->ngroups, sizeof(ab_group_t));
    for(i = 0; i < cache->ngroups; i++)
        if(_ab_is_member(cache, cache->groups[i], user->jid->node))
            groups[ngroups++] = cache->groups[i];

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
                    if(_ab_is_member(cache, groups[i], buddy->node)) {
                        /* this user's side: mod_roster loads it next */
                        _ab_store_item(user->sm, cache, jid_user(user->jid), buddy, groups, ngroups);

                        /* the buddy's side, if the buddy is loaded */
                        loaded = (user_t) xhash_get(user->sm->users, jid_user(buddy));
                        if(loaded != NULL)
                            _ab_reciprocate(cache, loaded, user->jid, groups, ngroups);
                        break;
                    }
            }

            jid_free(buddy);
        } while(os_iter_next(os));
    os_free(os);

done:
    /* the groups themselves belong to the cache */
    free(groups);

    /* never stop the user from loading */
    return 0;
}

static void _autobuddy_free(module_t mod) {
    ab_cache_t cache = (ab_cache_t) mod->private;

    if(cache == NULL)
        return;

    _ab_cache_clear(cache);
    free(cache);
    mod->private = NULL;
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->private = calloc(1, sizeof(struct ab_cache_st));

    mod->user_load = _autobuddy_user_load;
    mod->free = _autobuddy_free;

    return 0;
}
