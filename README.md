# ChatServer for FreeBSD

Apple's ChatServer — the jabberd2 XMPP (Jabber) server of OS X Server — ported
to FreeBSD 14 for the SunOS server edition.

The `main` branch is Apple's source, ChatServer-409 (OS X Server 3.0.2), from
[apple-oss-distributions/ChatServer](https://github.com/apple-oss-distributions/ChatServer).
This branch, `freebsd-port`, is the port.

## What is here

| Path | What it is |
| --- | --- |
| `jabberd2/` | jabberd2 2.7.0, the last upstream release, with Apple's changes forward-ported |
| `jabberd2/sm/mod_autobuddy.c` | Apple's auto-buddy module, using system groups instead of Open Directory groups |
| `jabber_autobuddy/` | `jabber_autobuddy(8)`, Apple's buddy management tool, rewritten in C |
| `pamauth/` | `pamauth(8)`, the PAM sign-in helper that replaces Apple's Open Directory login (`jabber_od_auth`) |
| `freebsd/rc.d/chatserver` | rc.d script; the service is off by default |
| `freebsd/pam.d/jabberd` | PAM policy |
| `freebsd/tests/` | End-to-end test, run in a FreeBSD 14.5 VM by `.github/workflows/freebsd.yml` |

### Apple's ChatServer changes

ChatServer-409 is jabberd 2.2.17 (2012) plus about 30 Apple patches. jabberd2
2.7.0 already contains most of them (private key passwords, router CA chains,
the CRAM-MD5 hooks, custom SQL in the storage API, message logging), and it
builds against OpenSSL 1.1 and 3. This port starts from 2.7.0 and carries:

- **mod_autobuddy**: when a user signs in, every other user of the same
  domain who shares one of the chosen groups becomes a buddy, under a roster
  group named after the group. Apple used Open Directory group GUIDs; this
  uses system groups (`getgrnam(3)`), so local groups and LDAP groups through
  the name service switch both work. Groups are chosen with
  `jabber_autobuddy --group`.
- **jabber_autobuddy**: the same commands as Apple's (`--inituser`,
  `--deleteuser`, `--addbuddy`, `--removebuddy`, `--all`, `--group`,
  `--group-by-id`, `--ungroup`, `--ungroup-by-id`, `--move-domain`, and
  Apple's `--i`-style spellings). Group IDs are numeric GIDs.
- The `autobuddy-groups` table and Apple's roster index in `db-setup.sqlite`,
  and the SQLite side of `storage_get_custom_sql`.

Fixed in jabberd2 2.7.0 while porting:

- c2s identified client sessions by socket fd number. The kernel gives that
  number to the next connection as soon as a client disconnects, so late
  packets from the sm for the old session (route errors in particular, which
  close the stream) could reset a new client's connection. Sessions now get
  ids that are never reused.
- XEP-0202 time: FreeBSD's `timezone` is a function, not the UTC offset, so
  the reported offset was garbage; it now comes from `tm_gmtoff`.
- TLS: TLS 1.2 is the minimum, and with OpenSSL 3, Diffie-Hellman groups are
  OpenSSL's automatic RFC 7919 groups in place of a callback whose smallest
  group was 1024 bits.
- `configure.ac` no longer needs autoconf-archive.

Replaced or dropped:

- **Open Directory login** (`jabber_od_auth`, `authreg_apple_od`): replaced
  by PAM. c2s uses jabberd2's `pipe` authreg module with `pamauth`, a small
  setuid-root helper (`pam_unix` can only check passwords as root), so c2s
  runs as `jabber`. Apple's chat service access list (SACL) becomes
  `pam_group(8)` in `/usr/local/etc/pam.d/jabberd`. jabberd2's own `ldapfull`
  (LDAP bind) and `pam` modules are built too.
- Mac-only parts: the Xcode project, Server Admin backup, restore, migration
  and promotion scripts, launchd and `/Library` paths, the Darwin configure
  cache, and Apple's patch tool.
- Apple's message-log rolling (use `newsyslog(8)`), the Python 2 `proxy65`
  file transfer proxy, and CRAM-MD5 (Open Directory only).

## Building

On FreeBSD 14:

```sh
pkg install autoconf automake libtool pkgconf gmake expat libidn udns gsasl \
    sqlite3 openldap26-client
make
make install        # as root; creates the jabber user and group (93)
```

OpenSSL is the base system's. Everything installs under `/usr/local`:
components in `libexec/jabberd`, modules in `lib/jabberd`, configuration in
`etc/jabberd`, and data in `/var/db/jabberd`.

## Running

1. Set your domain in place of `localhost.localdomain` in
   `/usr/local/etc/jabberd/sm.xml` and `c2s.xml`.
2. Optionally put a certificate and key in `/usr/local/etc/jabberd/server.pem`
   (mode 640, group `jabber`). Otherwise a self-signed one is created at
   first start.
3. Start it:

   ```sh
   sysrc chatserver_enable=YES
   service chatserver start
   ```

Users sign in with their system account name and password, over STARTTLS.
To make the members of a group buddies of each other, now and whenever
members sign in:

```sh
jabber_autobuddy --group staff
```

## Testing

`freebsd/tests/run.sh` (as root, after `make install`, on a scratch system)
creates test accounts and groups, starts the service, signs in with a small
XMPP client (`xmpp_client.py`), and checks PAM sign-in, TLS, auto-buddies,
`jabber_autobuddy`, `pam_group` and the rc.d script. The GitHub mirror runs it
in a FreeBSD 14.5 VM on every push.

## Licenses

jabberd2 is GPL 2 or later (`jabberd2/COPYING`); the new code here
(`mod_autobuddy.c`, `jabber_autobuddy`, `pamauth`) is under the same license.
Apple's original sources are on the `main` branch. Some of them — the Server
Admin scripts and Apple's patch tool — are licensed by Apple for use on
Apple-branded computers only, so none of their code is used here, and Apple's
Objective-C `jabber_autobuddy`, which carries no license grant, was rewritten
rather than ported.

Security fixes are this repository's responsibility: jabberd2 upstream has had
no release since 2.7.0 (2018). jabberd2 still uses some OpenSSL APIs that
OpenSSL 3 deprecates (low-level DH, EC_KEY, SHA1 and MD5 calls); they build with
warnings, and would need replacing for an OpenSSL release that removes them.
