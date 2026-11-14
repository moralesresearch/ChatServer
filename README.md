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
| `freebsd/pam.d/jabberd` | PAM policy: members of the `chat` group may sign in |
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
- TLS: TLS 1.2 is the minimum. With OpenSSL 3, when the certificate file
  holds no Diffie-Hellman parameters of its own, OpenSSL picks a built-in
  group to match the key (the RFC 3526 MODP groups, 2048 bits or more at
  the default security level) in place of a callback whose smallest group
  was 1024 bits. Parameters in the certificate file are used if present.
- The `pipe` sign-in module (`storage/authreg_pipe.c`), which carries every
  password check to `pamauth`: requests that do not fit a line are not sent,
  user names are checked before they are written to the helper, replies are
  read with a time limit, and after any error the helper is replaced, so a
  client can neither hang c2s nor get another request's answer.
- c2s closes a stream after three failed sign-in attempts, and offers
  `jabber:iq:auth` only when the configuration enables it (it does not).
- `configure.ac` no longer needs autoconf-archive.

Replaced or dropped:

- **Open Directory login** (`jabber_od_auth`, `authreg_apple_od`): replaced
  by PAM. c2s uses jabberd2's `pipe` authreg module with `pamauth`, a small
  setuid-root helper (`pam_unix` can only check passwords as root), so c2s
  runs as `jabber`. Apple's chat service access list (SACL) becomes
  `pam_group(8)` in `/usr/local/etc/pam.d/jabberd`: only members of the
  `chat` group may sign in. jabberd2's own `ldapfull` (LDAP bind) and `pam`
  modules are built too.
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
                    # and the chat group
```

OpenSSL is the base system's. Everything installs under `/usr/local`:
components in `libexec/jabberd`, modules in `lib/jabberd`, configuration in
`etc/jabberd` (mode 640, `root:jabber`), and data in `/var/db/jabberd`.

`make install DESTDIR=/path` installs into an image being built. `DESTDIR`
must be a whole FreeBSD root, not an empty staging directory: the `jabber`
user and the `chat` group are added to its password database (`pw -R`), and
the host needs a `jabber` group too, for the ownership of the installed
files. Nothing that is secret is made at install time, so every copy of an
image starts out the same; see "The router secret" below.

## Running

1. Set your domain in place of `localhost.localdomain` in
   `/usr/local/etc/jabberd/sm.xml` and `c2s.xml`.
2. Put a certificate for that domain, followed by its key, in
   `/usr/local/etc/jabberd/server.pem` (mode 640, `root:jabber`). See
   "The certificate" below; without one, a self-signed certificate is
   created at first start.
3. Let people in: only members of the `chat` group may sign in, and
   `make install` creates the group empty.

   ```sh
   pw groupmod chat -m alice,bob
   ```

4. Start it:

   ```sh
   sysrc chatserver_enable=YES
   service chatserver start
   ```

Users sign in with their system account name and password, with SASL PLAIN
over STARTTLS. To make the members of a group buddies of each other, now and
whenever members sign in:

```sh
jabber_autobuddy --group staff
```

Things to know about `jabber_autobuddy`:

- `--ungroup` removes every roster entry between two members of the group,
  including entries the users added themselves.
- The session manager keeps the roster of a signed-in user in memory.
  Changes made with `jabber_autobuddy` show at the user's next sign-in, and a
  roster change the user makes in the meantime is written from the copy in
  memory, which can undo the tool's change to that entry.
- Stop the service before `--move-domain` and `--deleteuser`.
- Group membership is cached by the session manager for a minute; groups
  added with `--group` or removed with `--ungroup` are noticed at once.

### Who can sign in

- Members of the `chat` group (`pam_group` in `/usr/local/etc/pam.d/jabberd`;
  change the group there, or remove the line to let every account in). An
  empty or missing group lets nobody in.
- Never root or a system account: `pamauth` refuses every account with a
  user ID below 1000, whatever the PAM policy says, so the chat port cannot
  be used to guess those passwords. See `pamauth(8)`.
- A stream is closed after three failed sign-in attempts, and c2s takes at
  most 20 connections per 10 seconds from one address, then none for 30
  seconds (`<connects>` in `c2s.xml`; raise it if many users share one
  address).
- The old `jabber:iq:auth` sign-in (XEP-0078) is off, because it tells
  anyone who asks whether an account exists. Clients need SASL PLAIN over
  TLS, which every current client has.
- Nobody is an administrator of the session manager by default; see
  `<aci>` in `sm.xml`.

### The router secret

The components (c2s, sm, s2s) sign in to the router on 127.0.0.1:5347 with a
shared secret, and whoever knows it can act as any component, and so as any
user. The configuration files are installed with the placeholder
`__CHATSERVER_ROUTER_SECRET__`. The first `service chatserver start` on a
host replaces it, in `router-users.xml`, `c2s.xml`, `sm.xml` and `s2s.xml`,
with 32 random bytes from `openssl rand`, keeping the files mode 640
`root:jabber`. Files that no longer hold the placeholder are never touched,
so you can set a secret of your own instead. The service does not start
while the placeholder is left in any of the four files.

The XEP-0114 component secret in `router.xml` is commented out. If you need
external components, set a long random secret of your own there.

### The certificate

The self-signed certificate made at first start names the host and the chat
domains of `c2s.xml`, and is valid for 825 days. Clients cannot verify a
self-signed certificate: they will warn, or refuse to connect, and a user
who clicks through the warning is not protected against someone in the
middle. Install a real certificate for your chat domain before users sign
in from networks you do not control:

```sh
cat fullchain.pem privkey.pem > /usr/local/etc/jabberd/server.pem
chown root:jabber /usr/local/etc/jabberd/server.pem
chmod 640 /usr/local/etc/jabberd/server.pem
service chatserver restart
```

To make a new self-signed one (after changing the domain, or when it
expires), delete `server.pem` and restart the service.

### Federation (s2s)

Server-to-server connections are off: the default components are
`router sm c2s`. To exchange messages with other XMPP servers, add s2s:

```sh
sysrc chatserver_components="router sm s2s c2s"
service chatserver restart
```

`s2s.xml` is set up to use `server.pem` and to require TLS on every
server-to-server connection. It listens on port 5269 on all addresses, and
does not verify other servers' certificates unless you set `<verify-mode>`;
`s2s.xml` also has a whitelist of domains.

### The rc.d script

`service chatserver status` reports each component, and fails if any is not
running, including one that has exited and is waiting for its supervisor
(`daemon(8)`) to start it again. `start` fails if a component's program or
configuration is missing, or a component does not stay up. The supervisors'
pidfiles are `/var/run/chatserver.<component>.pid`. The script runs as
root and does nothing inside the directories the `jabber` user owns
(`/var/db/jabberd`, `/var/run/jabberd`, `/var/log/jabberd`).

## Testing

`freebsd/tests/run.sh` (as root, after `make install`, on a scratch system)
creates test accounts and groups, starts the service, signs in with a small
XMPP client (`xmpp_client.py`), and checks PAM sign-in and who is refused,
the router secret, TLS, hostile sign-in attempts, auto-buddies,
`jabber_autobuddy`, `pam_group` and the rc.d script. It changes the system
it runs on (for one check it gives root a password, and puts the old one
back), so use a throwaway system. The GitHub mirror runs it in a FreeBSD
14.5 VM on every push.

## Licenses

jabberd2 is GPL 2 or later (`jabberd2/COPYING`); the new code here
(`mod_autobuddy.c`, `jabber_autobuddy`, `pamauth`, the Makefile, the rc.d
script, the PAM policy and the tests) is under the same license; see
`COPYING`.
Apple's original sources are on the `main` branch. Some of them — the Server
Admin scripts and Apple's patch tool — are licensed by Apple for use on
Apple-branded computers only, so none of their code is used here, and Apple's
Objective-C `jabber_autobuddy`, which carries no license grant, was rewritten
rather than ported.

Security fixes are this repository's responsibility: jabberd2 upstream has had
no release since 2.7.0 (2018). jabberd2 still uses some OpenSSL APIs that
OpenSSL 3 deprecates (low-level DH, EC_KEY, SHA1 and MD5 calls); they build with
warnings, and would need replacing for an OpenSSL release that removes them.
