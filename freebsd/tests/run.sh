#!/bin/sh
#
# License: GPL-2.0-or-later, like jabberd2 (see COPYING).
#
# End-to-end test of an installed ChatServer on a scratch FreeBSD system
# (it adds users and groups, edits the configuration, and for one check
# gives root a password, which it puts back): run as root after
# "make install". Needs python3.
#
set -eu

here=$(cd "$(dirname "$0")" && pwd)
client="python3 ${here}/xmpp_client.py"
domain=chat.test
etc=/usr/local/etc/jabberd
libexec=/usr/local/libexec/jabberd
dbdir=/var/db/jabberd
db=${dbdir}/sqlite.db
rcscript=/usr/local/etc/rc.d/chatserver
placeholder=__CHATSERVER_ROUTER_SECRET__
tmp=$(mktemp -d /tmp/chatserver-test.XXXXXX)
failures=0
root_hash=
root_changed=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
check() { # description command...
	desc=$1; shift
	if "$@"; then pass "${desc}"; else fail "${desc}"; fi
}
check_not() { # description command...: the command must fail
	desc=$1; shift
	if "$@"; then fail "${desc}"; else pass "${desc}"; fi
}
# has TEXT REGEX: a line of TEXT matches REGEX (the text is data, never
# part of a command line)
has() { printf '%s\n' "$1" | grep -Eq -- "$2"; }
lacks() { ! has "$1" "$2"; }
signed_in() { has "$1" '^# signed in as '; }
# is_rc N command...: the command exits with status N
is_rc() {
	want=$1; shift
	set +e
	"$@" >/dev/null 2>&1; got=$?
	set -e
	[ "${got}" = "${want}" ]
}

# put root's password back as it was
restore_root() {
	[ ${root_changed} = 1 ] || return 0
	case "${root_hash}" in
	'')	pw usermod root -w none ;;
	'*')	pw usermod root -w no ;;
	*)	echo "${root_hash}" | pw usermod root -H 0 ;;
	esac
	root_changed=0
}
cleanup() {
	restore_root || true
	pw groupmod chat -d root 2>/dev/null || true
	rm -rf "${tmp}"
}
trap cleanup EXIT

mkuser() { # name password "Full Name" [pw options]
	name=$1; password=$2; full=$3; shift 3
	pw userdel "${name}" -r 2>/dev/null || true
	echo "${password}" | pw useradd "${name}" -m -h 0 -c "${full}" -s /bin/sh "$@"
}

roster() { # user password -> roster on stdout, exit status of the client
	${client} "$1" "$2" ${domain}
}

sql() { sqlite3 ${db} "$1"; }

# the pid of a component (the child of its supervisor), or nothing
component_pid() {
	pgrep -x "$1" -P "$(cat /var/run/chatserver.$1.pid 2>/dev/null || echo 999999)" 2>/dev/null || true
}
components_up() { # names...
	for c in "$@"; do
		[ -n "$(component_pid ${c})" ] || return 1
	done
}
listening() { sockstat -46l -p "$1" | grep -q ":$1"; }
# wait for c2s to take connections
wait_c2s() {
	for i in $(seq 20); do
		if ${client} --plain-before-tls ${domain} >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	return 1
}
router_secret() {
	sed -n 's/.*<secret>\(.*\)<\/secret>.*/\1/p' ${etc}/router-users.xml
}
# the file without its XML comments
uncommented() { sed -e '/<!--.*-->/d' -e '/<!--/,/-->/d' "$1"; }

echo "== installed files"
ls -l ${libexec} /usr/local/lib/jabberd/mod_autobuddy.so \
    /usr/local/sbin/jabber_autobuddy ${rcscript} \
    /usr/local/etc/pam.d/jabberd ${etc}
check "pamauth is setuid root, group jabber, mode 4750" \
    test "$(stat -f '%Sp %Su %Sg' ${libexec}/pamauth)" = \
    "-rwsr-x--- root jabber"
for f in c2s.xml sm.xml s2s.xml router.xml router-users.xml \
    c2s.xml.dist router-users.xml.dist; do
	check "${f} is installed mode 640 root:jabber" \
	    test "$(stat -f '%Sp %Su %Sg' ${etc}/${f})" = "-rw-r----- root jabber"
done
echo "OpenSSL: $(openssl version)"
ldd ${libexec}/c2s | grep -E 'ssl|crypto|gsasl|idn|udns|expat'
jabber_autobuddy --version
check "the chat group was created" pw groupshow chat
check "the PAM policy lets only the chat group in" \
    grep -Eq '^account[[:space:]]+required[[:space:]]+pam_group\.so[[:space:]].*group=chat$' \
    /usr/local/etc/pam.d/jabberd

echo "== configuration as installed"
check "router-users.xml holds the placeholder, not a secret" \
    grep -q "<secret>${placeholder}</secret>" ${etc}/router-users.xml
for f in c2s sm s2s; do
	check "${f}.xml holds the placeholder" \
	    grep -q "<pass>${placeholder}</pass>" ${etc}/${f}.xml
done
check_not "router-users.xml does not have the old shared secret" \
    grep -q '<secret>secret</secret>' ${etc}/router-users.xml
for f in c2s sm s2s; do
	check_not "${f}.xml does not have the old shared secret" \
	    sh -c "sed -n '/<router>/,/<\/router>/p' ${etc}/${f}.xml | grep -q '<pass>secret</pass>'"
done
check_not "the XEP-0114 component secret is off in router.xml" \
    sh -c "sed -e '/<!--.*-->/d' -e '/<!--/,/-->/d' ${etc}/router.xml | grep -q '<secret>'"
check "c2s.xml limits connections per address" \
    grep -q "<connects seconds='10' throttle='30'>20</connects>" ${etc}/c2s.xml
check_not "sm.xml has no administrator by default" \
    sh -c "sed -e '/<!--.*-->/d' -e '/<!--/,/-->/d' ${etc}/sm.xml | grep -q \"<acl type='all'>\""
s2sconf=$(uncommented ${etc}/s2s.xml)
check "s2s.xml requires TLS" has "${s2sconf}" '<require_tls>1</require_tls>'
check "s2s.xml has a certificate" has "${s2sconf}" '<pemfile>.*server\.pem</pemfile>'

echo "== off by default"
check "the rc.d script's default is chatserver_enable=NO" \
    grep -q '^: \${chatserver_enable:="NO"}$' ${rcscript}
check_not "rc.conf does not enable it" \
    sh -c "sysrc -n chatserver_enable 2>/dev/null | grep -qi yes"
check "s2s is not among the default components" \
    grep -q '^: \${chatserver_components:="router sm c2s"}$' ${rcscript}
out=$(service chatserver start 2>&1 || true)
echo "${out}"
check "does not start unless enabled" has "${out}" 'Set chatserver_enable to YES'
check_not "nothing runs" pgrep -x 'router|sm|s2s|c2s'

echo "== set up accounts and configuration"
pw groupdel chatstaff 2>/dev/null || true
pw groupdel chatpair 2>/dev/null || true
mkuser alice 'alice-Secret1' 'Alice Liddell'
mkuser bob 'bob-Secret2' 'Bob Builder'
mkuser carol 'carol-Secret3' 'Carol Danvers'
mkuser dave 'dave-Secret4' 'Dave Bowman'
mkuser erin 'erin-Secret5' 'Erin Outsider'
mkuser frank 'frank-Secret6' 'Frank First'
mkuser grace 'grace-Secret7' 'Grace Second'
mkuser heidi 'heidi-Secret8' 'Heidi Late'
# a system account (uid below 1000) with a password
mkuser sysacct 'sysacct-Secret9' 'System Account' -u 999
# everyone but erin may use chat
pw groupmod chat -m alice,bob,carol,dave,frank,grace,heidi,sysacct
pw groupadd chatstaff -M alice,bob,dave
pw groupadd chatpair -M frank,grace
sed -i '' -e "s/localhost\.localdomain/${domain}/" ${etc}/sm.xml ${etc}/c2s.xml
# the tests connect far more often than the limit allows; it is put back
# and tested near the end
sed -i '' -e "s|<connects seconds='10' throttle='30'>20</connects>|<connects>0</connects>|" \
    ${etc}/c2s.xml
check "sed kept c2s.xml mode 640 root:jabber" \
    test "$(stat -f '%Sp %Su %Sg' ${etc}/c2s.xml)" = "-rw-r----- root jabber"

sysrc chatserver_enable=YES
check "service chatserver start succeeds" service chatserver start
check "c2s takes connections" wait_c2s
service chatserver status || true
check "service chatserver status reports all running" service chatserver status
check "router, sm and c2s each run under their supervisor" \
    components_up router sm c2s
check "c2s listens on 5222" listening 5222
check_not "s2s is not running by default" pgrep -x s2s
check_not "nothing listens on the s2s port 5269" listening 5269
sockstat -46l | grep -E ':5222|:5269|:5347' || true
check "the router only listens on loopback" \
    sh -c "sockstat -46l -p 5347 | grep -q '127.0.0.1:5347' && ! sockstat -46l -p 5347 | grep -q '\*:5347'"
check "c2s runs as jabber" \
    test "$(ps -o user= -p "$(component_pid c2s)")" = jabber
check "the database was created" test -s ${db}

echo "== router secret"
secret=$(router_secret)
check "the router secret is 64 hex digits made at first start" \
    has "${secret}" '^[0-9a-f]{64}$'
check_not "no placeholder is left in the configuration" \
    grep -l "${placeholder}" ${etc}/router-users.xml ${etc}/c2s.xml \
    ${etc}/sm.xml ${etc}/s2s.xml
for f in c2s sm s2s; do
	check "${f}.xml has the same secret" \
	    grep -q "<pass>${secret}</pass>" ${etc}/${f}.xml
done
for f in router-users.xml c2s.xml sm.xml s2s.xml; do
	check "${f} is still mode 640 root:jabber" \
	    test "$(stat -f '%Sp %Su %Sg' ${etc}/${f})" = "-rw-r----- root jabber"
done
check "the .dist files still hold the placeholder" \
    grep -q "${placeholder}" ${etc}/router-users.xml.dist
check_not "no temporary file is left in the configuration directory" \
    sh -c "ls -A ${etc} | grep -Ev '^(templates|server\.pem|[a-z0-9-]+\.(xml|cfg)(\.dist)?)$'"
check "the router refuses a component with the old secret (XEP-0114)" \
    is_rc 2 ${client} --component secret ${domain}

echo "== certificate"
check "a self-signed certificate was created" test -s ${etc}/server.pem
check "server.pem is mode 640 root:jabber" \
    test "$(stat -f '%Sp %Su %Sg' ${etc}/server.pem)" = "-rw-r----- root jabber"
san=$(openssl x509 -in ${etc}/server.pem -noout -ext subjectAltName)
echo "${san}"
check "the certificate names the chat domain" has "${san}" "DNS:${domain}(,|\$)"
check "the certificate names the host" has "${san}" "DNS:$(hostname)(,|\$)"

echo "== supervisor pidfiles"
for c in router sm c2s; do
	check "the ${c} pidfile is in /var/run, owned by root" \
	    test "$(stat -f '%Su %Sp' /var/run/chatserver.${c}.pid)" = "root -rw-------"
done
check "/var/run is not writable by others" \
    test "$(stat -f '%Su %Sp' /var/run)" = "root drwxr-xr-x"
check_not "no supervisor pidfile is in the jabber user's directory" \
    sh -c "ls /var/run/jabberd | grep -q daemon"

echo "== TLS"
check "PLAIN is not offered before STARTTLS" \
    ${client} --plain-before-tls ${domain}
r=$(roster carol 'carol-Secret3' || true)
echo "${r}"
check "carol signs in with her system password" signed_in "${r}"
check "the connection uses TLS 1.2 or later" has "${r}" 'over TLSv1\.[23]$'
for v in tls1 tls1_1; do
	out=$(openssl s_client -connect 127.0.0.1:5222 -starttls xmpp \
	    -xmpphost ${domain} -${v} -cipher 'DEFAULT:@SECLEVEL=0' \
	    </dev/null 2>&1 || true)
	printf '%s\n' "${out}" | grep -Ei 'alert|error|Cipher is|no protocols' | head -5
	check "a ${v} handshake does not complete" \
	    has "${out}" 'Cipher is \(NONE\)'
	# the refusal must be the server's (it answers the ClientHello with an
	# alert or by closing), not our own client declining to try
	check "it was the server that refused ${v}" \
	    has "${out}" 'alert protocol version|unexpected eof while reading'
	check "the client did offer ${v}" \
	    lacks "${out}" 'no protocols available|no cipher(s)? available|unknown option'
done
out=$(openssl s_client -connect 127.0.0.1:5222 -starttls xmpp \
    -xmpphost ${domain} -tls1_2 </dev/null 2>&1 || true)
check "a tls1_2 handshake by the same means succeeds" \
    has "${out}" 'New, TLSv1\.2, Cipher is [A-Z0-9]'

echo "== sign-in through PAM"
check "a wrong password is refused" is_rc 2 roster carol 'wrong-password'
check "an unknown user is refused" is_rc 2 roster nosuchuser 'whatever'
check "erin (not in the chat group) is refused" is_rc 2 roster erin 'erin-Secret5'
pw groupmod chat -m erin
check "erin signs in once she is in the chat group" roster erin 'erin-Secret5'
check "a system account (uid 999) in the chat group is refused" \
    is_rc 2 roster sysacct 'sysacct-Secret9'
root_hash=$(pw usershow root | cut -d: -f2)
root_changed=1
echo 'root-Secret0' | pw usermod root -h 0
pw groupmod chat -m root
check "root, with a password and in the chat group, is refused" \
    is_rc 2 roster root 'root-Secret0'
restore_root
pw groupmod chat -d root
check "root's password was put back" \
    test "$(pw usershow root | cut -d: -f2)" = "${root_hash}"

echo "== pamauth, asked directly as the jabber user"
ask() { # request lines on stdin -> pamauth's answers
	su -m jabber -c ${libexec}/pamauth
}
out=$(printf 'USER-EXISTS alice x\nUSER-EXISTS root x\nUSER-EXISTS sysacct x\nUSER-EXISTS nosuchuser x\nFREE\n' | ask | tr '\n' ' ')
echo "${out}"
check "USER-EXISTS: yes for alice; no for root, a system account, nobody" \
    test "${out}" = "OK USER-EXISTS CHECK-PASSWORD FREE OK NO NO NO "
pw64=$(printf '%s' 'alice-Secret1' | openssl base64 -A)
out=$(printf 'CHECK-PASSWORD alice %s x\nCHECK-PASSWORD alice eA== x\nUSER-EXISTS al\000ice x\nUSER-EXISTS alice x\n%02100d\nUSER-EXISTS alice \nFREE\n' "${pw64}" 0 | ask | tr '\n' ' ')
echo "${out}"
check "CHECK-PASSWORD; a NUL or an overlong line is refused and the next request still answered" \
    test "${out}" = "OK USER-EXISTS CHECK-PASSWORD FREE OK NO NO OK NO OK "
check_not "others cannot run pamauth" su -m nobody -c "${libexec}/pamauth </dev/null"

echo "== hostile sign-ins"
long_password=$(printf '%0800d' 0)
long_user=$(printf '%01100d' 0 | tr 0 a)
check "an 800-byte password is refused" is_rc 2 roster carol "${long_password}"
check "c2s still signs carol in afterwards" roster carol 'carol-Secret3'
check "an 1100-byte user name is refused" is_rc 2 roster "${long_user}" 'whatever'
check "c2s still signs carol in afterwards" roster carol 'carol-Secret3'
check "a user name with a space is refused" is_rc 2 roster 'carol x' 'carol-Secret3'
check "a user name with a newline is refused" is_rc 2 roster 'carol
USER-EXISTS carol' 'carol-Secret3'
check "c2s still signs carol in afterwards" roster carol 'carol-Secret3'
check_not "a wrong password after those is still refused (no stale answer)" \
    roster carol 'wrong-password'
r=$(${client} --wrong-first 2 carol 'carol-Secret3' ${domain} || true)
echo "${r}"
check "two wrong passwords, then the right one on the same stream: signed in" \
    has "${r}" '^# after 2 failures$'
set +e
r=$(${client} --wrong-first 3 carol 'carol-Secret3' ${domain} 2>/dev/null); rc=$?
set -e
echo "${r}"
check "three wrong passwords close the stream" test ${rc} = 3
check "it closed after the third failure" has "${r}" '^closed after 3 failures$'
helper=$(pgrep -x pamauth)
kill -KILL ${helper}
sleep 1
check "carol signs in after pamauth was killed (a new helper is started)" \
    roster carol 'carol-Secret3'
check "a new pamauth is running" \
    sh -c "pgrep -x pamauth >/dev/null && [ \"\$(pgrep -x pamauth)\" != '${helper}' ]"
check "pamauth is c2s's child" \
    test "$(ps -o ppid= -p "$(pgrep -x pamauth)" | tr -d ' ')" = "$(component_pid c2s)"
helper=$(pgrep -x pamauth)
kill -STOP ${helper}
echo "signing in while pamauth hangs (c2s gives it 10 seconds)"
check "a sign-in while pamauth hangs is refused, not left waiting" \
    is_rc 2 roster carol 'carol-Secret3'
check "carol signs in right afterwards (the hung helper was replaced)" \
    roster carol 'carol-Secret3'
check_not "the hung helper is gone" kill -0 ${helper}

# Six sign-in requests in one write are all read by c2s before it gets to
# close the stream. pamauth logs every password it checks; the requests are
# for six different users, the first one new to the log, so that syslogd
# does not fold the lines into "last message repeated".
sleep 1
log_before=$(wc -l < /var/log/auth.log)
r=$(${client} --pipeline heidi,alice,bob,dave,frank,grace 'wrong-password' ${domain} || true)
echo "${r}"
sleep 2
asked=$(tail -n +$((log_before + 1)) /var/log/auth.log |
    grep -c 'pamauth.*authentication failed for' || true)
tail -n +$((log_before + 1)) /var/log/auth.log | grep pamauth || true
echo "pamauth checked ${asked} of the 6 passwords"
check "six requests in one write were all sent" has "${r}" '^sent 6 requests in one write$'
check "none of them signed anyone in" has "${r}" '^successes: 0$'
check "the stream was closed" has "${r}" '^stream closed: yes$'
check "pamauth was asked for exactly 3 of them" test "${asked}" = 3
check "carol signs in afterwards" roster carol 'carol-Secret3'

echo "== jabber:iq:auth (XEP-0078) is off"
a=$(${client} --iq-auth alice ${domain} || true)
b=$(${client} --iq-auth nosuchuser ${domain} || true)
echo "${a}"
check "iq-auth is not offered" has "${a}" '^iq-auth feature: not offered$'
check "asking about alice gets an error" has "${a}" '^answer: error forbidden$'
check "asking about a user who does not exist gets the same answer" \
    test "${a}" = "${b}"

echo "== jabber_autobuddy"
jabber_autobuddy -V --inituser alice@${domain} --i bob@${domain}
jabber_autobuddy -V --group chatstaff
sql 'SELECT * FROM "autobuddy-groups"; SELECT "collection-owner", jid, name, "to", "from" FROM "roster-items";'
# before anyone signs in again: these rows are jabber_autobuddy's work,
# not mod_autobuddy's
check "--group stored alice and bob as buddies, both ways" \
    test "$(sql "SELECT COUNT(*) FROM \"roster-items\" WHERE \"to\" = 1 AND \"from\" = 1 AND ((\"collection-owner\" = 'alice@${domain}' AND jid = 'bob@${domain}') OR (\"collection-owner\" = 'bob@${domain}' AND jid = 'alice@${domain}'))")" = 2
check "--group stored the roster group" \
    test "$(sql "SELECT \"group\" FROM \"roster-groups\" WHERE \"collection-owner\" = 'alice@${domain}' AND jid = 'bob@${domain}'")" = chatstaff
r=$(roster alice 'alice-Secret1' || true)
echo "${r}"
check "alice has bob as a buddy, in group chatstaff" \
    has "${r}" "^bob@${domain}	both	Bob Builder	chatstaff\$"
check "alice signed in and does not have carol (not in chatstaff)" \
    sh -c 'printf "%s\n" "$1" | grep -q "^# signed in" && ! printf "%s\n" "$1" | grep -q "^carol@"' sh "${r}"
r=$(roster bob 'bob-Secret2' || true)
check "bob has alice as a buddy" \
    has "${r}" "^alice@${domain}	both	Alice Liddell	chatstaff\$"
check "jabber_autobuddy without a command fails" is_rc 1 jabber_autobuddy -V
check "--move-domain of a domain nobody is in fails" \
    is_rc 1 jabber_autobuddy --move-domain nosuch.test other.test
check "--move-domain refuses a domain starting with -" \
    is_rc 1 jabber_autobuddy --move-domain -x.test other.test

echo "== mod_autobuddy: a member's first sign-in"
check "dave is not in the database yet" \
    test "$(sql "SELECT COUNT(*) FROM active WHERE \"collection-owner\" = 'dave@${domain}'")" = 0
r=$(roster dave 'dave-Secret4' || true)
echo "${r}"
check "dave gets alice at his first sign-in" has "${r}" "^alice@${domain}	both"
check "dave gets bob at his first sign-in" has "${r}" "^bob@${domain}	both"
r=$(roster alice 'alice-Secret1' || true)
echo "${r}"
check "alice keeps bob after signing in again" has "${r}" "^bob@${domain}	both"
check "alice gets dave at her next sign-in" \
    has "${r}" "^dave@${domain}	both	Dave Bowman	chatstaff\$"

echo "== mod_autobuddy: a first sign-in while the buddy is signed in"
jabber_autobuddy -V --group chatpair
# frank signs in, and stays; then grace signs in for the first time
${client} --hold 14 frank 'frank-Secret6' ${domain} > ${tmp}/frank 2>&1 &
frank_pid=$!
sleep 4
${client} --hold 6 grace 'grace-Secret7' ${domain} > ${tmp}/grace 2>&1 || true
wait ${frank_pid} || true
f=$(cat ${tmp}/frank); g=$(cat ${tmp}/grace)
echo "frank saw:"; echo "${f}"
echo "grace saw:"; echo "${g}"
check "frank was signed in, with no buddy yet" \
    sh -c 'printf "%s\n" "$1" | grep -q "^# signed in" && ! printf "%s\n" "$1" | grep -q "^grace@.*	both	"' sh "${f}"
check "grace's first roster has frank, both ways" \
    has "${g}" "^frank@${domain}	both	Frank First	chatpair\$"
check "frank is told of grace by a roster push, both ways" \
    has "${f}" "^push	grace@${domain}	both\$"
check "grace receives frank's presence" \
    has "${g}" "^presence	frank@${domain}/test	available\$"
check "frank receives grace's presence" \
    has "${f}" "^presence	grace@${domain}/test	available\$"
check "the database has both items, both ways" \
    test "$(sql "SELECT COUNT(*) FROM \"roster-items\" WHERE \"to\" = 1 AND \"from\" = 1 AND ((\"collection-owner\" = 'frank@${domain}' AND jid = 'grace@${domain}') OR (\"collection-owner\" = 'grace@${domain}' AND jid = 'frank@${domain}'))")" = 2
check "and no item twice" \
    test "$(sql "SELECT COUNT(*) FROM \"roster-items\" WHERE \"collection-owner\" IN ('frank@${domain}', 'grace@${domain}')")" = 2
sleep 1
f=$(roster frank 'frank-Secret6' || true)
g=$(roster grace 'grace-Secret7' || true)
echo "${f}"; echo "${g}"
check "frank still has grace, both ways, when he signs in again" \
    has "${f}" "^grace@${domain}	both	Grace Second	chatpair\$"
check "grace still has frank, both ways, when she signs in again" \
    has "${g}" "^frank@${domain}	both	Frank First	chatpair\$"

echo "== mod_autobuddy: a one-way item is repaired"
sql "UPDATE \"roster-items\" SET \"to\" = 0 WHERE \"collection-owner\" = 'grace@${domain}' AND jid = 'frank@${domain}'"
check "the item is one-way in the database" \
    test "$(sql "SELECT \"to\" || \"from\" FROM \"roster-items\" WHERE \"collection-owner\" = 'grace@${domain}' AND jid = 'frank@${domain}'")" = 01
g=$(roster grace 'grace-Secret7' || true)
echo "${g}"
check "grace's item for frank is both ways again, name and group kept" \
    has "${g}" "^frank@${domain}	both	Frank First	chatpair\$"

echo "== mod_autobuddy: group membership is cached for a minute"
pw groupmod chatpair -m heidi
h=$(roster heidi 'heidi-Secret8' || true)
echo "${h}"
check "heidi signs in" signed_in "${h}"
check "heidi has no buddies yet: the membership read a moment ago is still used" \
    lacks "${h}" "^(frank|grace)@"
echo "waiting for the cache to expire"
sleep 62
h=$(roster heidi 'heidi-Secret8' || true)
echo "${h}"
check "heidi, new in the group, has frank a minute later" \
    has "${h}" "^frank@${domain}	both	Frank First	chatpair\$"

echo "== back-to-back sign-ins (a new connection right after one ends)"
ok=0
for i in $(seq 30); do
	if roster bob 'bob-Secret2' >/dev/null; then ok=$((ok + 1)); fi
done
echo "${ok} of 30 sign-ins succeeded"
check "30 back-to-back sign-ins all succeed" test ${ok} = 30

echo "== jabber_autobuddy --ungroup and --deleteuser"
jabber_autobuddy -V --ungroup chatstaff
r=$(roster alice 'alice-Secret1' || true)
echo "${r}"
check "alice signs in after --ungroup" signed_in "${r}"
check "--ungroup removes the pairings" lacks "${r}" "^(bob|dave)@"
jabber_autobuddy -V --addbuddy carol@${domain}
r=$(roster alice 'alice-Secret1' || true)
check "--addbuddy makes carol everyone's buddy" has "${r}" "^carol@${domain}	both"
jabber_autobuddy -V --deleteuser carol@${domain}
check "--deleteuser removes carol from the database" \
    test "$(sql "SELECT COUNT(*) FROM \"roster-items\" WHERE jid = 'carol@${domain}' OR \"collection-owner\" = 'carol@${domain}'; ")" = 0
check "commands on users not in the database fail" \
    is_rc 1 jabber_autobuddy --addbuddy nobody@${domain}

echo "== pam_group: another group"
cp /usr/local/etc/pam.d/jabberd ${tmp}/pam.jabberd
sed -i '' -e 's/group=chat$/group=chatstaff/' /usr/local/etc/pam.d/jabberd
grep pam_group /usr/local/etc/pam.d/jabberd
check "the policy now names chatstaff" \
    grep -q '^account.*pam_group.so.*group=chatstaff$' /usr/local/etc/pam.d/jabberd
check "alice (in chatstaff) may sign in" roster alice 'alice-Secret1'
check "carol (not in chatstaff) may not" is_rc 2 roster carol 'carol-Secret3'
cp ${tmp}/pam.jabberd /usr/local/etc/pam.d/jabberd
check "carol may again with the installed policy" roster carol 'carol-Secret3'

echo "== status and supervision"
kill -KILL "$(component_pid c2s)"
check_not "status fails while c2s is down" service chatserver status
service chatserver status || true
echo "waiting for the supervisor to start c2s again"
sleep 8
check "c2s takes connections again" wait_c2s
check "status succeeds once the supervisor has restarted c2s" \
    service chatserver status
check "signing in works after c2s was restarted" roster bob 'bob-Secret2'

echo "== restart: nothing done as root inside the jabber user's directories"
scratch=$(mktemp -d /tmp/chatserver-scratch.XXXXXX)
before=$(stat -f '%Su:%Sg %Sp' ${scratch})
check "stats was created by the service, owned by jabber" \
    test "$(stat -f '%Su %HT' ${dbdir}/stats)" = "jabber Directory"
# what a compromised component could do
su -m jabber -c "rmdir ${dbdir}/stats && ln -s ${scratch} ${dbdir}/stats"
check "stats is now a symbolic link to a root-owned directory" \
    test "$(readlink ${dbdir}/stats)" = "${scratch}"
secret=$(router_secret)
check "service chatserver restart succeeds" service chatserver restart
check "c2s takes connections after the restart" wait_c2s
check "the linked directory's owner and mode are untouched" \
    test "$(stat -f '%Su:%Sg %Sp' ${scratch})" = "${before}"
rm ${dbdir}/stats
rmdir ${scratch}
check "restart brings all components back" service chatserver status
check "each component runs under its supervisor" components_up router sm c2s
check "the router secret is unchanged by a restart" \
    test "$(router_secret)" = "${secret}"
check "signing in works after a restart" roster bob 'bob-Secret2'

echo "== Diffie-Hellman parameters in server.pem"
dh_bits() { # the size of the group the server uses for a DHE cipher
	openssl s_client -connect 127.0.0.1:5222 -starttls xmpp \
	    -xmpphost ${domain} -tls1_2 -cipher 'DHE-RSA-AES256-GCM-SHA384' \
	    </dev/null 2>&1 |
	    sed -n 's/^Server Temp Key: DH, \([0-9]*\) bits$/\1/p'
}
bits=$(dh_bits)
echo "automatic group: ${bits} bits"
check "without parameters in server.pem, the group matches the 3072-bit key" \
    test "${bits}" = 3072
cp -p ${etc}/server.pem ${tmp}/server.pem
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 >> ${etc}/server.pem
check "server.pem now has DH parameters" grep -q 'DH PARAMETERS' ${etc}/server.pem
check "service chatserver restart succeeds" service chatserver restart
check "c2s takes connections after the restart" wait_c2s
bits=$(dh_bits)
echo "with parameters: ${bits} bits"
check "with 2048-bit parameters in server.pem, those are used" \
    test "${bits}" = 2048
cp -p ${tmp}/server.pem ${etc}/server.pem

echo "== connection rate limit"
sed -i '' -e "s|<connects>0</connects>|<connects seconds='10' throttle='30'>20</connects>|" \
    ${etc}/c2s.xml
check "the installed limit is back in c2s.xml" \
    grep -q "<connects seconds='10' throttle='30'>20</connects>" ${etc}/c2s.xml
check "service chatserver restart succeeds" service chatserver restart
check "c2s takes connections after the restart" wait_c2s
sleep 11	# a new counting period
ok=0; refused=0
for i in $(seq 40); do
	if ${client} --plain-before-tls ${domain} >/dev/null 2>&1; then
		ok=$((ok + 1))
	else
		refused=$((refused + 1))
	fi
done
echo "${ok} of 40 connections were taken, ${refused} refused"
check "the first connections are taken" test ${ok} -ge 1
check "no more than 20 connections in a row are taken" test ${ok} -le 20
check "the rest are refused" test ${refused} -ge 20

echo "== stop"
sleep 300 &
bystander=$!
check "service chatserver stop succeeds" service chatserver stop
check_not "status fails when stopped" service chatserver status
check_not "no component is left running" pgrep -x 'router|sm|s2s|c2s'
check_not "no pamauth is left running" pgrep -x pamauth
check_not "no supervisor pidfile is left" \
    sh -c "ls /var/run/chatserver.*.pid 2>/dev/null | grep -q ."
# a pidfile is never trusted to hold a process to signal
echo "-1" > /var/run/chatserver.c2s.pid
echo "${bystander}" > /var/run/chatserver.sm.pid
check_not "status does not take a made-up pidfile for a running component" \
    service chatserver status
service chatserver stop
check "stop does not signal what a made-up pidfile names" kill -0 ${bystander}
kill ${bystander}
check_not "stop removed the made-up pidfiles" \
    sh -c "ls /var/run/chatserver.*.pid 2>/dev/null | grep -q ."

echo "== start refuses what cannot work"
mv ${libexec}/c2s ${libexec}/c2s.off
check_not "start fails when a component's program is missing" \
    service chatserver start
mv ${libexec}/c2s.off ${libexec}/c2s
service chatserver stop >/dev/null 2>&1 || true
cp -p ${etc}/c2s.xml ${tmp}/c2s.xml
sed -i '' -e "s|<pass>${secret}</pass>|<pass>${placeholder}</pass>|" ${etc}/c2s.xml
set +e
out=$(service chatserver start 2>&1); rc=$?
set -e
echo "${out}"
check "start fails while a file still holds the placeholder" test ${rc} != 0
check "and says which" has "${out}" "c2s\.xml"
check_not "nothing was started" pgrep -x 'router|sm|s2s|c2s'
check "router-users.xml kept its secret" test "$(router_secret)" = "${secret}"
cp -p ${tmp}/c2s.xml ${etc}/c2s.xml

# a configuration from an earlier build, with the secret everyone knows
cp -p ${etc}/router-users.xml ${tmp}/router-users.xml
sed -i '' -e "s|<secret>${secret}</secret>|<secret>secret</secret>|" ${etc}/router-users.xml
check "router-users.xml now has the old shared secret" \
    grep -q '<secret>secret</secret>' ${etc}/router-users.xml
set +e
out=$(service chatserver start 2>&1); rc=$?
set -e
echo "${out}"
check "start fails with the old shared secret in router-users.xml" test ${rc} != 0
check "and says why" has "${out}" 'old shared one'
check "it names router-users.xml" has "${out}" 'router-users\.xml'
check "it says how to fix it" has "${out}" "${placeholder}"
check_not "nothing was started" pgrep -x 'router|sm|s2s|c2s'
cp -p ${tmp}/router-users.xml ${etc}/router-users.xml
cp -p ${etc}/sm.xml ${tmp}/sm.xml
sed -i '' -e "s|<pass>${secret}</pass>|<pass>secret</pass>|" ${etc}/sm.xml
set +e
out=$(service chatserver start 2>&1); rc=$?
set -e
echo "${out}"
check "start fails with the old shared secret in sm.xml" test ${rc} != 0
check "it names sm.xml" has "${out}" '/sm\.xml'
check_not "nothing was started" pgrep -x 'router|sm|s2s|c2s'
cp -p ${tmp}/sm.xml ${etc}/sm.xml
check "sm.xml has the host's secret again" grep -q "<pass>${secret}</pass>" ${etc}/sm.xml

echo '<c2s><broken' > ${etc}/c2s.xml
check_not "start fails when c2s cannot stay up (broken c2s.xml)" \
    service chatserver start
service chatserver stop >/dev/null 2>&1 || true
cp -p ${tmp}/c2s.xml ${etc}/c2s.xml

echo "== s2s, when asked for"
sysrc chatserver_components="router sm s2s c2s"
check "start with s2s succeeds" service chatserver start
check "c2s takes connections" wait_c2s
check "status reports all four running" service chatserver status
check "s2s runs under its supervisor" components_up router sm s2s c2s
check "s2s listens on 5269" listening 5269
check "signing in works with s2s running" roster bob 'bob-Secret2'
check "service chatserver stop succeeds" service chatserver stop
check_not "no component is left running" pgrep -x 'router|sm|s2s|c2s'
sysrc -x chatserver_components
sysrc chatserver_enable=NO

echo "== syslog"
grep -E 'jabberd|pamauth|jabber_autobuddy' /var/log/messages /var/log/auth.log | tail -150 || true

if [ ${failures} -ne 0 ]; then
	echo "${failures} check(s) failed"
	exit 1
fi
echo "all checks passed"
