#!/bin/sh
#
# End-to-end test of an installed ChatServer on a scratch FreeBSD system
# (it adds users and groups, and edits the configuration): run as root
# after "make install". Needs python3.
#
set -eu

here=$(cd "$(dirname "$0")" && pwd)
client="python3 ${here}/xmpp_client.py"
domain=chat.test
etc=/usr/local/etc/jabberd
db=/var/db/jabberd/sqlite.db
failures=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
check() { # description command...
	desc=$1; shift
	if "$@"; then pass "${desc}"; else fail "${desc}"; fi
}

mkuser() { # name password "Full Name"
	pw userdel "$1" -r 2>/dev/null || true
	echo "$2" | pw useradd "$1" -m -h 0 -c "$3" -s /bin/sh
}

roster() { # user password -> roster on stdout, exit status of the client
	${client} "$1" "$2" ${domain}
}

echo "== installed files"
ls -l /usr/local/libexec/jabberd /usr/local/lib/jabberd/mod_autobuddy.so \
    /usr/local/sbin/jabber_autobuddy /usr/local/etc/rc.d/chatserver \
    /usr/local/etc/pam.d/jabberd ${etc}
check "pamauth is setuid root, group jabber, mode 4750" \
    test "$(stat -f '%Sp %Su %Sg' /usr/local/libexec/jabberd/pamauth)" = \
    "-rwsr-x--- root jabber"
check "c2s.xml is not world-readable" \
    test "$(stat -f '%Sp %Su %Sg' ${etc}/c2s.xml)" = "-rw-r----- root jabber"
echo "OpenSSL: $(openssl version)"
ldd /usr/local/libexec/jabberd/c2s | grep -E 'ssl|crypto|gsasl|idn|udns|expat'
jabber_autobuddy --version

echo "== off by default"
check "chatserver_enable defaults to NO" \
    test "$(sysrc -n chatserver_enable 2>/dev/null || echo NO)" = NO
out=$(service chatserver start 2>&1 || true)
echo "${out}"
check "does not start unless enabled" \
    sh -c "echo '${out}' | grep -q 'Set chatserver_enable to YES'"

echo "== set up accounts and configuration"
pw groupdel chatstaff 2>/dev/null || true
mkuser alice 'alice-Secret1' 'Alice Liddell'
mkuser bob 'bob-Secret2' 'Bob Builder'
mkuser carol 'carol-Secret3' 'Carol Danvers'
mkuser dave 'dave-Secret4' 'Dave Bowman'
pw groupadd chatstaff -M alice,bob
sed -i '' -e "s/localhost\.localdomain/${domain}/" ${etc}/sm.xml ${etc}/c2s.xml

sysrc chatserver_enable=YES
check "service chatserver start succeeds" service chatserver start
sleep 3
service chatserver status
check "all four components run" service chatserver status
sockstat -46l | grep -E ':5222|:5269|:5347' || true
check "the router only listens on loopback" \
    sh -c "sockstat -46l -p 5347 | grep -q '127.0.0.1:5347' && ! sockstat -46l -p 5347 | grep -q '\*:5347'"
check "c2s runs as jabber" \
    test "$(ps -o user= -p $(pgrep -x c2s))" = jabber
check "a self-signed certificate was created" test -s ${etc}/server.pem
check "the database was created" test -s ${db}

echo "== sign-in through PAM"
check "PLAIN is not offered before STARTTLS" \
    ${client} --plain-before-tls carol x ${domain}
set +e
roster carol 'wrong-password' >/dev/null; rc=$?
set -e
check "a wrong password is refused" test ${rc} = 2
set +e
roster nosuchuser 'whatever' >/dev/null; rc=$?
set -e
check "an unknown user is refused" test ${rc} = 2
check "carol signs in with her system password" roster carol 'carol-Secret3'
r=$(roster carol 'carol-Secret3' || true)
echo "${r}"
check "the connection uses TLS 1.2 or later" \
    sh -c "echo '${r}' | grep -q 'over TLSv1\.[23]'"

echo "== jabber_autobuddy"
jabber_autobuddy -V --inituser alice@${domain} --i bob@${domain}
jabber_autobuddy -V --group chatstaff
sqlite3 ${db} 'SELECT * FROM "autobuddy-groups"; SELECT "collection-owner", jid, name, "to", "from" FROM "roster-items";'
r=$(roster alice 'alice-Secret1' || true)
echo "${r}"
check "alice has bob as a buddy, in group chatstaff" \
    sh -c "echo '${r}' | grep -q '^bob@${domain}	both	Bob Builder	chatstaff$'"
check "alice does not have carol (not in chatstaff)" \
    sh -c "! echo '${r}' | grep -q '^carol@'"
r=$(roster bob 'bob-Secret2' || true)
check "bob has alice as a buddy" \
    sh -c "echo '${r}' | grep -q '^alice@${domain}	both	Alice Liddell	chatstaff$'"

echo "== mod_autobuddy: a new member's first sign-in"
pw groupmod chatstaff -m dave
r=$(roster dave 'dave-Secret4' || true)
echo "${r}"
check "dave gets alice and bob at his first sign-in" \
    sh -c "echo '${r}' | grep -q '^alice@${domain}	both' && echo '${r}' | grep -q '^bob@${domain}	both'"
r=$(roster alice 'alice-Secret1' || true)
echo "${r}"
check "alice keeps bob after signing in again" \
    sh -c "echo '${r}' | grep -q '^bob@${domain}	both'"
check "alice gets dave at her next sign-in" \
    sh -c "echo '${r}' | grep -q '^dave@${domain}	both	Dave Bowman	chatstaff$'"

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
check "--ungroup removes the pairings" sh -c "test -z \"\$(echo '${r}' | grep -v '^#')\""
jabber_autobuddy -V --addbuddy carol@${domain}
r=$(roster alice 'alice-Secret1' || true)
check "--addbuddy makes carol everyone's buddy" sh -c "echo '${r}' | grep -q '^carol@${domain}	both'"
jabber_autobuddy -V --deleteuser carol@${domain}
check "--deleteuser removes carol from the database" \
    test "$(sqlite3 ${db} "SELECT COUNT(*) FROM \"roster-items\" WHERE jid = 'carol@${domain}' OR \"collection-owner\" = 'carol@${domain}'; ")" = 0
set +e
jabber_autobuddy --addbuddy nobody@${domain} 2>/dev/null; rc=$?
set -e
check "commands on users not in the database fail" test ${rc} = 1

echo "== pam_group: only members of one group may sign in"
cp /usr/local/etc/pam.d/jabberd /tmp/pam.jabberd
sed -i '' -e 's/^#account\(.*pam_group.so.*\)group=chat$/account\1group=chatstaff/' \
    /usr/local/etc/pam.d/jabberd
grep pam_group /usr/local/etc/pam.d/jabberd
check "alice (in chatstaff) may sign in" roster alice 'alice-Secret1'
set +e
roster carol 'carol-Secret3' >/dev/null; rc=$?
set -e
check "carol (not in chatstaff) may not" test ${rc} = 2
cp /tmp/pam.jabberd /usr/local/etc/pam.d/jabberd

echo "== restart and stop"
check "service chatserver restart succeeds" service chatserver restart
sleep 3
check "restart brings all components back" service chatserver status
check "signing in works after a restart" roster bob 'bob-Secret2'
check "service chatserver stop succeeds" service chatserver stop
set +e
service chatserver status; rc=$?
set -e
check "stop stops all components" test ${rc} != 0
check "no component is left running" sh -c "! pgrep -x 'router|sm|s2s|c2s'"
sysrc chatserver_enable=NO

echo "== syslog"
grep -E 'jabberd|pamauth|jabber_autobuddy' /var/log/messages /var/log/auth.log || true

if [ ${failures} -ne 0 ]; then
	echo "${failures} check(s) failed"
	exit 1
fi
echo "all checks passed"
