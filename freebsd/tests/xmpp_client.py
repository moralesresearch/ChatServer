#!/usr/bin/env python3
# License: GPL-2.0-or-later, like jabberd2 (see COPYING).
"""A minimal XMPP client for testing ChatServer: STARTTLS, SASL PLAIN,
resource binding and a roster fetch. Standard library only.

usage: xmpp_client.py [options] USER PASSWORD DOMAIN
       xmpp_client.py --plain-before-tls DOMAIN
       xmpp_client.py --iq-auth USER DOMAIN
       xmpp_client.py --component SECRET DOMAIN
       xmpp_client.py --pipeline USER,USER,... PASSWORD DOMAIN

Prints "# signed in as ..." and the roster as lines of
"jid<TAB>subscription<TAB>name<TAB>groups", and exits 0 when the user signed
in; exits 2 when the server refused the password, 3 when the server closed
the stream after refusing it, 1 on any other error (a timeout, for one).

  --wrong-first N   try N wrong passwords on the same stream before the
                    real one
  --hold SECONDS    after the roster, send presence and stay signed in,
                    then print what arrived: "push<TAB>jid<TAB>subscription"
                    for roster pushes, "presence<TAB>from<TAB>type"

The other forms sign nobody in:

  --plain-before-tls  exit 0 if SASL PLAIN is not offered before STARTTLS
  --iq-auth USER      after STARTTLS, ask for the jabber:iq:auth (XEP-0078)
                      fields of USER, print the error condition (or
                      "fields"), and say whether the stream features offer
                      iq-auth; always exits 0 when it got an answer
  --component SECRET  try the router's XEP-0114 component handshake on port
                      5347; exit 0 if accepted, 2 if refused
  --pipeline USERS    after STARTTLS, send one SASL PLAIN request for each
                      of the comma-separated USERS, with PASSWORD, in a
                      single write, and print how many answers came back
                      before the server closed the stream; exits 0
"""

import argparse
import base64
import hashlib
import re
import socket
import ssl
import sys
import time

HOST, PORT, ROUTER_PORT = "127.0.0.1", 5222, 5347

STREAM_END = r"</stream:stream>"


class Closed(Exception):
    """The server ended the stream."""


class Stream:
    def __init__(self, domain, port=PORT, ns="jabber:client"):
        self.domain = domain
        self.ns = ns
        self.sock = socket.create_connection((HOST, port), timeout=15)
        self.buf = ""

    def send(self, data):
        self.sock.sendall(data.encode())

    def expect(self, pattern):
        """Wait for pattern; raise Closed if the stream ends first."""
        rx = re.compile(pattern, re.S)
        end = re.compile(STREAM_END)
        while True:
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            if end.search(self.buf):
                raise Closed("stream closed; received: " + self.buf)
            try:
                data = self.sock.recv(65536)
            except (ConnectionResetError, BrokenPipeError):
                data = b""
            if not data:
                raise Closed("connection closed; received: " + self.buf)
            self.buf += data.decode("utf-8", "replace")

    def collect(self, seconds):
        """Everything that arrives in the next seconds."""
        deadline = time.time() + seconds
        while True:
            left = deadline - time.time()
            if left <= 0:
                break
            self.sock.settimeout(left)
            try:
                data = self.sock.recv(65536)
            except (socket.timeout, ssl.SSLWantReadError):
                break
            if not data:
                break
            self.buf += data.decode("utf-8", "replace")
        self.sock.settimeout(15)
        text, self.buf = self.buf, ""
        return text

    def open(self, version=" version='1.0'"):
        self.buf = ""
        self.send("<?xml version='1.0'?><stream:stream to='%s' "
                  "xmlns='%s' "
                  "xmlns:stream='http://etherx.jabber.org/streams'%s>"
                  % (self.domain, self.ns, version))

    def open_features(self):
        self.open()
        return self.expect(r"<stream:features.*?</stream:features>").group(0)

    def starttls(self):
        self.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        self.expect(r"<proceed[^>]*/>")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # the test certificate is self-signed
        self.sock = ctx.wrap_socket(self.sock, server_hostname=self.domain)
        self.tls_version = self.sock.version()

    def iq(self, iq_id, body):
        self.send(body)
        return self.expect(r"<iq[^>]*id=['\"]%s['\"][^>]*?(/>|>.*?</iq>)"
                           % iq_id).group(0)


def mechanisms(features):
    return re.findall(r"<mechanism>([^<]+)</mechanism>", features)


def attrs_of(tag):
    return dict(re.findall(r"([\w:]+)=['\"]([^'\"]*)['\"]", tag))


def tls_stream(domain):
    """A stream after STARTTLS, and its features."""
    s = Stream(domain)
    features = s.open_features()
    if "urn:ietf:params:xml:ns:xmpp-tls" not in features:
        raise ValueError("no STARTTLS offered")
    s.starttls()
    return s, s.open_features()


def plain_before_tls(domain):
    features = Stream(domain).open_features()
    if "urn:ietf:params:xml:ns:xmpp-tls" not in features:
        print("no STARTTLS offered", file=sys.stderr)
        return 1
    offered = mechanisms(features)
    print("mechanisms before TLS: %s" % (offered or "none"))
    return 1 if "PLAIN" in offered else 0


def iq_auth(user, domain):
    s, features = tls_stream(domain)
    print("iq-auth feature: %s"
          % ("offered" if "http://jabber.org/features/iq-auth" in features
             else "not offered"))
    reply = s.iq("a1", "<iq type='get' id='a1'><query xmlns='jabber:iq:auth'>"
                 "<username>%s</username></query></iq>" % user)
    m = re.search(r"<error\b[^>]*>\s*<([\w-]+)", reply)
    if m:
        print("answer: error %s" % m.group(1))
    elif "type='result'" in reply or 'type="result"' in reply:
        print("answer: fields")
    else:
        print("answer: %s" % reply)
    return 0


def component(secret, domain):
    s = Stream("test-component." + domain, ROUTER_PORT,
               "jabber:component:accept")
    s.open(version="")
    try:
        header = s.expect(r"<stream:stream[^>]*>").group(0)
        sid = attrs_of(header).get("id", "")
        digest = hashlib.sha1((sid + secret).encode()).hexdigest()
        s.send("<handshake>%s</handshake>" % digest)
        s.expect(r"<handshake[^>]*/>|<handshake[^>]*>\s*</handshake>")
    except Closed as e:
        print("component handshake refused: %s" % e, file=sys.stderr)
        return 2
    print("component handshake accepted")
    return 0


def pipeline(users, password, domain):
    s, features = tls_stream(domain)
    if "PLAIN" not in mechanisms(features):
        raise ValueError("PLAIN not offered after STARTTLS")
    requests = ""
    for user in users.split(","):
        token = base64.b64encode(
            ("\0%s\0%s" % (user, password)).encode()).decode()
        requests += ("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
                     "mechanism='PLAIN'>%s</auth>" % token)
    s.send(requests)    # one write: one TLS record, read by c2s at once
    text = s.collect(8)
    print("sent %d requests in one write" % len(users.split(",")))
    print("failures: %d" % len(re.findall(r"<failure\b", text)))
    print("successes: %d" % len(re.findall(r"<success\b", text)))
    print("stream closed: %s" % ("yes" if re.search(STREAM_END, text)
                                 else "no"))
    return 0


def sign_in(args):
    s, features = tls_stream(args.domain)
    if "PLAIN" not in mechanisms(features):
        print("PLAIN not offered after STARTTLS: %s" % features,
              file=sys.stderr)
        return 1

    passwords = ["wrong-%d" % i for i in range(args.wrong_first)]
    passwords.append(args.password)
    failures = 0
    for n, password in enumerate(passwords):
        token = base64.b64encode(
            ("\0%s\0%s" % (args.user, password)).encode()).decode()
        try:
            s.send("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
                   "mechanism='PLAIN'>%s</auth>" % token)
            result = s.expect(r"<success[^>]*?(/>|>.*?</success>)|"
                              r"<failure.*?</failure>").group(0)
        except (Closed, BrokenPipeError, ConnectionResetError) as e:
            print("closed after %d failures" % failures)
            print("closed: %s" % e, file=sys.stderr)
            return 3
        if result.startswith("<success"):
            break
        failures += 1
        if n == len(passwords) - 1:
            print("refused: %s" % result, file=sys.stderr)
            return 2

    features = s.open_features()
    s.iq("b1", "<iq type='set' id='b1'><bind "
         "xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>test"
         "</resource></bind></iq>")
    if "urn:ietf:params:xml:ns:xmpp-session" in features:
        s.iq("s1", "<iq type='set' id='s1'><session "
             "xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>")
    roster = s.iq("r1", "<iq type='get' id='r1'><query "
                  "xmlns='jabber:iq:roster'/></iq>")

    print("# signed in as %s@%s over %s" % (args.user, args.domain,
                                            s.tls_version))
    if failures:
        print("# after %d failures" % failures)
    for item in re.finditer(r"<item\b([^>]*?)(/>|>(.*?)</item>)", roster, re.S):
        attrs = attrs_of(item.group(1))
        groups = re.findall(r"<group>([^<]*)</group>", item.group(3) or "")
        print("\t".join([attrs.get("jid", ""), attrs.get("subscription", ""),
                         attrs.get("name", ""), ",".join(groups)]))

    if args.hold:
        s.send("<presence/>")
        text = s.collect(args.hold)
        for iq in re.finditer(r"<iq\b[^>]*>\s*<query\b[^>]*jabber:iq:roster"
                              r".*?</iq>", text, re.S):
            for item in re.finditer(r"<item\b([^>]*?)(/>|>)", iq.group(0)):
                attrs = attrs_of(item.group(1))
                print("push\t%s\t%s" % (attrs.get("jid", ""),
                                        attrs.get("subscription", "")))
        for pres in re.finditer(r"<presence\b([^>]*?)(/>|>)", text):
            attrs = attrs_of(pres.group(1))
            print("presence\t%s\t%s" % (attrs.get("from", ""),
                                        attrs.get("type", "available")))

    s.send("<presence type='unavailable'/></stream:stream>")
    return 0


def main(argv):
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--plain-before-tls", action="store_true")
    p.add_argument("--iq-auth", action="store_true")
    p.add_argument("--component", action="store_true")
    p.add_argument("--pipeline", action="store_true")
    p.add_argument("--wrong-first", type=int, default=0)
    p.add_argument("--hold", type=float, default=0)
    p.add_argument("rest", nargs="+")
    args = p.parse_args(argv)

    if args.plain_before_tls:
        (domain,) = args.rest
        return plain_before_tls(domain)
    if args.iq_auth:
        user, domain = args.rest
        return iq_auth(user, domain)
    if args.component:
        secret, domain = args.rest
        return component(secret, domain)
    if args.pipeline:
        users, password, domain = args.rest
        return pipeline(users, password, domain)
    args.user, args.password, args.domain = args.rest
    return sign_in(args)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, Closed, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(1)
