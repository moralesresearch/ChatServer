#!/usr/bin/env python3
"""A minimal XMPP client for testing ChatServer: STARTTLS, SASL PLAIN,
resource binding and a roster fetch. Standard library only.

usage: xmpp_client.py [--plain-before-tls] USER PASSWORD DOMAIN

Prints the roster as lines of "jid<TAB>subscription<TAB>name<TAB>groups"
and exits 0 when the user signed in; exits 2 when the server refused the
password, 1 on any other error. With --plain-before-tls it only reports
whether PLAIN is offered before STARTTLS (exit 0 if not offered).
"""

import base64
import re
import socket
import ssl
import sys

HOST, PORT = "127.0.0.1", 5222


class Stream:
    def __init__(self, domain):
        self.domain = domain
        self.sock = socket.create_connection((HOST, PORT), timeout=15)
        self.buf = ""

    def send(self, data):
        self.sock.sendall(data.encode())

    def expect(self, pattern):
        rx = re.compile(pattern, re.S)
        while True:
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            data = self.sock.recv(65536)
            if not data:
                raise EOFError("connection closed; received: " + self.buf)
            self.buf += data.decode("utf-8", "replace")

    def open(self):
        self.buf = ""
        self.send("<?xml version='1.0'?><stream:stream to='%s' "
                  "xmlns='jabber:client' "
                  "xmlns:stream='http://etherx.jabber.org/streams' "
                  "version='1.0'>" % self.domain)
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


def main(argv):
    plain_check = False
    if argv and argv[0] == "--plain-before-tls":
        plain_check = True
        argv = argv[1:]
    user, password, domain = argv

    s = Stream(domain)
    features = s.open()
    if "urn:ietf:params:xml:ns:xmpp-tls" not in features:
        print("no STARTTLS offered", file=sys.stderr)
        return 1
    if plain_check:
        offered = mechanisms(features)
        print("mechanisms before TLS: %s" % (offered or "none"))
        return 1 if "PLAIN" in offered else 0

    s.starttls()
    features = s.open()
    if "PLAIN" not in mechanisms(features):
        print("PLAIN not offered after STARTTLS: %s" % features,
              file=sys.stderr)
        return 1

    token = base64.b64encode(("\0%s\0%s" % (user, password)).encode()).decode()
    s.send("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
           "mechanism='PLAIN'>%s</auth>" % token)
    result = s.expect(r"<success[^>]*?(/>|>.*?</success>)|"
                      r"<failure.*?</failure>").group(0)
    if result.startswith("<failure"):
        print("refused: %s" % result, file=sys.stderr)
        return 2

    features = s.open()
    s.iq("b1", "<iq type='set' id='b1'><bind "
         "xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>test"
         "</resource></bind></iq>")
    if "urn:ietf:params:xml:ns:xmpp-session" in features:
        s.iq("s1", "<iq type='set' id='s1'><session "
             "xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>")
    roster = s.iq("r1", "<iq type='get' id='r1'><query "
                  "xmlns='jabber:iq:roster'/></iq>")

    print("# signed in as %s@%s over %s" % (user, domain, s.tls_version))
    for item in re.finditer(r"<item\b([^>]*?)(/>|>(.*?)</item>)", roster, re.S):
        attrs = dict(re.findall(r"(\w+)=['\"]([^'\"]*)['\"]", item.group(1)))
        groups = re.findall(r"<group>([^<]*)</group>", item.group(3) or "")
        print("\t".join([attrs.get("jid", ""), attrs.get("subscription", ""),
                         attrs.get("name", ""), ",".join(groups)]))

    s.send("<presence type='unavailable'/></stream:stream>")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, EOFError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(1)
