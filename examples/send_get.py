#!/usr/bin/env python3

import socket
import gnutls.errors
from gnutls.connection import *


def get(hostname, port=443):
    ctx = TLSContext(X509Credentials())
    sock = socket.create_connection((hostname, port))
    s = ClientSession(sock, ctx)
    s.handshake()
    print(s.peer_certificate.subject)
    print(s.protocol.decode(), s.cipher.decode())
    s.send(memoryview(f'GET / HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0\r\nAccept: */*\r\n\r\n'.encode()))
    try:
        print(s.recv(1024).decode())
    except gnutls.errors.GNUTLSError as e:
        if 'Rehandshake' in str(e):
            s.handshake()
            print(s.recv(1024).decode())
    except Exception:
        print('pass')
    s.shutdown()
    s.close()


if __name__ == '__main__':
    for x in {'www.github.com'}:
        get(x)
