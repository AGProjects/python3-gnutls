#!/usr/bin/env python3

"""Synchronous server that handles each connection in a thread"""

import sys
import os
import socket
from threading import Thread

from gnutls.crypto import *
from gnutls.connection import *

script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())
ca = X509Certificate(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())
cred = X509Credentials(cert, key, [ca], [crl])
context = TLSContext(cred)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ssf = ServerSessionFactory(sock, context)
ssf.bind(('0.0.0.0', 10000))
ssf.listen(100)

#X509Credentials.verify_peer=False


class SessionHandler(Thread):
    def __init__(self, session, address):
        Thread.__init__(self, name='SessionHandler')
        self.setDaemon(True)
        self.session = session
        self.address = address

    def run(self):
        session = self.session
        try:
            session.handshake()
            peer_cert = session.peer_certificate
            try:
                peer_name = peer_cert.subject
            except AttributeError:
                peer_name = 'Unknown'
            print('\nNew connection from:', peer_name)
            print('Protocol:     ', session.protocol.decode())
            print('KX algorithm: ', session.kx_algorithm.decode())
            print('Cipher:       ', session.cipher.decode())
            print('MAC algorithm:', session.mac_algorithm.decode())
            print('Compression:  ', session.compression.decode())
            session.verify_peer()
            cred.check_certificate(peer_cert, cert_name='peer certificate')
        except Exception as e:
            print('Handshake failed:', e)
        else:
            while True:
                try:
                    buf = session.recv(1024)
                    if not buf:
                        print("Peer has closed the session")
                        break
                    else:
                        if buf.strip().lower() == 'quit':
                            print("Got quit command, closing connection")
                            session.bye()
                            break
                    print("\nReceived from client: %s" % buf.decode())
                    session.send(b"Hello, I have received this from you: " + buf)
                except Exception as e:
                    print("Error in reception: ", e)
                    break
        try:
            session.shutdown()
        except:
            pass
        session.close()

while True:
    session, address = ssf.accept()
    handler = SessionHandler(session, address)
    handler.start()
