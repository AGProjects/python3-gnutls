#!/usr/bin/env python3

"""Synchronous client using python-gnutls"""

import sys
import os
import socket

from gnutls.crypto import *
from gnutls.connection import *
from gnutls.errors import GNUTLSError

script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())
ca_text = open(certs_path + '/ca.pem').read()

start = False
ca = []
for line in ca_text.split("\n"):
    if "BEGIN CERT" in line:
       start = True
       crt = line + "\n"
    elif "END CERT" in line:
       crt = crt + line + "\n"
       end = True
       start = False
       try:
           ca_cert = X509Certificate(crt)
           ca.append(ca_cert)
       except GNUTLSError:
           continue

    elif start:
       crt = crt + line + "\n"
                      
crl = X509CRL(open(certs_path + '/crl.pem').read())
cred = X509Credentials(cert, key, ca, [crl])
context = TLSContext(cred)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
session = ClientSession(sock, context)

try:
    session.connect(('127.0.0.1', 10000))
    session.handshake()
    peer_cert = session.peer_certificate

    try:
        peer_name = peer_cert.subject
    except AttributeError:
        peer_name = 'Unknown'

    print('\n')
    print('Connection to:', peer_name)
    print('Issued by:    ', peer_cert.issuer)
    print('Protocol:     ', session.protocol.decode())
    print('KX algorithm: ', session.kx_algorithm.decode())
    print('Cipher:       ', session.cipher.decode())
    print('MAC algorithm:', session.mac_algorithm.decode())
    print('Compression:  ', session.compression.decode())
            
    session.verify_peer()
    print('Certificate is verified')
    session.send(b"Test data")
    buf = session.recv(1024)
    print('\nReceived from server: ', buf.rstrip().decode("utf-8"))
    session.bye()
    session.close()
except GNUTLSError as e:
    print(('\nConnection failed: {}'.format(e)))
    sys.exit(1)
