#!/usr/bin/python

import sys, os
script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
gnutls_path = os.path.realpath(os.path.join(script_path, '..'))
sys.path[0:0] = [gnutls_path]

from gnutls.crypto import *
from gnutls.connection import *
from gnutls.errors import *
from gnutls.interfaces import twisted

from twisted.internet import pollreactor; pollreactor.install()
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor

class EchoProtocol(LineOnlyReceiver):
    delimiter = '\n'
    
    def connectionMade(self):
        self.sendLine('echo')
    
    def lineReceived(self, line):
        print 'received: ', line
        self.transport.loseConnection()
        reactor.stop()

class EchoFactory(ClientFactory):
    protocol = EchoProtocol

certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())

ca = X509Certificate(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())

cred = X509Credentials(cert, key, [ca])

reactor.connectTLS('localhost', 10000, EchoFactory(), cred)

reactor.run()