# Copyright (C) 2007 AG Projects
#

"""GNUTLS errors"""

__all__ = ['Error', 'GNUTLSError', 'CertificateError', 'X509NameError', 'GNUTLSException']

from gnutls.library.constants import *
from gnutls.library.functions import gnutls_strerror

class Error(Exception): pass
class GNUTLSError(Error): pass
class CertificateError(Error): pass
class X509NameError(Error): pass

class GNUTLSException(object):
    @classmethod
    def check(cls, retcode):
        if retcode >= 0:
            return
        elif retcode == GNUTLS_E_AGAIN:
            raise WouldBlockError(gnutls_strerror(retcode))
        elif retcode in (GNUTLS_E_MEMORY_ERROR, GNUTLS_E_SHORT_MEMORY_BUFFER):
            raise MemoryError(gnutls_strerror(retcode))
        elif retcode in (GNUTLS_E_NO_CERTIFICATE_FOUND, ):
            raise CertificateError(gnutls_strerror(retcode))
        else:
            raise GNUTLSError(gnutls_strerror(retcode))