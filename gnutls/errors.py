"""GNUTLS errors"""

__all__ = [
    "Error",
    "GNUTLSError",
    "OperationWouldBlock",
    "OperationInterrupted",
    "CertificateError",
    "CertificateAuthorityError",
    "CertificateSecurityError",
    "CertificateExpiredError",
    "CertificateRevokedError",
    "RequestedDataNotAvailable",
]


class Error(Exception):
    pass


class GNUTLSError(Error):
    pass


class OperationWouldBlock(GNUTLSError):
    pass


class OperationInterrupted(GNUTLSError):
    pass


class CertificateError(GNUTLSError):
    def __init__(self, error, certificate=None, context=None):
        self.error = error
        self.certificate = certificate
        self.context = context


class CertificateAuthorityError(CertificateError):
    def __init__(self, error, certificate=None, context=None):
        self.error = error
        self.certificate = certificate
        self.context = context


class CertificateSecurityError(CertificateError):
    def __init__(self, error, certificate=None, context=None):
        self.error = error
        self.certificate = certificate
        self.context = context


class CertificateExpiredError(CertificateError):
    def __init__(self, error, certificate=None, context=None):
        self.error = error
        self.certificate = certificate
        self.context = context


class CertificateRevokedError(CertificateError):
    def __init__(self, error, certificate=None, context=None):
        self.error = error
        self.certificate = certificate
        self.context = context


class RequestedDataNotAvailable(GNUTLSError):
    pass
