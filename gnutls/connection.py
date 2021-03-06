"""
GNUTLS connection support
"""

__all__ = [
    "X509Credentials",
    "TLSContext",
    "TLSContextServerOptions",
    "ClientSession",
    "ServerSession",
    "ServerSessionFactory",
]

from time import time

from twisted.internet import ssl
from gnutls.library.constants import GNUTLS_SHUT_RDWR as SOCKET_SHUT_RDWR
from gnutls.constants import CRED_CERTIFICATE

from _ctypes import PyObj_FromPtr
from ctypes import (
    c_char_p,
    POINTER,
    c_uint,
    c_void_p,
    string_at,
    c_size_t,
    byref,
    cast,
    create_string_buffer,
)

from gnutls.crypto import X509Identity, X509Certificate

from gnutls.errors import (
    CertificateAuthorityError,
    CertificateError,
    CertificateExpiredError,
    CertificateRevokedError,
    CertificateSecurityError,
    RequestedDataNotAvailable,
    GNUTLSError,
)

from gnutls.library.constants import (
    GNUTLS_A_BAD_CERTIFICATE,
    GNUTLS_A_CERTIFICATE_EXPIRED,
    GNUTLS_A_CERTIFICATE_REVOKED,
    GNUTLS_A_INSUFFICIENT_SECURITY,
    GNUTLS_AL_FATAL,
    GNUTLS_A_UNKNOWN_CA,
    GNUTLS_CERT_INSECURE_ALGORITHM,
    GNUTLS_CERT_INVALID,
    GNUTLS_CERT_REQUEST,
    GNUTLS_CERT_REVOKED,
    GNUTLS_CERT_SIGNER_NOT_CA,
    GNUTLS_CERT_SIGNER_NOT_FOUND,
    GNUTLS_CLIENT,
    GNUTLS_CRT_X509,
    GNUTLS_NAME_DNS,
    GNUTLS_SERVER,
    GNUTLS_SHUT_RDWR,
    GNUTLS_X509_FMT_DER,
)

from gnutls.library.types import (
    gnutls_certificate_credentials_t,
    gnutls_session_t,
    gnutls_certificate_retrieve_function,
    gnutls_priority_t,
    gnutls_x509_crt_t,
)

from gnutls.library.functions import (
    gnutls_alert_send,
    gnutls_bye,
    gnutls_certificate_allocate_credentials,
    gnutls_certificate_free_credentials,
    gnutls_certificate_get_peers,
    gnutls_certificate_server_set_request,
    gnutls_certificate_set_retrieve_function,
    gnutls_certificate_set_verify_limits,
    gnutls_certificate_set_x509_key,
    gnutls_certificate_set_x509_trust,
    gnutls_certificate_type_get,
    gnutls_certificate_verify_peers2,
    gnutls_cipher_get,
    gnutls_cipher_get_name,
    gnutls_compression_get,
    gnutls_compression_get_name,
    gnutls_credentials_clear,
    gnutls_credentials_set,
    gnutls_deinit,
    gnutls_handshake,
    gnutls_handshake_set_private_extensions,
    gnutls_init,
    gnutls_kx_get,
    gnutls_kx_get_name,
    gnutls_mac_get,
    gnutls_mac_get_name,
    gnutls_priority_deinit,
    gnutls_priority_init,
    gnutls_priority_set_direct,
    gnutls_protocol_get_name,
    gnutls_protocol_get_version,
    gnutls_record_get_direction,
    gnutls_record_recv,
    gnutls_record_send,
    gnutls_server_name_get,
    gnutls_server_name_set,
    gnutls_session_get_ptr,
    gnutls_session_set_ptr,
    gnutls_set_default_priority,
    gnutls_transport_set_ptr,
)

@gnutls_certificate_retrieve_function
def _retrieve_certificate(
    c_session, req_ca_dn, nreqs, pk_algos, pk_algos_length, retr_st
):
    session = PyObj_FromPtr(gnutls_session_get_ptr(c_session))
    identity = session.credentials.select_server_identity(session)
    retr_st.contents.deinit_all = 0
    if identity is None:
        retr_st.contents.ncerts = 0
    else:
        retr_st.contents.ncerts = 1
        retr_st.contents.cert_type = GNUTLS_CRT_X509
        retr_st.contents.cert.x509.contents = identity.cert._c_object
        retr_st.contents.key.x509 = identity.key._c_object
    return 0


class _ServerNameIdentities(dict):
    """
    Used internally by X509Credentials to map server names
    to X509 identities for the server name extension
    """

    def __init__(self, identities):
        dict.__init__(self)
        for identity in identities:
            self.add(identity)

    def add(self, identity):
        for name in identity.cert.alternative_names.dns:
            self[name.decode().lower()] = identity
        for ip in identity.cert.alternative_names.ip:
            self[ip.decode()] = identity
        subject = identity.cert.subject
        if subject.CN is not None:
            self[subject.CN.lower()] = identity

    def get(self, server_name, default=None):
        server_name = server_name.decode().lower()
        if server_name in self:
            return self[server_name]
        for name in (n for n in self if n.startswith("*.")):
            suffix = name[1:]
            if server_name.endswith(suffix) and "." not in server_name[: -len(suffix)]:
                return self[name]
        return default


class X509Credentials(object):
    def __new__(cls, *args, **kwargs):
        c_object = gnutls_certificate_credentials_t()
        gnutls_certificate_allocate_credentials(byref(c_object))
        instance = object.__new__(cls)
        instance.__deinit = gnutls_certificate_free_credentials
        instance._c_object = c_object
        return instance

    def __init__(self, cert=None, key=None, trusted=[], crl_list=[], identities=[]):
        """
        Credentials contain a X509 certificate, a private key, a list of trusted CAs and
        a list of CRLs (all optional).
        An optional list of additional X509 identities can be specified for applications
        that need more that one identity
        """
        if cert and key:
            gnutls_certificate_set_x509_key(
                self._c_object, byref(cert._c_object), 1, key._c_object
            )
        elif (cert, key) != (None, None):
            raise ValueError("Specify neither or both the certificate and private key")
        gnutls_certificate_set_retrieve_function(self._c_object, _retrieve_certificate)
        self._max_depth = 5
        self._max_bits = 8200
        self._type = CRED_CERTIFICATE
        self._cert = cert
        self._key = key
        self._identities = tuple(identities)
        self._trusted = ()
        self.add_trusted(trusted)
        self.crl_list = crl_list
        self.server_name_identities = _ServerNameIdentities(identities)
        if cert and key:
            self.server_name_identities.add(X509Identity(cert, key))

    def __del__(self):
        self.__deinit(self._c_object)

    # Methods to alter the credentials at runtime

    def verify_callback(self, peer_cert, preverify_status=None):
        """
        Verifies the peer certificate and raises an exception if it cannot be accepted
        """
        if isinstance(preverify_status, Exception):
            raise preverify_status
        self.check_certificate(peer_cert, cert_name='peer certificate')

    def add_trusted(self, trusted):
        size = len(trusted)
        if size > 0:
            ca_list = (gnutls_x509_crt_t * size)(*[cert._c_object for cert in trusted])
            gnutls_certificate_set_x509_trust(
                self._c_object, cast(byref(ca_list), POINTER(gnutls_x509_crt_t)), size
            )
            self._trusted = self._trusted + tuple(trusted)

    # Properties

    @property
    def cert(self):
        return self._cert

    @property
    def key(self):
        return self._key

    @property
    def identities(self):
        return self._identities

    @property
    def trusted(self):
        return self._trusted

    def _get_crl_list(self):
        return self._crl_list

    def _set_crl_list(self, crl_list):
        self._crl_list = tuple(crl_list)

    crl_list = property(_get_crl_list, _set_crl_list)
    del _get_crl_list, _set_crl_list

    def _get_max_verify_length(self):
        return self._max_depth

    def _set_max_verify_length(self, max_depth):
        gnutls_certificate_set_verify_limits(self._c_object, self._max_bits, max_depth)
        self._max_depth = max_depth

    max_verify_length = property(_get_max_verify_length, _set_max_verify_length)
    del _get_max_verify_length, _set_max_verify_length

    def _get_max_verify_bits(self):
        return self._max_bits

    def _set_max_verify_bits(self, max_bits):
        gnutls_certificate_set_verify_limits(self._c_object, max_bits, self._max_depth)
        self._max_bits = max_bits

    max_verify_bits = property(_get_max_verify_bits, _set_max_verify_bits)
    del _get_max_verify_bits, _set_max_verify_bits

    # Methods to select and validate certificates

    def check_certificate(self, cert, cert_name="certificate"):
        """
        Verify activation, expiration and revocation for the given certificate
        """
        now = time()
        if cert.activation_time > now:
            raise CertificateExpiredError("%s is not yet activated" % cert_name)
        if cert.expiration_time < now:
            raise CertificateExpiredError("%s has expired" % cert_name)
        for crl in self.crl_list:
            crl.check_revocation(cert, cert_name=cert_name)

    def select_server_identity(self, session):
        """
        Select which identity the server will use for a given session.
        The default selection algorithm uses
        the server name extension. A subclass can overwrite it
        if a different selection algorithm is desired.
        """
        server_name = session.server_name
        if server_name is not None:
            return self.server_name_identities.get(server_name)
        elif self.cert and self.key:
            return self
            # since we have the cert and key attributes
            # we can behave like a X509Identity
        else:
            return None


class TLSContextServerOptions(object):
    def __init__(self, certificate_request=GNUTLS_CERT_REQUEST):
        self.certificate_request = certificate_request


class TLSContext(object):
    def __init__(self, credentials, session_parameters=None, server_options=None):
        self.credentials = credentials
        self.session_parameters = session_parameters
        self.server_options = server_options or TLSContextServerOptions()

    @property
    def session_parameters(self):
        return self.__dict__.get("session_parameters")

    @session_parameters.setter
    def session_parameters(self, value):
        priority = gnutls_priority_t()
        try:
            if value:
                value = bytes(value, 'utf-8')
            gnutls_priority_init(byref(priority), value, None)
        except GNUTLSError:
            raise ValueError("invalid session parameters: %s" % value)
        else:
            gnutls_priority_deinit(priority)
        self.__dict__["session_parameters"] = value

    def getContext(self):
        return TLSContext(self.credentials)


class Session(object):
    """
    Abstract class representing a TLS session created
    from a TCP socket and a Credentials object.
    """

    session_type = (
        None  # placeholder for GNUTLS_SERVER or GNUTLS_CLIENT as defined by subclass
    )

    def __new__(cls, *args, **kwargs):
        if cls is Session:
            raise RuntimeError("Session cannot be instantiated directly")
        instance = object.__new__(cls)
        instance.__deinit = gnutls_deinit
        instance._c_object = gnutls_session_t()
        return instance

    def __init__(self, socket, context):
        gnutls_init(byref(self._c_object), self.session_type)
        # Store a pointer to self on the C session
        gnutls_session_set_ptr(self._c_object, id(self))
        gnutls_set_default_priority(self._c_object)
        if context.session_parameters:
            if isinstance(context.session_parameters, str):
                parameters = bytes(context.session_parameters, 'utf-8')
            else:
                parameters = context.session_parameters
        else:
            parameters = None
        gnutls_priority_set_direct(self._c_object, parameters, None)
        gnutls_transport_set_ptr(self._c_object, socket.fileno())
        gnutls_handshake_set_private_extensions(self._c_object, 1)
        self.socket = socket
        self.context = context
        self.credentials = context.credentials

    def __del__(self):
        self.__deinit(self._c_object)

    def __getattr__(self, name):
        # Generic wrapper for the underlying socket methods and attributes.
        return getattr(self.socket, name)

    # Session properties

    def _get_credentials(self):
        return self._credentials

    def _set_credentials(self, credentials):
        # Release all credentials, otherwise gnutls will only release
        # an existing credential of
        # the same type as the one being set and we can end up
        # with multiple credentials in C.
        gnutls_credentials_clear(self._c_object)
        gnutls_credentials_set(
            self._c_object, credentials._type, cast(credentials._c_object, c_void_p)
        )
        self._credentials = credentials

    credentials = property(_get_credentials, _set_credentials)
    del _get_credentials, _set_credentials

    @property
    def protocol(self):
        return gnutls_protocol_get_name(gnutls_protocol_get_version(self._c_object))

    @property
    def kx_algorithm(self):
        return gnutls_kx_get_name(gnutls_kx_get(self._c_object))

    @property
    def cipher(self):
        return gnutls_cipher_get_name(gnutls_cipher_get(self._c_object))

    @property
    def mac_algorithm(self):
        return gnutls_mac_get_name(gnutls_mac_get(self._c_object))

    @property
    def compression(self):
        return gnutls_compression_get_name(gnutls_compression_get(self._c_object))

    @property
    def peer_certificate(self):
        if gnutls_certificate_type_get(self._c_object) != GNUTLS_CRT_X509:
            return None
        list_size = c_uint()
        cert_list = gnutls_certificate_get_peers(self._c_object, byref(list_size))
        if list_size.value == 0:
            return None
        cert = cert_list[0]
        return X509Certificate(string_at(cert.data, cert.size), GNUTLS_X509_FMT_DER)

    # Status checking after an operation was interrupted (these properties are
    # only useful to check after an operation was interrupted, otherwise their
    # value is meaningless).

    @property
    def interrupted_while_writing(self):
        """
        True if an operation was interrupted while writing
        """
        return gnutls_record_get_direction(self._c_object) == 1

    @property
    def interrupted_while_reading(self):
        """
        True if an operation was interrupted while reading
        """
        return gnutls_record_get_direction(self._c_object) == 0

    # Session methods

    def handshake(self):
        gnutls_handshake(self._c_object)

    def send(self, data):
        if not data:
            return 0

        elif isinstance(data, memoryview):
            data = data.tobytes()

        return gnutls_record_send(self._c_object, data, len(data))

    def sendall(self, data):
        size = len(data)
        while size > 0:
            sent = self.send(data[-size:])
            size -= sent

    def recv(self, limit):
        data = create_string_buffer(limit)
        size = gnutls_record_recv(self._c_object, data, limit)
        return data[:size]

    def send_alert(self, exception):
        alertdict = {
            CertificateError: GNUTLS_A_BAD_CERTIFICATE,
            CertificateAuthorityError: GNUTLS_A_UNKNOWN_CA,
            CertificateSecurityError: GNUTLS_A_INSUFFICIENT_SECURITY,
            CertificateExpiredError: GNUTLS_A_CERTIFICATE_EXPIRED,
            CertificateRevokedError: GNUTLS_A_CERTIFICATE_REVOKED,
        }
        alert = alertdict.get(exception.__class__)
        if alert:
            gnutls_alert_send(self._c_object, GNUTLS_AL_FATAL, alert)

    def bye(self, how=GNUTLS_SHUT_RDWR):
        gnutls_bye(self._c_object, how)

    def shutdown(self, how=SOCKET_SHUT_RDWR):
        self.socket.shutdown(how)

    def close(self):
        self.socket.close()

    def verify_peer(self):
        status = c_uint()
        gnutls_certificate_verify_peers2(self._c_object, byref(status))
        status = status.value
        if status & GNUTLS_CERT_SIGNER_NOT_FOUND:
            raise CertificateAuthorityError("peer certificate signer not found", self.peer_certificate, self.context)
        elif status & GNUTLS_CERT_SIGNER_NOT_CA:
            raise CertificateAuthorityError("peer certificate signer is not a CA", self.peer_certificate, self.context)
        elif status & GNUTLS_CERT_INVALID:
            raise CertificateError("peer certificate invalid", self.peer_certificate, self.context)
        elif status & GNUTLS_CERT_INSECURE_ALGORITHM:
            raise CertificateSecurityError("peer certificate uses an insecure algorithm ", self.peer_certificate, self.context)
        elif status & GNUTLS_CERT_REVOKED:
            raise CertificateRevokedError("peer certificate was revoked", self.peer_certificate, self.context)


class ClientSession(Session):
    session_type = GNUTLS_CLIENT

    def __init__(self, socket, context, server_name=None):
        Session.__init__(self, socket, context)
        self._server_name = None
        if server_name is not None:
            self.server_name = server_name

    def _get_server_name(self):
        return self._server_name

    def _set_server_name(self, server_name):
        gnutls_server_name_set(
            self._c_object, GNUTLS_NAME_DNS, c_char_p(server_name), len(server_name)
        )
        self._server_name = server_name

    server_name = property(_get_server_name, _set_server_name)
    del _get_server_name, _set_server_name


class ServerSession(Session):
    session_type = GNUTLS_SERVER

    def __init__(self, socket, context):
        Session.__init__(self, socket, context)
        if context.server_options.certificate_request is not None:
            gnutls_certificate_server_set_request(
                self._c_object, context.server_options.certificate_request
            )

    @property
    def server_name(self):
        data_length = c_size_t(256)
        data = create_string_buffer(data_length.value)
        hostname_type = c_uint()
        for i in range(2 ** 16):
            try:
                gnutls_server_name_get(
                    self._c_object, data, byref(data_length), byref(hostname_type), i
                )
            except RequestedDataNotAvailable:
                break
            except MemoryError:
                data_length.value += 1  # one extra byte for the terminating 0
                data = create_string_buffer(data_length.value)
                gnutls_server_name_get(
                    self._c_object, data, byref(data_length), byref(hostname_type), i
                )
            if hostname_type.value != GNUTLS_NAME_DNS:
                continue
            return data.value
        return None


class ServerSessionFactory(object):
    def __init__(self, socket, context, session_class=ServerSession):
        if not issubclass(session_class, ServerSession):
            raise TypeError("session_class must be a subclass of ServerSession")
        self.socket = socket
        self.context = context
        self.session_class = session_class

    def __getattr__(self, name):
        # Generic wrapper for the underlying socket methods and attributes
        return getattr(self.socket, name)

    def bind(self, address):
        self.socket.bind(address)

    def listen(self, backlog):
        self.socket.listen(backlog)

    def accept(self):
        new_sock, address = self.socket.accept()
        session = self.session_class(new_sock, self.context)
        return session, address

    def shutdown(self, how=SOCKET_SHUT_RDWR):
        self.socket.shutdown(how)

    def close(self):
        self.socket.close()
