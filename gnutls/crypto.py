"""GNUTLS crypto support"""

__all__ = [
    "X509Name",
    "X509Certificate",
    "X509PrivateKey",
    "X509Identity",
    "X509CRL",
    "DHParams",
    "Pkcs7",
    "X509TrustList",
    "PrivateKey",
    "PublicKey",
    "AEADCipher",
    "Cipher",
]

import math

import re
from ctypes import (
    byref,
    cast,
    c_char_p,
    create_string_buffer,
    c_size_t,
    c_uint,
    c_void_p,
)

from gnutls.errors import (
    CertificateError,
    CertificateRevokedError,
    RequestedDataNotAvailable,
)

from gnutls.library.constants import (
    GNUTLS_PK_DSA,
    GNUTLS_PK_ECDH_X25519,
    GNUTLS_PK_ECDSA,
    GNUTLS_PK_EDDSA_ED25519,
    GNUTLS_PK_RSA,
    GNUTLS_PK_RSA_PSS,
    GNUTLS_SAN_DN,
    GNUTLS_SAN_DNSNAME,
    GNUTLS_SAN_IPADDRESS,
    GNUTLS_SAN_OTHERNAME,
    GNUTLS_SAN_RFC822NAME,
    GNUTLS_SAN_URI,
    GNUTLS_X509_FMT_PEM,
)

from gnutls.library.types import gnutls_pkcs7_signature_info_st, gnutls_x509_dn_t

from gnutls.library.functions import (
    gnutls_aead_cipher_decrypt,
    gnutls_aead_cipher_deinit,
    gnutls_aead_cipher_encrypt,
    gnutls_aead_cipher_hd_t,
    gnutls_aead_cipher_init,
    gnutls_cipher_add_auth,
    gnutls_cipher_decrypt2,
    gnutls_cipher_deinit,
    gnutls_cipher_encrypt2,
    gnutls_cipher_get_block_size,
    gnutls_cipher_hd_t,
    gnutls_cipher_init,
    gnutls_cipher_set_iv,
    gnutls_cipher_tag,
    gnutls_datum_t,
    gnutls_dh_params_deinit,
    gnutls_dh_params_generate2,
    gnutls_dh_params_init,
    gnutls_dh_params_t,
    gnutls_digest_algorithm_t,
    gnutls_hex_encode2,
    gnutls_pkcs7_deinit,
    gnutls_pkcs7_export,
    gnutls_pkcs7_get_signature_count,
    gnutls_pkcs7_get_signature_info,
    gnutls_pkcs7_import,
    gnutls_pkcs7_init,
    gnutls_pkcs7_sign,
    gnutls_pkcs7_signature_info_deinit,
    gnutls_pkcs7_t,
    gnutls_pkcs7_verify,
    gnutls_pkcs7_verify_direct,
    gnutls_privkey_decrypt_data,
    gnutls_privkey_deinit,
    gnutls_privkey_export_dsa_raw,
    gnutls_privkey_export_rsa_raw,
    gnutls_privkey_generate,
    gnutls_privkey_get_pk_algorithm,
    gnutls_privkey_import_tpm_url,
    gnutls_privkey_import_url,
    gnutls_privkey_import_x509,
    gnutls_privkey_init,
    gnutls_privkey_sign_data,
    gnutls_privkey_sign_hash,
    gnutls_privkey_t,
    gnutls_pubkey_deinit,
    gnutls_pubkey_encrypt_data,
    gnutls_pubkey_export_dsa_raw,
    gnutls_pubkey_export_rsa_raw,
    gnutls_pubkey_get_pk_algorithm,
    gnutls_pubkey_get_preferred_hash_algorithm,
    gnutls_pubkey_import_dsa_raw,
    gnutls_pubkey_import_rsa_raw,
    gnutls_pubkey_import_tpm_url,
    gnutls_pubkey_import_url,
    gnutls_pubkey_import_x509,
    gnutls_pubkey_init,
    gnutls_pubkey_t,
    gnutls_pubkey_verify_data2,
    gnutls_pubkey_verify_hash2,
    gnutls_typed_vdata_st,
    gnutls_x509_crl_deinit,
    gnutls_x509_crl_export,
    gnutls_x509_crl_get_crt_count,
    gnutls_x509_crl_get_issuer_dn,
    gnutls_x509_crl_get_version,
    gnutls_x509_crl_import,
    gnutls_x509_crl_init,
    gnutls_x509_crl_t,
    gnutls_x509_crt_check_hostname,
    gnutls_x509_crt_check_issuer,
    gnutls_x509_crt_check_revocation,
    gnutls_x509_crt_deinit,
    gnutls_x509_crt_export,
    gnutls_x509_crt_get_activation_time,
    gnutls_x509_crt_get_dn,
    gnutls_x509_crt_get_expiration_time,
    gnutls_x509_crt_get_issuer_dn,
    gnutls_x509_crt_get_serial,
    gnutls_x509_crt_get_subject_alt_name,
    gnutls_x509_crt_get_version,
    gnutls_x509_crt_import,
    gnutls_x509_crt_init,
    gnutls_x509_crt_t,
    gnutls_x509_dn_deinit,
    gnutls_x509_dn_get_str2,
    gnutls_x509_dn_import,
    gnutls_x509_dn_init,
    gnutls_x509_privkey_deinit,
    gnutls_x509_privkey_export,
    gnutls_x509_privkey_import,
    gnutls_x509_privkey_init,
    gnutls_x509_privkey_t,
    gnutls_x509_trust_list_add_cas,
    gnutls_x509_trust_list_add_trust_mem,
    gnutls_x509_trust_list_deinit,
    gnutls_x509_trust_list_init,
    gnutls_x509_trust_list_t,
)


class CWrapper(object):
    ctype = None
    deinit = None

    def __init__(self, *args, **kwargs):
        super(CWrapper, self).__init__(*args, **kwargs)
        self._c_object = self.ctype()

    def __del__(self):
        if self.deinit:
            self.deinit(self._c_object)


class X509NameMeta(type):
    long_names = {
        "country": "C",
        "state": "ST",
        "locality": "L",
        "common_name": "CN",
        "organization": "O",
        "organization_unit": "OU",
        "email": "EMAIL",
    }

    def __new__(cls, name, bases, dic):
        instance = type.__new__(cls, name, bases, dic)
        instance.ids = X509NameMeta.long_names.values()
        for long_name, short_name in X509NameMeta.long_names.items():
            # Map a long_name property to the short_name attribute
            cls.add_property(instance, long_name, short_name)
        return instance

    def add_property(instance, name, short_name):
        setattr(instance, name, property(lambda self: getattr(self, short_name, None)))


class X509Name(str, metaclass=X509NameMeta):
    def __init__(self, dname):
        str.__init__(self)
        pairs = [x.replace("\\,", ",") for x in re.split(r"(?<!\\),", dname)]
        for pair in pairs:
            try:
                name, value = pair.split("=", 1)
            except ValueError:
                raise ValueError("Invalid X509 distinguished name: %s" % dname)
            str.__setattr__(self, name, value)
        for name in X509Name.ids:
            if not hasattr(self, name):
                str.__setattr__(self, name, None)

    def __setattr__(self, name, value):
        if name in X509Name.ids:
            raise AttributeError("can't set attribute")
        str.__setattr__(self, name, value)


class AlternativeNames(object):
    __slots__ = {
        "dns": GNUTLS_SAN_DNSNAME,
        "email": GNUTLS_SAN_RFC822NAME,
        "uri": GNUTLS_SAN_URI,
        "ip": GNUTLS_SAN_IPADDRESS,
        "other": GNUTLS_SAN_OTHERNAME,
        "dn": GNUTLS_SAN_DN,
    }

    def __init__(self, names):
        object.__init__(self)
        for name, key in self.__slots__.items():
            setattr(self, name, tuple(names.get(key, ())))


class X509TrustList(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_trust_list_deinit
        instance._c_object = gnutls_x509_trust_list_t()
        instance._alternative_names = None
        return instance

    def __init__(self):
        gnutls_x509_trust_list_init(byref(self._c_object), 0)

    def __del__(self):
        self.__deinit(self._c_object, 0)

    def add_ca(self, cert, flags=0):
        gnutls_x509_trust_list_add_cas(self._c_object, byref(cert._c_object), 1, flags)

    def add_certificate(self, cert, flags=0):

        # mrrrggg, we have to export the certificate to a blob
        buf = cert.export()
        data = gnutls_datum_t(buf)
        gnutls_x509_trust_list_add_trust_mem(self._c_object, byref(data))


class X509Dn(CWrapper):
    ctype = gnutls_x509_dn_t

    def __init__(self, data=None):
        super(X509Dn, self).__init__()
        gnutls_x509_dn_init(byref(self._c_object))
        if data:
            gnutls_x509_dn_import(self._c_object, data)
        self.deinit = gnutls_x509_dn_deinit

    def __str__(self):
        tmp = gnutls_datum_t()
        gnutls_x509_dn_get_str2(self._c_object, byref(tmp), 0)
        return tmp.get_string_and_free().decode()


def _gnutls_datum_t_hex_encode(self):
    if not self.data:
        None
    if not self.size:
        None
    tmp = gnutls_datum_t()
    gnutls_hex_encode2(self, byref(tmp))
    return tmp.get_string_and_free().decode()


class Pkcs7SignatureInfo(CWrapper):
    ctype = gnutls_pkcs7_signature_info_st

    def __init__(self):
        super(Pkcs7SignatureInfo, self).__init__()
        self.deinit = gnutls_pkcs7_signature_info_deinit

    @property
    def issuer_dn(self):
        return X509Dn(self._c_object.issuer_dn)

    @property
    def signing_time(self):
        return self._c_object.signing_time

    @property
    def algo(self):
        return self._c_object.algo

    @property
    def signer_serial(self):
        return _gnutls_datum_t_hex_encode(self._c_object.signer_serial)

    @property
    def issuer_keyid(self):
        return _gnutls_datum_t_hex_encode(self._c_object.issuer_keyid)


class Pkcs7(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_pkcs7_deinit
        instance._c_object = gnutls_pkcs7_t()
        instance._alternative_names = None
        return instance

    def __init__(self):
        gnutls_pkcs7_init(byref(self._c_object))

    def __del__(self):
        self.__deinit(self._c_object)

    def import_signature(self, buf, format=GNUTLS_X509_FMT_PEM):
        data = gnutls_datum_t(buf)
        gnutls_pkcs7_import(self._c_object, byref(data), format)

    def sign(self, cert, privkey, buf, hash_algo=None, flags=0):

        # auto detect the best algorithm to use
        if hash_algo is None:
            pubkey = PublicKey()
            pubkey.import_x509(cert)
            hash_algo = pubkey.get_preferred_hash_algorithm()

        # convert from a X509PrivateKey to a PrivateKey
        if isinstance(privkey, X509PrivateKey):
            pkey = PrivateKey()
            pkey.import_x509(privkey)
            privkey = pkey

        data = gnutls_datum_t(buf)
        gnutls_pkcs7_sign(
            self._c_object,
            cert._c_object,
            privkey._c_object,
            byref(data),
            0,  # FIXME?
            0,  # FIXME?
            hash_algo,
            flags,
        )

    def get_signature_count(self):
        return gnutls_pkcs7_get_signature_count(self._c_object)

    def get_signature_info(self):
        infos = []
        for idx in range(0, self.get_signature_count()):
            st = Pkcs7SignatureInfo()
            gnutls_pkcs7_get_signature_info(self._c_object, idx, byref(st._c_object))
            infos.append(st)
        return infos

    def verify_direct(self, cert, buf, idx=-1, flags=0):
        data = gnutls_datum_t(buf)

        # by default, check all signatures in context
        if idx == -1:
            idxs = list(range(self.get_signature_count()))
        else:
            idxs = [idx]
        for idx in idxs:
            gnutls_pkcs7_verify_direct(self._c_object, cert._c_object, idx, data, flags)

    def verify(self, tl, buf, idx=-1, flags=0):
        data = gnutls_datum_t(buf)
        vdata = gnutls_typed_vdata_st()

        # by default, check all signatures in context
        if idx == -1:
            idxs = list(range(self.get_signature_count()))
        else:
            idxs = [idx]
        for idx in idxs:
            gnutls_pkcs7_verify(
                self._c_object,
                tl._c_object,
                byref(vdata),
                0,  # do we care about vdata?
                idx,
                byref(data),
                flags,
            )

    def export(self, format=GNUTLS_X509_FMT_PEM):
        size = c_size_t(4096)
        pemdata = create_string_buffer(size.value)
        try:
            gnutls_pkcs7_export(
                self._c_object, format, cast(pemdata, c_void_p), byref(size)
            )
        except MemoryError:
            pemdata = create_string_buffer(size.value)
            gnutls_pkcs7_export(
                self._c_object, format, cast(pemdata, c_void_p), byref(size)
            )
        return pemdata.value


class PrivateKey(object):
    KEY_TYPE_NONE = 0
    KEY_TYPE_RSA = 1
    KEY_TYPE_DSA = 2
    KEY_TYPE_EC = 3

    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        return instance

    def __init__(self, pk=None, uri=None, keytype=KEY_TYPE_NONE):
        self.__deinit = gnutls_privkey_deinit
        self._c_object = gnutls_privkey_t()
        if pk is None:
            gnutls_privkey_init(byref(self._c_object))
        elif isinstance(pk, PrivateKey):
            self.__deinit = None
            self._c_object = pk._c_object
            uri = pk.uri
        else:
            raise TypeError("pk must be either None or PrivateKey")
        self.pk = pk
        self.uri = uri
        self.keytype = keytype
        self.srk_password = None
        self.key_password = None

    def __get__(self, obj, type_=None):
        return self._c_object

    def __set__(self, obj, value):
        raise AttributeError("Read-only attribute")

    def __del__(self):
        if self.__deinit:
            self.__deinit(self._c_object)

    def is_pkcs11(self):
        return self.uri is not None and (
            self.uri.startswith("tpmkey:") or self.uri.startswith("pkcs11:")
        )

    def get_uri(self):
        return self.uri

    def import_x509(self, x509_privkey, flags=0):
        gnutls_privkey_import_x509(self._c_object, x509_privkey._c_object, flags)

    @staticmethod
    def upcast(algo, pk):
        pk.keytype = PrivateKey.pk_algorithm_to_keytype(algo)
        if pk.keytype == PrivateKey.KEY_TYPE_RSA:
            return RSAPrivateKey(pk)
        if pk.keytype == PrivateKey.KEY_TYPE_DSA:
            return DSAPrivateKey(pk)

        return pk

    @staticmethod
    def generate(algo=GNUTLS_PK_RSA, bits=2048, flags=0):
        pk = PrivateKey()
        gnutls_privkey_generate(pk._c_object, algo, bits, flags)
        return pk.upcast(algo, pk)

    @classmethod
    def pk_algorithm_to_keytype(cls, algo):
        if algo in [GNUTLS_PK_RSA, GNUTLS_PK_RSA_PSS]:
            return PrivateKey.KEY_TYPE_RSA
        if algo in [GNUTLS_PK_DSA]:
            return PrivateKey.KEY_TYPE_DSA
        if algo in [GNUTLS_PK_ECDSA, GNUTLS_PK_ECDH_X25519, GNUTLS_PK_EDDSA_ED25519]:
            return PrivateKey.KEY_TYPE_EC
        raise ValueError("Unknown pk_algorithm %d to convert to key type" % algo)

    @staticmethod
    def import_uri(uri, flags=0, srk_password=None, key_password=None):
        pk = PrivateKey()
        pk.uri = uri.encode()
        pk.srk_password = srk_password
        pk.key_password = key_password

        if not srk_password and not key_password:
            gnutls_privkey_import_url(pk._c_object, uri.encode(), flags)
        else:
            gnutls_privkey_import_tpm_url(
                pk._c_object,
                uri.encode(),
                srk_password.encode(),
                key_password.encode(),
                flags,
            )

        algo = gnutls_privkey_get_pk_algorithm(pk._c_object, None)
        return pk.upcast(algo, pk)

    def sign_data(self, hash_algo, flags, buf):
        data = gnutls_datum_t(buf)
        _signature = gnutls_datum_t()
        gnutls_privkey_sign_data(
            self._c_object, hash_algo, flags, byref(data), byref(_signature)
        )
        return _signature.get_string_and_free()

    def sign_hash(self, hash_algo, flags, buf):
        hash_data = gnutls_datum_t(buf)
        _signature = gnutls_datum_t()
        gnutls_privkey_sign_hash(
            self._c_object, hash_algo, flags, byref(hash_data), byref(_signature)
        )
        return _signature.get_string_and_free()

    def decrypt_data(self, flags, ciphertext):
        plaintext = gnutls_datum_t()
        gnutls_privkey_decrypt_data(
            self._c_object, flags, gnutls_datum_t(ciphertext), plaintext
        )
        return plaintext.get_string_and_free()


class RSAPrivateKey(PrivateKey):
    def __init__(self, pk):
        super(RSAPrivateKey, self).__init__(pk=pk)
        self.srk_password = pk.srk_password

    def get_public_key(self):
        if self.uri:
            return PublicKey.import_uri(self.uri, 0, self.srk_password)
        m = gnutls_datum_t()
        e = gnutls_datum_t()
        gnutls_privkey_export_rsa_raw(
            self._c_object, m, e, None, None, None, None, None, None
        )
        return RSAPublicKey.import_rsa_raw(
            m.get_string_and_free(), e.get_string_and_free()
        )


class DSAPrivateKey(PrivateKey):
    def __init__(self, pk):
        super(DSAPrivateKey, self).__init__(pk=pk)

    def get_public_key(self):
        if self.uri:
            return PublicKey.import_uri(self.uri, 0, self.srk_password)
        p = gnutls_datum_t()
        q = gnutls_datum_t()
        g = gnutls_datum_t()
        y = gnutls_datum_t()
        gnutls_privkey_export_dsa_raw(self._c_object, p, q, g, y, None)
        return DSAPublicKey.import_dsa_raw(
            p.get_string_and_free(),
            q.get_string_and_free(),
            g.get_string_and_free(),
            y.get_string_and_free(),
        )

    @staticmethod
    def generate(algo=GNUTLS_PK_DSA, bits=2048, flags=0):
        return PrivateKey.generate(algo=algo, bits=bits, flags=flags)


class PublicKey(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        return instance

    def __init__(self, pubkey=None):
        self.__deinit = gnutls_pubkey_deinit
        self._c_object = gnutls_pubkey_t()
        if pubkey is None:
            gnutls_pubkey_init(byref(self._c_object))
        elif isinstance(pubkey, PublicKey):
            self.__deinit = None
            self._c_object = pubkey._c_object
        else:
            raise TypeError("pk must be either None or PublicKey")
        self.pubkey = pubkey

    def __get__(self, obj, type_=None):
        return self._c_object

    def __set__(self, obj, value):
        raise AttributeError("Read-only attribute")

    def __del__(self):
        if self.__deinit:
            self.__deinit(self._c_object)

    def import_x509(self, x509_cert, flags=0):
        gnutls_pubkey_import_x509(self._c_object, x509_cert._c_object, flags)

    def get_preferred_hash_algorithm(self):
        algo = gnutls_digest_algorithm_t()
        mand = c_uint()
        gnutls_pubkey_get_preferred_hash_algorithm(
            self._c_object, algo, mand
        )  # TODO: do something with mand?
        return algo

    @staticmethod
    def upcast(algo, pubkey):
        keytype = PrivateKey.pk_algorithm_to_keytype(algo)
        if keytype == PrivateKey.KEY_TYPE_RSA:
            return RSAPublicKey(pubkey)
        if keytype == PrivateKey.KEY_TYPE_DSA:
            return DSAPublicKey(pubkey)
        return pubkey

    @staticmethod
    def import_uri(uri, flags=0, srk_password=None):
        pubkey = PublicKey()
        if not srk_password:
            gnutls_pubkey_import_url(pubkey._c_object, uri, flags)
        else:
            gnutls_pubkey_import_tpm_url(pubkey._c_object, uri, srk_password, flags)
        algo = gnutls_pubkey_get_pk_algorithm(pubkey._c_object, None)
        return pubkey.upcast(algo, pubkey)

    def verify_data2(self, sign_algo, flags, buf, signature):
        gnutls_pubkey_verify_data2(
            self._c_object,
            sign_algo,
            flags,
            gnutls_datum_t(buf),
            gnutls_datum_t(signature),
        )

    def verify_hash2(self, sign_algo, flags, hashbuf, signature):
        gnutls_pubkey_verify_hash2(
            self._c_object,
            sign_algo,
            flags,
            gnutls_datum_t(hashbuf),
            gnutls_datum_t(signature),
        )

    def encrypt_data(self, flags, plaintext):
        ciphertext = gnutls_datum_t()
        gnutls_pubkey_encrypt_data(
            self._c_object, flags, gnutls_datum_t(plaintext), ciphertext
        )
        return ciphertext.get_string_and_free()


class RSAPublicKey(PublicKey):
    def __init__(self, pubkey):
        super(RSAPublicKey, self).__init__(pubkey=pubkey)

    @staticmethod
    def import_rsa_raw(m, e):
        pubkey = PublicKey()
        gnutls_pubkey_import_rsa_raw(
            pubkey._c_object, gnutls_datum_t(m), gnutls_datum_t(e)
        )
        return RSAPublicKey(pubkey=pubkey)

    def export_rsa_raw(self):
        m = gnutls_datum_t()
        e = gnutls_datum_t()
        gnutls_pubkey_export_rsa_raw(self._c_object, m, e)
        return m.get_string_and_free(), e.get_string_and_free()


class DSAPublicKey(PublicKey):
    def __init__(self, pubkey):
        super(DSAPublicKey, self).__init__(pubkey=pubkey)

    @staticmethod
    def import_dsa_raw(p, q, g, y):
        pubkey = PublicKey()
        gnutls_pubkey_import_dsa_raw(
            pubkey._c_object,
            gnutls_datum_t(p),
            gnutls_datum_t(q),
            gnutls_datum_t(g),
            gnutls_datum_t(y),
        )
        return DSAPublicKey(pubkey=pubkey)

    def export_dsa_raw(self):
        p = gnutls_datum_t()
        q = gnutls_datum_t()
        g = gnutls_datum_t()
        y = gnutls_datum_t()
        gnutls_pubkey_export_dsa_raw(self._c_object, p, q, g, y)
        return (
            p.get_string_and_free(),
            q.get_string_and_free(),
            g.get_string_and_free(),
            y.get_string_and_free(),
        )


class X509Certificate(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_crt_deinit
        instance._c_object = gnutls_x509_crt_t()
        instance._alternative_names = None
        return instance

    def __init__(self, buf, format=GNUTLS_X509_FMT_PEM):
        gnutls_x509_crt_init(byref(self._c_object))
        data = gnutls_datum_t(buf)
        gnutls_x509_crt_import(self._c_object, byref(data), format)

    def __del__(self):
        self.__deinit(self._c_object)

    @property
    def subject(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        try:
            gnutls_x509_crt_get_dn(self._c_object, dname, byref(size))
        except MemoryError:
            dname = create_string_buffer(size.value)
            gnutls_x509_crt_get_dn(self._c_object, dname, byref(size))
        return X509Name(dname.value.decode())

    @property
    def issuer(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        try:
            gnutls_x509_crt_get_issuer_dn(self._c_object, dname, byref(size))
        except MemoryError:
            dname = create_string_buffer(size.value)
            gnutls_x509_crt_get_issuer_dn(self._c_object, dname, byref(size))
        return X509Name(dname.value.decode())

    @property
    def alternative_names(self):
        if self._alternative_names is not None:
            return self._alternative_names
        names = {}
        size = c_size_t(256)
        alt_name = create_string_buffer(size.value)
        for i in range(65536):
            try:
                name_type = gnutls_x509_crt_get_subject_alt_name(
                    self._c_object, i, alt_name, byref(size), None
                )
            except RequestedDataNotAvailable:
                break
            except MemoryError:
                alt_name = create_string_buffer(size.value)
                name_type = gnutls_x509_crt_get_subject_alt_name(
                    self._c_object, i, alt_name, byref(size), None
                )
            names.setdefault(name_type, []).append(alt_name.value)
        self._alternative_names = AlternativeNames(names)
        return self._alternative_names

    @property
    def serial_number(self):

        size = c_size_t(1)
        try:
            gnutls_x509_crt_get_serial(self._c_object, None, byref(size))
        except MemoryError:
            pass
        serial = create_string_buffer(size.value)
        gnutls_x509_crt_get_serial(
            self._c_object, cast(byref(serial), c_void_p), byref(size)
        )
        return serial.value.hex().lstrip("0")

    @property
    def activation_time(self):
        return gnutls_x509_crt_get_activation_time(self._c_object)

    @property
    def expiration_time(self):
        return gnutls_x509_crt_get_expiration_time(self._c_object)

    @property
    def version(self):
        return gnutls_x509_crt_get_version(self._c_object)

    def has_issuer(self, issuer):
        """Return True if the certificate was issued by the given issuer, False otherwise."""
        if not isinstance(issuer, X509Certificate):
            raise TypeError("issuer must be an X509Certificate object")
        return bool(gnutls_x509_crt_check_issuer(self._c_object, issuer._c_object))

    def has_hostname(self, hostname):
        """Return True if the hostname matches the DNSName/IPAddress subject alternative name extension
           of this certificate, False otherwise."""
        # For details see http://www.ietf.org/rfc/rfc2459.txt, section 4.2.1.7 Subject Alternative Name
        return bool(gnutls_x509_crt_check_hostname(self._c_object, hostname))

    def check_issuer(self, issuer):
        """Raise CertificateError if certificate was not issued by the given issuer"""
        if not self.has_issuer(issuer):
            raise CertificateError("certificate issuer doesn't match")

    def check_hostname(self, hostname):
        """Raise CertificateError if the certificate DNSName/IPAddress subject alternative name extension
           doesn't match the given hostname"""
        if not self.has_hostname(hostname):
            raise CertificateError("certificate doesn't match hostname")

    def export(self, format=GNUTLS_X509_FMT_PEM):
        size = c_size_t(4096)
        pemdata = create_string_buffer(size.value)
        try:
            gnutls_x509_crt_export(
                self._c_object, format, cast(pemdata, c_void_p), byref(size)
            )
        except MemoryError:
            pemdata = create_string_buffer(size.value)
            gnutls_x509_crt_export(
                self._c_object, format, cast(pemdata, c_void_p), byref(size)
            )
        return pemdata.raw[: size.value]


class X509PrivateKey(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_privkey_deinit
        instance._c_object = gnutls_x509_privkey_t()
        return instance

    def __init__(self, buf, format=GNUTLS_X509_FMT_PEM):
        gnutls_x509_privkey_init(byref(self._c_object))
        data = gnutls_datum_t(buf)
        gnutls_x509_privkey_import(self._c_object, byref(data), format)

    def __del__(self):
        self.__deinit(self._c_object)

    def export(self, format=GNUTLS_X509_FMT_PEM):
        size = c_size_t(4096)
        pemdata = create_string_buffer(size.value)
        try:
            gnutls_x509_privkey_export(
                self._c_object, format, cast(pemdata, c_void_p), byref(size)
            )
        except MemoryError:
            pemdata = create_string_buffer(size.value)
            gnutls_x509_privkey_export(
                self._c_object, format, cast(pemdata, c_void_p), byref(size)
            )
        return pemdata.raw[: size.value]


class X509Identity(object):
    """A X509 identity represents a X509 certificate and private key pair"""

    __slots__ = ("cert", "key")

    def __init__(self, cert, key):
        self.cert = cert
        self.key = key

    def __setattr__(self, name, value):
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("can't set attribute")
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        if name in self.__slots__:
            raise AttributeError("can't delete attribute")
        object.__delattr__(self, name)


class X509CRL(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_crl_deinit
        instance._c_object = gnutls_x509_crl_t()
        return instance

    def __init__(self, buf, format=GNUTLS_X509_FMT_PEM):
        gnutls_x509_crl_init(byref(self._c_object))
        data = gnutls_datum_t(buf)
        gnutls_x509_crl_import(self._c_object, byref(data), format)

    def __del__(self):
        self.__deinit(self._c_object)

    @property
    def count(self):
        return gnutls_x509_crl_get_crt_count(self._c_object)

    @property
    def version(self):
        return gnutls_x509_crl_get_version(self._c_object)

    @property
    def issuer(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        try:
            gnutls_x509_crl_get_issuer_dn(self._c_object, dname, byref(size))
        except MemoryError:
            dname = create_string_buffer(size.value)
            gnutls_x509_crl_get_issuer_dn(self._c_object, dname, byref(size))
        return X509Name(dname.value.decode())

    def is_revoked(self, cert):
        """Return True if certificate is revoked, False otherwise"""
        return bool(
            gnutls_x509_crt_check_revocation(cert._c_object, byref(self._c_object), 1)
        )

    def check_revocation(self, cert, cert_name="certificate"):
        """Raise CertificateRevokedError if the given certificate is revoked"""
        if self.is_revoked(cert):
            raise CertificateRevokedError("%s was revoked" % cert_name)

    def export(self, format=GNUTLS_X509_FMT_PEM):
        size = c_size_t(4096)
        pemdata = create_string_buffer(size.value)
        try:
            gnutls_x509_crl_export(
                self._c_object, format, cast(pemdata, c_void_p), byref(size)
            )
        except MemoryError:
            pemdata = create_string_buffer(size.value)
            gnutls_x509_crl_export(
                self._c_object, format, cast(pemdata, c_void_p), byref(size)
            )
        return pemdata.raw[: size.value]


class DHParams(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_dh_params_deinit
        instance._c_object = gnutls_dh_params_t()
        return instance

    def __init__(self, bits=1024):
        gnutls_dh_params_init(byref(self._c_object))
        gnutls_dh_params_generate2(self._c_object, bits)

    def __get__(self, obj, type_=None):
        return self._c_object

    def __set__(self, obj, value):
        raise AttributeError("Read-only attribute")

    def __del__(self):
        self.__deinit(self._c_object)


class Cipher(CWrapper):
    ctype = gnutls_cipher_hd_t

    def __init__(self, algo, key, iv):
        super(Cipher, self).__init__()
        gnutls_cipher_init(
            byref(self._c_object), algo, gnutls_datum_t(key), gnutls_datum_t(iv)
        )
        self.algorithm = algo
        self.deinit = gnutls_cipher_deinit

    def set_iv(self, iv):
        gnutls_cipher_set_iv(self._c_object, c_char_p(iv), c_size_t(len(iv)))

    def add_auth(self, auth):
        gnutls_cipher_add_auth(self._c_object, c_char_p(auth), c_size_t(len(auth)))

    def decrypt(self, cipher_text):
        pt = create_string_buffer(len(cipher_text))
        gnutls_cipher_decrypt2(
            self._c_object,
            c_char_p(cipher_text),
            c_size_t(cipher_text),
            pt,
            c_size_t(len(pt)),
        )
        return pt.value

    def encrypt(self, plain_text):
        bs = gnutls_cipher_get_block_size(self.algorithm)
        ct = create_string_buffer(int(math.ceil(len(plain_text) / float(bs)) * bs))
        gnutls_cipher_encrypt2(
            self._c_object,
            c_char_p(plain_text),
            c_size_t(plain_text),
            ct,
            c_size_t(len(ct)),
        )
        return ct.value

    def cipher_tag(self, tag_size):
        assert tag_size > 0
        tag = create_string_buffer(tag_size)
        gnutls_cipher_tag(self._c_object, tag, c_size_t(tag_size))
        return tag.value


class AEADCipher(CWrapper):
    ctype = gnutls_aead_cipher_hd_t

    def __init__(self, algo, key):
        super(AEADCipher, self).__init__()
        data = gnutls_datum_t(key)
        gnutls_aead_cipher_init(byref(self._c_object), algo, byref(data))
        self.deinit = gnutls_aead_cipher_deinit

    def encrypt(self, nonce, auth, tag_size, plain_text):
        csize = c_size_t(tag_size + len(plain_text) + 16)
        ct = create_string_buffer(csize.value)

        try:
            gnutls_aead_cipher_encrypt(
                self._c_object,
                c_char_p(nonce),
                c_size_t(len(nonce)),
                c_char_p(auth),
                c_size_t(len(auth)),
                c_size_t(tag_size),
                c_char_p(plain_text),
                c_size_t(len(plain_text)),
                cast(ct, c_void_p),
                byref(csize),
            )
        except MemoryError:
            ct = create_string_buffer(csize.value)
            gnutls_aead_cipher_encrypt(
                self._c_object,
                c_char_p(nonce),
                c_size_t(len(nonce)),
                c_char_p(auth),
                c_size_t(len(auth)),
                c_size_t(tag_size),
                c_char_p(plain_text),
                c_size_t(len(plain_text)),
                cast(ct, c_void_p),
                byref(csize),
            )

        return ct.value

    def decrypt(self, nonce, auth, tag_size, cipher_text):
        psize = c_size_t(tag_size + len(cipher_text) + 16)
        pt = create_string_buffer(psize.value)

        try:
            gnutls_aead_cipher_decrypt(
                self._c_object,
                c_char_p(nonce),
                c_size_t(len(nonce)),
                c_char_p(auth),
                c_size_t(len(auth)),
                c_size_t(tag_size),
                c_char_p(cipher_text),
                c_size_t(len(cipher_text)),
                cast(pt, c_void_p),
                byref(psize),
            )
        except MemoryError:
            pt = create_string_buffer(psize.value)
            gnutls_aead_cipher_decrypt(
                self._c_object,
                c_char_p(nonce),
                c_size_t(len(nonce)),
                c_char_p(auth),
                c_size_t(len(auth)),
                c_size_t(tag_size),
                c_char_p(cipher_text),
                c_size_t(len(cipher_text)),
                cast(pt, c_void_p),
                byref(psize),
            )

        return pt.value
