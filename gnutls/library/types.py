import sys
from ctypes import (
    addressof,
    cast,
    c_char_p,
    CFUNCTYPE,
    c_int,
    c_long,
    c_size_t,
    c_ubyte,
    c_uint,
    c_ulong,
    c_void_p,
    POINTER,
    string_at,
    Structure,
    Union,
)

# Type aliases
#

time_t = c_long
size_t = c_size_t
ssize_t = c_long

gnutls_openpgp_keyid_t = c_ubyte * 8
gnutls_pkcs7_attrs_t = c_void_p
gnutls_pkcs7_t = c_void_p
gnutls_privkey_t = c_void_p
gnutls_pubkey_t = c_void_p
gnutls_transport_ptr_t = c_void_p
gnutls_typed_vdata_st = c_void_p
gnutls_x509_dn_t = c_void_p
gnutls_x509_trust_list_t = c_void_p


# Enumerations
#

gnutls_alert_description_t = c_int  # enum
gnutls_alert_level_t = c_int  # enum
gnutls_certificate_import_flags = c_int  # enum
gnutls_certificate_print_formats = c_int  # enum
gnutls_certificate_request_t = c_int  # enum
gnutls_certificate_status_t = c_int  # enum
gnutls_certificate_type_t = c_int  # enum
gnutls_certificate_verify_flags = c_int  # enum
gnutls_cipher_algorithm_t = c_int  # enum
gnutls_close_request_t = c_int  # enum
gnutls_compression_method_t = c_int  # enum
gnutls_connection_end_t = c_int  # enum
gnutls_credentials_type_t = c_int  # enum
gnutls_digest_algorithm_t = c_int  # enum
gnutls_handshake_description_t = c_int  # enum
gnutls_ia_apptype_t = c_int  # enum
gnutls_kx_algorithm_t = c_int  # enum
gnutls_mac_algorithm_t = c_int  # enum
gnutls_openpgp_crt_fmt = c_int  # enum
gnutls_openpgp_crt_status_t = c_int  # enum
gnutls_params_type_t = c_int  # enum
gnutls_pk_algorithm_t = c_int  # enum
gnutls_pkcs_encrypt_flags_t = c_int  # enum
gnutls_privkey_type_t = c_int  # enum
gnutls_protocol_t = c_int  # enum
gnutls_psk_key_flags = c_int  # enum
gnutls_server_name_type_t = c_int  # enum
gnutls_sign_algorithm_t = c_int  # enum
gnutls_supplemental_data_format_type_t = c_int  # enum
gnutls_x509_crt_fmt_t = c_int  # enum
gnutls_x509_subject_alt_name_t = c_int  # enum

gnutls_certificate_print_formats_t = gnutls_certificate_print_formats
gnutls_openpgp_crt_fmt_t = gnutls_openpgp_crt_fmt


# Unions, structures and pointers to structure types
#


class gnutls_session_int(Structure):
    _fields_ = []


gnutls_session_t = POINTER(gnutls_session_int)


class gnutls_ia_server_credentials_st(Structure):
    _fields_ = []


gnutls_ia_server_credentials_t = POINTER(gnutls_ia_server_credentials_st)


class gnutls_ia_client_credentials_st(Structure):
    _fields_ = []


gnutls_ia_client_credentials_t = POINTER(gnutls_ia_client_credentials_st)


class gnutls_dh_params_int(Structure):
    _fields_ = []


gnutls_dh_params_t = POINTER(gnutls_dh_params_int)


class gnutls_x509_privkey_int(Structure):
    _fields_ = []


gnutls_x509_privkey_t = POINTER(gnutls_x509_privkey_int)
gnutls_rsa_params_t = POINTER(gnutls_x509_privkey_int)


class params(Union):
    _fields_ = [("dh", gnutls_dh_params_t), ("rsa_export", gnutls_rsa_params_t)]


class gnutls_pkcs11_privkey_st(Structure):
    _fields_ = []


gnutls_pkcs11_privkey_t = POINTER(gnutls_pkcs11_privkey_st)


class gnutls_priority_st(Structure):
    _fields_ = []


gnutls_priority_t = POINTER(gnutls_priority_st)


class gnutls_datum_t(Structure):
    _fields_ = [("data", POINTER(c_ubyte)), ("size", c_uint)]

    def __init__(self, buf=None):
        if buf:
            if isinstance(buf, str):
                buf = bytes(buf, 'utf-8')
            self.data = cast(c_char_p(buf), POINTER(c_ubyte))
            self.size = c_uint(len(buf))

    def get_string_and_free(self):
        res = string_at(self.data, self.size)
        gnutls_free_function(addressof(self.data))
        self.data = None
        return res


class gnutls_params_st(Structure):
    _fields_ = [("type", gnutls_params_type_t), ("params", params), ("deinit", c_int)]


class gnutls_certificate_credentials_st(Structure):
    _fields_ = []


gnutls_certificate_credentials_t = POINTER(gnutls_certificate_credentials_st)
gnutls_certificate_server_credentials = gnutls_certificate_credentials_t
gnutls_certificate_client_credentials = gnutls_certificate_credentials_t


class gnutls_anon_server_credentials_st(Structure):
    _fields_ = []


gnutls_anon_server_credentials_t = POINTER(gnutls_anon_server_credentials_st)


class gnutls_anon_client_credentials_st(Structure):
    _fields_ = []


gnutls_anon_client_credentials_t = POINTER(gnutls_anon_client_credentials_st)


class gnutls_x509_crl_int(Structure):
    _fields_ = []


gnutls_x509_crl_t = POINTER(gnutls_x509_crl_int)


class gnutls_x509_crt_int(Structure):
    _fields_ = []


gnutls_x509_crt_t = POINTER(gnutls_x509_crt_int)


class gnutls_openpgp_keyring_int(Structure):
    _fields_ = []


gnutls_openpgp_keyring_t = POINTER(gnutls_openpgp_keyring_int)


class gnutls_srp_server_credentials_st(Structure):
    _fields_ = []


gnutls_srp_server_credentials_t = POINTER(gnutls_srp_server_credentials_st)


class gnutls_srp_client_credentials_st(Structure):
    _fields_ = []


gnutls_srp_client_credentials_t = POINTER(gnutls_srp_client_credentials_st)


class gnutls_psk_server_credentials_st(Structure):
    _fields_ = []


gnutls_psk_server_credentials_t = POINTER(gnutls_psk_server_credentials_st)


class gnutls_psk_client_credentials_st(Structure):
    _fields_ = []


gnutls_psk_client_credentials_t = POINTER(gnutls_psk_client_credentials_st)


class gnutls_openpgp_crt_int(Structure):
    _fields_ = []


gnutls_openpgp_crt_t = POINTER(gnutls_openpgp_crt_int)


class gnutls_openpgp_privkey_int(Structure):
    _fields_ = []


gnutls_openpgp_privkey_t = POINTER(gnutls_openpgp_privkey_int)


class api_cipher_hd_st(Structure):
    _fields_ = []


gnutls_cipher_hd_t = POINTER(api_cipher_hd_st)


class api_aead_cipher_hd_st(Structure):
    _fields_ = []


gnutls_aead_cipher_hd_t = POINTER(api_aead_cipher_hd_st)


class gnutls_privkey_int(Structure):
    _fields_ = []


gnutls_privkey_t = POINTER(gnutls_privkey_int)


class gnutls_pubkey_int(Structure):
    _fields_ = []


gnutls_pubkey_t = POINTER(gnutls_pubkey_int)


class cert(Union):
    _fields_ = [("x509", POINTER(gnutls_x509_crt_t)), ("pgp", gnutls_openpgp_crt_t)]


class key(Union):
    _fields_ = [
        ("x509", gnutls_x509_privkey_t),
        ("pgp", gnutls_openpgp_privkey_t),
        ("pkcs11", gnutls_pkcs11_privkey_t),
    ]


class gnutls_retr2_st(Structure):
    _fields_ = [
        ("cert_type", gnutls_certificate_type_t),
        ("key_type", gnutls_privkey_type_t),
        ("cert", cert),
        ("ncerts", c_uint),
        ("key", key),
        ("deinit_all", c_uint),
    ]


class gnutls_x509_ava_st(Structure):
    _fields_ = [
        ("oid", gnutls_datum_t),
        ("value", gnutls_datum_t),
        ("value_tag", c_ulong),
    ]


class gnutls_pkcs7_int(Structure):
    _fields_ = []


gnutls_pkcs7_t = POINTER(gnutls_pkcs7_int)


class gnutls_pkcs7_signature_info_st(Structure):
    _fields_ = [
        ("algo", gnutls_sign_algorithm_t),
        ("sig", gnutls_datum_t),
        ("issuer_dn", gnutls_datum_t),
        ("signer_serial", gnutls_datum_t),
        ("issuer_keyid", gnutls_datum_t),
        ("signing_time", time_t),
        ("signed_attrs", gnutls_pkcs7_attrs_t),
        ("unsigned_attrs", gnutls_pkcs7_attrs_t),
        ("pad", c_ubyte * 64),
    ]


gnutls_pkcs7_signature_info_t = POINTER(gnutls_pkcs7_signature_info_st)


class gnutls_x509_crq_int(Structure):
    _fields_ = []


gnutls_x509_crq_t = POINTER(gnutls_x509_crq_int)


# Function type declarations
#

gnutls_alloc_function = CFUNCTYPE(c_void_p, size_t)
gnutls_calloc_function = CFUNCTYPE(c_void_p, size_t, size_t)
gnutls_certificate_retrieve_function = CFUNCTYPE(
    c_int,
    gnutls_session_t,
    POINTER(gnutls_datum_t),
    c_int,
    POINTER(gnutls_pk_algorithm_t),
    c_int,
    POINTER(gnutls_retr2_st),
)
gnutls_db_remove_func = CFUNCTYPE(c_int, c_void_p, gnutls_datum_t)
gnutls_db_retr_func = CFUNCTYPE(gnutls_datum_t, c_void_p, gnutls_datum_t)
gnutls_db_store_func = CFUNCTYPE(c_int, c_void_p, gnutls_datum_t, gnutls_datum_t)
gnutls_free_function = CFUNCTYPE(None, c_void_p)
gnutls_handshake_post_client_hello_func = CFUNCTYPE(c_int, gnutls_session_t)
gnutls_ia_avp_func = CFUNCTYPE(
    c_int,
    gnutls_session_t,
    c_void_p,
    c_char_p,
    size_t,
    POINTER(c_char_p),
    POINTER(size_t),
)
gnutls_is_secure_function = CFUNCTYPE(c_int, c_void_p)
gnutls_log_func = CFUNCTYPE(None, c_int, c_char_p)
gnutls_openpgp_recv_key_func = CFUNCTYPE(
    c_int, gnutls_session_t, POINTER(c_ubyte), c_uint, POINTER(gnutls_datum_t)
)
gnutls_oprfi_callback_func = CFUNCTYPE(
    c_int, gnutls_session_t, c_void_p, size_t, POINTER(c_ubyte), POINTER(c_ubyte)
)
gnutls_params_function = CFUNCTYPE(
    c_int, gnutls_session_t, gnutls_params_type_t, POINTER(gnutls_params_st)
)
gnutls_psk_client_credentials_function = CFUNCTYPE(
    c_int, gnutls_session_t, POINTER(c_char_p), POINTER(gnutls_datum_t)
)
gnutls_psk_server_credentials_function = CFUNCTYPE(
    c_int, gnutls_session_t, c_char_p, POINTER(gnutls_datum_t)
)
gnutls_pull_func = CFUNCTYPE(ssize_t, gnutls_transport_ptr_t, c_void_p, size_t)
gnutls_push_func = CFUNCTYPE(ssize_t, gnutls_transport_ptr_t, c_void_p, size_t)
gnutls_realloc_function = CFUNCTYPE(c_void_p, c_void_p, size_t)
gnutls_sign_func = CFUNCTYPE(
    c_int,
    gnutls_session_t,
    c_void_p,
    gnutls_certificate_type_t,
    POINTER(gnutls_datum_t),
    POINTER(gnutls_datum_t),
    POINTER(gnutls_datum_t),
)
gnutls_srp_client_credentials_function = CFUNCTYPE(
    c_int, gnutls_session_t, POINTER(c_char_p), POINTER(c_char_p)
)
gnutls_srp_server_credentials_function = CFUNCTYPE(
    c_int,
    gnutls_session_t,
    c_char_p,
    POINTER(gnutls_datum_t),
    POINTER(gnutls_datum_t),
    POINTER(gnutls_datum_t),
    POINTER(gnutls_datum_t),
)


__all__ = sorted(
    name
    for name in sys.modules[__name__].__dict__
    if name.startswith("gnutls_")
    or name in ("size_t", "ssize_t", "time_t", "cert", "key", "params")
)
