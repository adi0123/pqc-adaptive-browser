# ============================================================
# TLS RECORD TYPES
# ============================================================

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT              = 21
CONTENT_HANDSHAKE          = 22
CONTENT_APPLICATION_DATA   = 23


# ============================================================
# HANDSHAKE TYPES
# ============================================================

HANDSHAKE_CLIENT_HELLO          = 1
HANDSHAKE_SERVER_HELLO          = 2
HANDSHAKE_ENCRYPTED_EXTENSIONS  = 8
HANDSHAKE_CERTIFICATE           = 11

# ============================================================
# TLS VERSIONS
# ============================================================

TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304


# ============================================================
# EXTENSIONS
# ============================================================

EXT_SERVER_NAME             = 0x0000
EXT_SUPPORTED_GROUPS        = 0x000A
EXT_SIGNATURE_ALGORITHMS    = 0x000D
EXT_ALPN                    = 0x0010
EXT_SUPPORTED_VERSIONS      = 0x002B
EXT_PSK_KEY_EXCHANGE_MODES  = 0x002D
EXT_KEY_SHARE               = 0x0033


# ============================================================
# SUPPORTED GROUPS
# ============================================================

GROUP_X25519      = 0x001D
GROUP_SECP256R1   = 0x0017
GROUP_SECP384R1   = 0x0018
GROUP_SECP521R1   = 0x0019


# ============================================================
# OUR PQC GROUP
# ============================================================

GROUP_HYBRID = 0x11EC

# =====================================================
# Supported Groups
# =====================================================

SUPPORTED_GROUPS = {

    # Classical Curves
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",

    0x001D: "X25519",
    0x001E: "X448",

    # PQC Hybrid Groups
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP256r1MLKEM768",
    0x11EE: "SecP384r1MLKEM1024",
}


def get_supported_group_name(group_id: int):

    return SUPPORTED_GROUPS.get(
        group_id,
        f"Unknown (0x{group_id:04X})"
    )
# =====================================================
# Signature Algorithms
# =====================================================

SIGNATURE_ALGORITHMS = {

    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",

    0x0603: "ecdsa_secp521r1_sha512",

    0x0804: "rsa_pss_rsae_sha256",

    0x0805: "rsa_pss_rsae_sha384",

    0x0806: "rsa_pss_rsae_sha512",

    0x0807: "ed25519",

    0x0808: "ed448",

    0x0401: "rsa_pkcs1_sha256",

    0x0501: "rsa_pkcs1_sha384",

    0x0601: "rsa_pkcs1_sha512",
}
def get_signature_algorithm_name(alg):

    return SIGNATURE_ALGORITHMS.get(

        alg,

        f"Unknown (0x{alg:04X})"

    )
# =====================================================
# PSK Key Exchange Modes
# =====================================================

PSK_KE = 0
PSK_DHE_KE = 1

PSK_KEY_EXCHANGE_MODES = {

    PSK_KE: "psk_ke",

    PSK_DHE_KE: "psk_dhe_ke",

}


def get_psk_key_exchange_mode_name(mode):

    return PSK_KEY_EXCHANGE_MODES.get(

        mode,

        f"Unknown ({mode})"

    )
CONTENT_TYPES = {

    CONTENT_CHANGE_CIPHER_SPEC: "Change Cipher Spec",

    CONTENT_ALERT: "Alert",

    CONTENT_HANDSHAKE: "Handshake",

    CONTENT_APPLICATION_DATA: "Application Data",

}
def get_content_type_name(content_type):

    return CONTENT_TYPES.get(

        content_type,

        f"Unknown ({content_type})"

    )
HANDSHAKE_TYPES = {

    HANDSHAKE_CLIENT_HELLO: "ClientHello",

    HANDSHAKE_SERVER_HELLO: "ServerHello",

    HANDSHAKE_ENCRYPTED_EXTENSIONS: "EncryptedExtensions",

    HANDSHAKE_CERTIFICATE: "Certificate",

}

def get_handshake_name(handshake_type):

    return HANDSHAKE_TYPES.get(

        handshake_type,

        f"Unknown ({handshake_type})"

    )
TLS_VERSIONS = {

    TLS10: "TLS 1.0",

    TLS11: "TLS 1.1",

    TLS12: "TLS 1.2",

    TLS13: "TLS 1.3",

}

def get_tls_version_name(version):

    return TLS_VERSIONS.get(

        version,

        f"Unknown (0x{version:04X})"

    )

