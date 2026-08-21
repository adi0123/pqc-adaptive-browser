from dataclasses import dataclass, field


# ==========================================================
# TLS RECORD
# ==========================================================

@dataclass
class TLSRecord:

    content_type: int
    version: int
    length: int

    handshake: object = None


# ==========================================================
# HANDSHAKE
# ==========================================================

@dataclass
class Handshake:

    handshake_type: int
    length: int

    body: object = None


# ==========================================================
# CLIENT HELLO
# ==========================================================

@dataclass
class ClientHello:

    legacy_version: int

    random: bytes

    session_id: bytes
    
    cipher_suites: list = field(default_factory=list)

    compression_methods: list = field(default_factory=list)

    extensions_length: int = 0

    extensions: list = field(default_factory=list)
    
# ==========================================================
# TLS EXTENSION
# ==========================================================
@dataclass
class TLSExtension:

    extension_type: int

    length: int

    data: bytes

    parsed: object = None
    
# ==========================================================
# SUPPORTED VERSIONS EXTENSION
# ==========================================================

@dataclass
class SupportedVersions:

    versions: list = field(default_factory=list)
    
# ==========================================================
# SUPPORTED GROUPS EXTENSION
# ==========================================================

@dataclass
class SupportedGroups:

    groups: list = field(default_factory=list)
    
# ==========================================================
# KEY SHARE ENTRY
# ==========================================================

@dataclass
class KeyShareEntry:

    group: int

    key_exchange: bytes


# ==========================================================
# KEY SHARE EXTENSION
# ==========================================================

@dataclass
class KeyShare:

    entries: list = field(default_factory=list)
    
# ==========================================================
# SIGNATURE ALGORITHMS EXTENSION
# ==========================================================

@dataclass
class SignatureAlgorithms:

    algorithms: list = field(default_factory=list)
    
# ==========================================================
# ALPN EXTENSION
# ==========================================================

@dataclass
class ALPN:

    protocols: list = field(default_factory=list)
# ==========================================================
# SERVER NAME EXTENSION (SNI)
# ==========================================================

@dataclass
class ServerName:

    hostname: str
    
# ==========================================================
# PSK KEY EXCHANGE MODES EXTENSION
# ==========================================================

@dataclass
class PSKKeyExchangeModes:

    modes: list = field(default_factory=list)
    
@dataclass
class ServerHello:

    legacy_version: int

    random: bytes

    session_id: bytes

    cipher_suite: int

    compression_method: int

    extensions_length: int

    extensions: list = field(default_factory=list)
    
# ==========================================================
# ENCRYPTED EXTENSIONS
# ==========================================================

@dataclass
class EncryptedExtensions:

    extensions_length: int

    extensions: list = field(default_factory=list)

# ==========================================================
# CERTIFICATE ENTRY
# ==========================================================

@dataclass
class CertificateEntry:

    certificate: bytes

    extensions: list = field(default_factory=list)


# ==========================================================
# CERTIFICATE
# ==========================================================

@dataclass
class Certificate:

    context: bytes

    entries: list = field(default_factory=list)
