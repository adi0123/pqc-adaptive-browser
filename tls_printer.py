from tls_constants import *
from tls_structures import (
    ClientHello,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateEntry,
    SupportedVersions,
    SupportedGroups,
    KeyShare,
    SignatureAlgorithms,
    ALPN,
    ServerName,
    PSKKeyExchangeModes,
)
def print_record(record):

    print("=" * 60)
    print("TLS RECORD")
    print("=" * 60)

    name = get_content_type_name(
        record.content_type
    )

    print(f"Content Type : {name}")
    name = get_tls_version_name(
        record.version
    )

    print(f"Version : {name}")
    print(f"Length       : {record.length}")

    if record.handshake:

        print()

        print_handshake(record.handshake)
        
def print_handshake(handshake):

    print("=" * 60)
    print("HANDSHAKE")
    print("=" * 60)

    name = get_handshake_name(
        handshake.handshake_type
    )

    print(f"Type : {name}")
    print(f"Length : {handshake.length}")

    if handshake.body:

        print()

        if isinstance(handshake.body, ClientHello):

            print_client_hello(handshake.body)

        elif isinstance(handshake.body, ServerHello):

            print_server_hello(handshake.body)
            
        elif isinstance(handshake.body, EncryptedExtensions):

            print_encrypted_extensions(handshake.body)
            
        elif isinstance(handshake.body, Certificate):

            print_certificate(handshake.body)
        
def print_client_hello(ch):

    print("=" * 60)
    print("CLIENT HELLO")
    print("=" * 60)

    print(f"Legacy Version : 0x{ch.legacy_version:04X}")

    print(f"Random         : {ch.random.hex()}")

    print(f"Session ID     : {ch.session_id.hex()}")

    print()

    print(f"Cipher Suites ({len(ch.cipher_suites)})")

    for suite in ch.cipher_suites:

        print(f"   0x{suite:04X}")

    print()

    print(f"Compression Methods ({len(ch.compression_methods)})")

    for method in ch.compression_methods:

        print(f"   {method}")

    print()

    print_extensions(ch.extensions)
def print_server_hello(sh):

    print("=" * 60)
    print("SERVER HELLO")
    print("=" * 60)

    print(f"Legacy Version : 0x{sh.legacy_version:04X}")

    print(f"Random         : {sh.random.hex()}")

    print(f"Session ID     : {sh.session_id.hex()}")

    print()

    print(f"Cipher Suite   : 0x{sh.cipher_suite:04X}")

    print(f"Compression    : {sh.compression_method}")

    print()

    print_extensions(sh.extensions)
  
def print_encrypted_extensions(ee):

    print("=" * 60)
    print("ENCRYPTED EXTENSIONS")
    print("=" * 60)

    print(
        f"Extensions Length : {ee.extensions_length}"
    )

    print()

    print_extensions(
        ee.extensions
    )  
  
def print_extensions(extensions):

    print("=" * 60)
    print("EXTENSIONS")
    print("=" * 60)

    for ext in extensions:

        print()

        print(f"Extension : 0x{ext.extension_type:04X}")

        if ext.parsed is None:

            continue

        if isinstance(ext.parsed, SupportedVersions):

            print_supported_versions(ext.parsed)

        elif isinstance(ext.parsed, SupportedGroups):

            print_supported_groups(ext.parsed)

        elif isinstance(ext.parsed, KeyShare):

            print_key_share(ext.parsed)

        elif isinstance(ext.parsed, SignatureAlgorithms):

            print_signature_algorithms(ext.parsed)

        elif isinstance(ext.parsed, ALPN):

            print_alpn(ext.parsed)

        elif isinstance(ext.parsed, ServerName):

            print_server_name(ext.parsed)

        elif isinstance(ext.parsed, PSKKeyExchangeModes):

            print_psk_modes(ext.parsed)

def print_certificate(cert):

    print("=" * 60)
    print("CERTIFICATE")
    print("=" * 60)

    print(
        f"Certificate Entries : {len(cert.entries)}"
    )

    print()

    for index, entry in enumerate(cert.entries):

        print(
            f"Certificate #{index + 1}"
        )

        print(
            f"DER Size : {len(entry.certificate)} bytes"
        )

        print()

        if entry.extensions:

            print_extensions(
                entry.extensions
            )
            
def print_supported_versions(data):

    print("Supported Versions:")

    for version in data.versions:

        print(f"   0x{version:04X}")

def print_supported_groups(data):

    print("Supported Groups:")

    for group in data.groups:

        name = get_supported_group_name(group)

        print(f"   {name} (0x{group:04X})")
        
def print_key_share(data):

    print("Key Shares:")

    for entry in data.entries:

        name = get_supported_group_name(entry.group)

        print(f"   Group : {name}")

        print(f"   Key Length : {len(entry.key_exchange)} bytes")

        print()
        
def print_signature_algorithms(data):

    print("Signature Algorithms:")

    for alg in data.algorithms:

        name = get_signature_algorithm_name(alg)

        print(f"   {name}")
        
def print_alpn(data):

    print("ALPN Protocols:")

    for protocol in data.protocols:

        print(f"   {protocol}")
        
def print_server_name(data):

    print("Server Name:")

    print(f"   {data.hostname}")
    
def print_psk_modes(data):

    print("PSK Key Exchange Modes:")

    for mode in data.modes:

        name = get_psk_key_exchange_mode_name(mode)

        print(f"   {name}")
