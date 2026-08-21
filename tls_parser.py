"""
TLS Parser
==========

Part 1

This parser currently supports

- TLS Record
- Handshake Header

ClientHello parsing will be implemented in Part 2.
"""

from tls_utils import BufferReader

from tls_structures import (

    TLSRecord,
    Handshake,
    ClientHello,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateEntry,
    TLSExtension,
    SupportedVersions,
    SupportedGroups,
    KeyShare,
    KeyShareEntry,
    SignatureAlgorithms,
    ALPN,
    ServerName,
    PSKKeyExchangeModes,
)

from tls_constants import *


class TLSParser:

    def __init__(self, data: bytes):

        self.reader = BufferReader(data)

    # =====================================================
    # Public API
    # =====================================================

    def parse(self):
        """
        Parse an entire TLS record.

        Returns
        -------
        TLSRecord
        """

        return self._parse_record()

    # =====================================================
    # TLS RECORD
    # =====================================================

    def _parse_record(self):

        content_type = self.reader.read_u8()

        version = self.reader.read_u16()

        length = self.reader.read_u16()

        record = TLSRecord(
            content_type=content_type,
            version=version,
            length=length
        )

        #
        # Only handshake records are parsed for now.
        #

        if content_type == CONTENT_HANDSHAKE:

            record.handshake = self._parse_handshake()

        return record

    # =====================================================
    # HANDSHAKE
    # =====================================================

    def _parse_handshake(self):

        handshake_type = self.reader.read_u8()

        handshake_length = self.reader.read_u24()

        handshake = Handshake(

            handshake_type=handshake_type,

            length=handshake_length

        )

        if handshake_type == HANDSHAKE_CLIENT_HELLO:

            handshake.body = self._parse_client_hello()

        elif handshake_type == HANDSHAKE_SERVER_HELLO:

            handshake.body = self._parse_server_hello()
            
        elif handshake_type == HANDSHAKE_ENCRYPTED_EXTENSIONS:

            handshake.body = self._parse_encrypted_extensions()
            
        elif handshake_type == HANDSHAKE_CERTIFICATE:

            handshake.body = self._parse_certificate()

        return handshake
    
    def _parse_client_hello(self):

        #
        # Legacy Version
        #

        legacy_version = self.reader.read_u16()

        #
        # Random
        #

        random = self.reader.read(32)

        #
        # Session ID
        #

        session_length = self.reader.read_u8()

        session_id = self.reader.read(session_length)

        #
        # Cipher Suites
        #

        cipher_length = self.reader.read_u16()

        cipher_suites = []

        for _ in range(cipher_length // 2):

            cipher_suites.append(

                self.reader.read_u16()

            )

        #
        # Compression Methods
        #

        compression_length = self.reader.read_u8()

        compression_methods = []

        for _ in range(compression_length):

            compression_methods.append(

                self.reader.read_u8()

            )

        #
        # Extensions Length
        #

        extensions_length = self.reader.read_u16()

        extensions = self._parse_extensions(
            extensions_length,
            is_server=False
        )

        return ClientHello(

            legacy_version=legacy_version,

            random=random,

            session_id=session_id,

            cipher_suites=cipher_suites,

            compression_methods=compression_methods,

            extensions_length=extensions_length,

            extensions=extensions

        )
    def _parse_server_hello(self):

        #
        # Legacy Version
        #

        legacy_version = self.reader.read_u16()

        #
        # Random
        #

        random = self.reader.read(32)

        #
        # Session ID Echo
        #

        session_length = self.reader.read_u8()

        session_id = self.reader.read(
            session_length
        )

        #
        # Selected Cipher Suite
        #

        cipher_suite = self.reader.read_u16()

        #
        # Compression Method
        #

        compression_method = self.reader.read_u8()

        #
        # Extensions
        #

        extensions_length = self.reader.read_u16()

        extensions = self._parse_extensions(
            extensions_length,
            is_server=True
        )

        return ServerHello(

            legacy_version=legacy_version,

            random=random,

            session_id=session_id,

            cipher_suite=cipher_suite,

            compression_method=compression_method,

            extensions_length=extensions_length,

            extensions=extensions

        )
    
    def _parse_encrypted_extensions(self):

        #
        # Total Extensions Length
        #

        extensions_length = self.reader.read_u16()

        extensions = self._parse_extensions(
            extensions_length,
            is_server=True
        )

        return EncryptedExtensions(

            extensions_length=extensions_length,

            extensions=extensions

        )
    
    def _parse_extensions(self, total_length, is_server=False):

        start = self.reader.tell()

        extensions = []

        while self.reader.tell() - start < total_length:

            extension_type = self.reader.read_u16()

            extension_length = self.reader.read_u16()

            extension_data = self.reader.read(
                extension_length
            )

            parsed = self._parse_extension_data(
                extension_type,
                extension_data,
                is_server
            )

            extension = TLSExtension(
                extension_type=extension_type,
                length=extension_length,
                data=extension_data,
                parsed=parsed
            )

            extensions.append(extension)

        return extensions
    
    def _parse_certificate(self):

        #
        # Certificate Request Context
        #

        context_length = self.reader.read_u8()

        context = self.reader.read(
            context_length
        )

        #
        # Certificate List Length
        #

        certificate_list_length = self.reader.read_u24()

        start = self.reader.tell()

        entries = []

        while self.reader.tell() - start < certificate_list_length:

            #
            # Certificate Length
            #

            certificate_length = self.reader.read_u24()

            certificate = self.reader.read(
                certificate_length
            )

            #
            # Certificate Extensions
            #

            extensions_length = self.reader.read_u16()

            extensions = self._parse_extensions(
                extensions_length,
                is_server=True
            )

            entries.append(

                CertificateEntry(

                    certificate=certificate,

                    extensions=extensions

                )

            )

        return Certificate(

            context=context,

            entries=entries

        )
        
    def _parse_extension_data(
        self,
        extension_type,
        extension_data,
        is_server=False
    ):
        if extension_type == EXT_SUPPORTED_VERSIONS:

            if is_server:

                return self._parse_server_supported_version(
                    extension_data
                )

            else:

                return self._parse_supported_versions(
                    extension_data
                )

        elif extension_type == EXT_SUPPORTED_GROUPS:

            return self._parse_supported_groups(
                extension_data
            )

        elif extension_type == EXT_KEY_SHARE:

            if is_server:
                return self._parse_server_key_share(
                    extension_data
                )
            else:
                return self._parse_client_key_share(
                    extension_data
                )
            
        elif extension_type == EXT_SIGNATURE_ALGORITHMS:

            return self._parse_signature_algorithms(
                extension_data
            )
            
        elif extension_type == EXT_ALPN:

            return self._parse_alpn(
                extension_data
            )
            
        elif extension_type == EXT_SERVER_NAME:

            return self._parse_server_name(
                extension_data
            )
            
        elif extension_type == EXT_PSK_KEY_EXCHANGE_MODES:

            return self._parse_psk_key_exchange_modes(
                extension_data
            )

        return None
        
    def _parse_supported_versions(
        self,
        extension_data
    ):

        reader = BufferReader(extension_data)

        total_length = reader.read_u8()

        versions = []

        while reader.remaining() > 0:

            versions.append(
                reader.read_u16()
            )

        return SupportedVersions(
            versions=versions
        )
        
    def _parse_server_supported_version(
        self,
        extension_data
    ):

        reader = BufferReader(extension_data)

        version = reader.read_u16()

        return SupportedVersions(
            versions=[version]
        )
    
    def _parse_supported_groups(
        self,
        extension_data
    ):

        reader = BufferReader(extension_data)

        total_length = reader.read_u16()

        groups = []

        while reader.remaining() > 0:

            groups.append(
                reader.read_u16()
            )

        return SupportedGroups(
            groups=groups
        )
        
    def _parse_client_key_share(
        self,
        extension_data
    ):

        reader = BufferReader(extension_data)

        #
        # Total length of all KeyShare entries
        #

        total_length = reader.read_u16()

        entries = []

        while reader.remaining() > 0:

            group = reader.read_u16()

            key_length = reader.read_u16()

            key_exchange = reader.read(
                key_length
            )

            entries.append(

                KeyShareEntry(

                    group=group,

                    key_exchange=key_exchange

                )

            )

        return KeyShare(
            entries=entries
        )
        
    def _parse_server_key_share(
        self,
        extension_data
    ):

        reader = BufferReader(extension_data)

        #
        # ServerHello contains exactly ONE KeyShareEntry.
        #

        group = reader.read_u16()

        key_length = reader.read_u16()

        key_exchange = reader.read(key_length)

        return KeyShare(
            entries=[
                KeyShareEntry(
                    group=group,
                    key_exchange=key_exchange
                )
            ]
        )
        
    def _parse_signature_algorithms(
        self,
        extension_data
    ):

        reader = BufferReader(extension_data)

        #
        # Total length
        #

        total_length = reader.read_u16()

        algorithms = []

        while reader.remaining() > 0:

            algorithms.append(
                reader.read_u16()
            )

        return SignatureAlgorithms(
            algorithms=algorithms
        )
        
    def _parse_alpn(
        self,
        extension_data
    ):

        reader = BufferReader(extension_data)

        #
        # Total protocol list length
        #

        total_length = reader.read_u16()

        protocols = []

        while reader.remaining() > 0:

            protocol_length = reader.read_u8()

            protocol = reader.read(
                protocol_length
            ).decode(
                "ascii",
                errors="ignore"
            )

            protocols.append(protocol)

        return ALPN(
            protocols=protocols
        )
    
    def _parse_server_name(
        self,
        extension_data
    ):

        reader = BufferReader(extension_data)

        #
        # Total server name list length
        #

        total_length = reader.read_u16()

        #
        # Name Type
        #

        name_type = reader.read_u8()

        #
        # Hostname Length
        #

        hostname_length = reader.read_u16()

        hostname = reader.read(
            hostname_length
        ).decode(
            "utf-8",
            errors="ignore"
        )

        return ServerName(
            hostname=hostname
        )
        
    def _parse_psk_key_exchange_modes(
        self,
        extension_data
    ):

        reader = BufferReader(extension_data)

        #
        # Number of modes
        #

        total_length = reader.read_u8()

        modes = []

        while reader.remaining() > 0:

            modes.append(
                reader.read_u8()
            )

        return PSKKeyExchangeModes(
            modes=modes
        )
    
    # =====================================================
    # Helper Functions
    # =====================================================

    def tell(self):

        return self.reader.tell()

    def seek(self, position):

        self.reader.seek(position)

    def remaining(self):

        return self.reader.remaining()

    def read(self, size):

        return self.reader.read(size)

    def read_u8(self):

        return self.reader.read_u8()

    def read_u16(self):

        return self.reader.read_u16()

    def read_u24(self):

        return self.reader.read_u24()

    def read_u32(self):

        return self.reader.read_u32()
