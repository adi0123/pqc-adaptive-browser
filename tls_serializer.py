from tls_constants import *

class TLSSerializer:

    def __init__(self):
        pass

    # ============================================
    # Public API
    # ============================================

    def serialize(self, record):

        return self._serialize_record(record)

    # ============================================
    # TLS Record
    # ============================================

    def _serialize_record(self, record):

        #
        # Serialize the handshake first.
        #

        handshake_bytes = self._serialize_handshake(
            record.handshake
        )

        #
        # TLS Record Header
        #

        data = b""

        #
        # Content Type
        #

        data += record.content_type.to_bytes(
            1,
            "big"
        )

        #
        # Version
        #

        data += record.version.to_bytes(
            2,
            "big"
        )

        #
        # Record Length
        #

        data += len(handshake_bytes).to_bytes(
            2,
            "big"
        )

        #
        # Payload
        #

        data += handshake_bytes

        return data

    # ============================================
    # Handshake
    # ============================================
    def _serialize_handshake(self, handshake):

        #
        # Serialize handshake body
        #

        if handshake.handshake_type == HANDSHAKE_CLIENT_HELLO:

            body = self._serialize_client_hello(
                handshake.body
            )

        elif handshake.handshake_type == HANDSHAKE_SERVER_HELLO:

            body = self._serialize_server_hello(
                handshake.body
            )

        elif handshake.handshake_type == HANDSHAKE_ENCRYPTED_EXTENSIONS:

            body = self._serialize_encrypted_extensions(
                handshake.body
            )

        else:

            raise NotImplementedError(
                f"Unsupported handshake type {handshake.handshake_type}"
            )

        #
        # Handshake Header
        #

        data = b""

        #
        # Handshake Type
        #

        data += handshake.handshake_type.to_bytes(
            1,
            "big"
        )

        #
        # Handshake Length (3 bytes)
        #

        data += len(body).to_bytes(
            3,
            "big"
        )

        #
        # Body
        #

        data += body

        return data

    # ============================================
    # ClientHello
    # ============================================

    def _serialize_client_hello(self, client_hello):

        data = b""

        #
        # Legacy Version
        #

        data += client_hello.legacy_version.to_bytes(
            2,
            "big"
        )

        #
        # Random
        #

        data += client_hello.random

        #
        # Session ID
        #

        data += len(
            client_hello.session_id
        ).to_bytes(
            1,
            "big"
        )

        data += client_hello.session_id

        #
        # Cipher Suites
        #

        cipher_bytes = b""

        for suite in client_hello.cipher_suites:

            cipher_bytes += suite.to_bytes(
                2,
                "big"
            )

        data += len(
            cipher_bytes
        ).to_bytes(
            2,
            "big"
        )

        data += cipher_bytes

        #
        # Compression Methods
        #

        compression_bytes = b""

        for method in client_hello.compression_methods:

            compression_bytes += method.to_bytes(
                1,
                "big"
            )

        data += len(
            compression_bytes
        ).to_bytes(
            1,
            "big"
        )

        data += compression_bytes

        #
        # Extensions
        #

        extension_bytes = self._serialize_extensions(
            client_hello.extensions
        )

        data += len(
            extension_bytes
        ).to_bytes(
            2,
            "big"
        )

        data += extension_bytes

        return data
    # ============================================
    # Extensions
    # ============================================

    
    def _serialize_extensions(self, extensions):

        output = bytearray()

        for ext in extensions:

            extension_data = self._serialize_extension_data(
                ext
            )

            output.extend(
                ext.extension_type.to_bytes(2, "big")
            )

            output.extend(
                len(extension_data).to_bytes(2, "big")
            )

            output.extend(extension_data)

        return bytes(output)
        
    def _serialize_supported_versions(self, data):

        output = bytearray()

        output.append(
            len(data.versions) * 2
        )

        for version in data.versions:

            output.extend(
                version.to_bytes(2, "big")
            )

        return bytes(output)
        
    def _serialize_supported_groups(self, data):

        output = bytearray()

        groups = bytearray()

        for group in data.groups:

            groups.extend(
                group.to_bytes(2, "big")
            )

        output.extend(
            len(groups).to_bytes(2, "big")
        )

        output.extend(groups)

        return bytes(output)
        
    def _serialize_key_share(self, data):

        entries = bytearray()

        for entry in data.entries:

            entries.extend(
                entry.group.to_bytes(2, "big")
            )

            entries.extend(
                len(entry.key_exchange).to_bytes(2, "big")
            )

            entries.extend(
                entry.key_exchange
            )

        output = bytearray()

        output.extend(
            len(entries).to_bytes(2, "big")
        )

        output.extend(entries)

        return bytes(output)
        
    def _serialize_signature_algorithms(self, data):

        algorithms = bytearray()

        for alg in data.algorithms:

            algorithms.extend(
                alg.to_bytes(2, "big")
            )

        output = bytearray()

        output.extend(
            len(algorithms).to_bytes(2, "big")
        )

        output.extend(algorithms)

        return bytes(output)
        
    def _serialize_alpn(self, data):

        protocols = bytearray()

        for protocol in data.protocols:

            encoded = protocol.encode("ascii")

            protocols.append(len(encoded))

            protocols.extend(encoded)

        output = bytearray()

        output.extend(
            len(protocols).to_bytes(2, "big")
        )

        output.extend(protocols)

        return bytes(output)
        
    def _serialize_server_name(self, data):

        hostname = data.hostname.encode("utf-8")

        server_name = bytearray()

        server_name.append(0)

        server_name.extend(
            len(hostname).to_bytes(2, "big")
        )

        server_name.extend(hostname)

        output = bytearray()

        output.extend(
            len(server_name).to_bytes(2, "big")
        )

        output.extend(server_name)

        return bytes(output)
        
    def _serialize_psk_modes(self, data):

        output = bytearray()

        output.append(
            len(data.modes)
        )

        for mode in data.modes:

            output.append(mode)

        return bytes(output)
    
    def _serialize_server_hello(self, server_hello):
        raise NotImplementedError()


    def _serialize_encrypted_extensions(self, encrypted_extensions):
        raise NotImplementedError()
        
    def _serialize_extension_data(self, extension):

        if extension.extension_type == EXT_SUPPORTED_VERSIONS:
            return self._serialize_supported_versions(
                extension.parsed
            )

        elif extension.extension_type == EXT_SUPPORTED_GROUPS:
            return self._serialize_supported_groups(
                extension.parsed
            )

        elif extension.extension_type == EXT_KEY_SHARE:
            return self._serialize_key_share(
                extension.parsed
            )

        elif extension.extension_type == EXT_SIGNATURE_ALGORITHMS:
            return self._serialize_signature_algorithms(
                extension.parsed
            )

        elif extension.extension_type == EXT_ALPN:
            return self._serialize_alpn(
                extension.parsed
            )

        elif extension.extension_type == EXT_SERVER_NAME:
            return self._serialize_server_name(
                extension.parsed
            )

        elif extension.extension_type == EXT_PSK_KEY_EXCHANGE_MODES:
            return self._serialize_psk_modes(
                extension.parsed
            )

        #
        # Unknown extension
        #

        return extension.data
        
    
