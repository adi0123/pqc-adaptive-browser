import struct

GROUP_MAP = {
    0x001D: "X25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x6399: "X25519Kyber768Draft00",
    0x11EC: "X25519MLKEM768",
}

class TLSParser:

    def __init__(self, data):

        self.data = data
        self.offset = 0

    def read_u8(self):

        value = self.data[self.offset]

        self.offset += 1

        return value

    def read_u16(self):

        value = struct.unpack(
            "!H",
            self.data[self.offset:self.offset + 2]
        )[0]

        self.offset += 2

        return value

    def read_u24(self):

        b1 = self.read_u8()

        b2 = self.read_u8()

        b3 = self.read_u8()

        return (b1 << 16) | (b2 << 8) | b3

    def read_bytes(self, n):

        value = self.data[self.offset:self.offset + n]

        self.offset += n

        return value
        
    def parse_tls_record(self):

        record = {}

        record["content_type"] = self.read_u8()

        record["version"] = self.read_u16()

        record["length"] = self.read_u16()

        return record
        
    def remaining(self):

        return len(self.data) - self.offset
        
    def parse_handshake(self):

        handshake = {}

        handshake["type"] = self.read_u8()

        handshake["length"] = self.read_u24()

        return handshake
        
    def skip(self, n):

        self.offset += n
    
    def parse_client_hello(self):

        client_hello = {}

        #
        # Legacy Version
        #

        client_hello["legacy_version"] = self.read_u16()

        #
        # Random
        #

        client_hello["random"] = self.read_bytes(32)

        #
        # Session ID
        #

        session_length = self.read_u8()

        client_hello["session_length"] = session_length

        client_hello["session_id"] = self.read_bytes(
            session_length
        )

        #
        # Cipher Suites
        #

        client_hello["cipher_offset"] = self.offset

        cipher_length = self.read_u16()

        client_hello["cipher_length"] = cipher_length

        client_hello["cipher_suites"] = self.read_bytes(
            cipher_length
        )

        #
        # Compression Methods
        #

        client_hello["compression_offset"] = self.offset

        compression_length = self.read_u8()

        client_hello["compression_length"] = compression_length

        client_hello["compression"] = self.read_bytes(
            compression_length
        )

        #
        # Extensions
        #

        client_hello["extensions_length_offset"] = self.offset

        extensions_length = self.read_u16()

        client_hello["extensions_length"] = extensions_length

        client_hello["extensions_offset"] = self.offset

        return client_hello
        
    def parse_extension(self):

        extension = {}

        extension["type"] = self.read_u16()

        extension["length"] = self.read_u16()

        extension["data"] = self.read_bytes(
        extension["length"]
        )

        return extension
        
    def parse_extensions(self, total_length):

        extensions = []

        start = self.offset

        while self.offset - start < total_length:

            extensions.append(
                self.parse_extension()
            )

        return extensions
        
    def parse_keyshare_client(self, extension_data):

        parser = TLSParser(extension_data)

        keyshare = {}

        #
        # Total length
        #

        total_length = parser.read_u16()
        end = parser.offset + total_length
        keyshare["groups"] = []

        while parser.offset < end:

            group = parser.read_u16()

            key_length = parser.read_u16()

            parser.skip(key_length)

            keyshare["groups"].append(group)

        return keyshare
        
    def parse_supported_groups(self, extension_data):

        parser = TLSParser(extension_data)

        groups = {}

        total_length = parser.read_u16()
        end = parser.offset + total_length
        groups["supported_groups"] = []

        while parser.offset < end:

            group = parser.read_u16()

            groups["supported_groups"].append(group)

        return groups
        
    def parse_supported_versions(self, extension_data):

        parser = TLSParser(extension_data)

        versions = {}

        total_length = parser.read_u8()
        end = parser.offset + total_length
        versions["versions"] = []

        while parser.offset < end:

            version = parser.read_u16()

            versions["versions"].append(version)

        return versions
        
    def parse_server_hello(self):

        server = {}

        #
        # legacy_version
        #

        server["legacy_version"] = self.read_u16()

        #
        # Random
        #

        server["random"] = self.read_bytes(32)

        #
        # Session ID
        #

        session_length = self.read_u8()

        server["session_id"] = self.read_bytes(session_length)

        #
        # Selected Cipher Suite
        #

        server["cipher_suite"] = self.read_u16()

        #
        # Compression Method
        #

        server["compression"] = self.read_u8()

        #
        # Extensions
        #

        server["extensions_length"] = self.read_u16()

        return server
        
    def parse_keyshare_server(self, extension_data):

        parser = TLSParser(extension_data)

        keyshare = {}

        keyshare["group"] = parser.read_u16()

        key_length = parser.read_u16()

        keyshare["key"] = parser.read_bytes(key_length)

        return keyshare
        
    def parse_certificate(self):

        certificate = {}

        #
        # Certificate Request Context
        #

        context_length = self.read_u8()

        certificate["context"] = self.read_bytes(
            context_length
        )

        #
        # Certificate List
        #

        certificate["list_length"] = self.read_u24()

        return certificate
        
    def parse_certificate_list(self, total_length):

        certificates = []

        start = self.offset

        while self.offset - start < total_length:

            entry = {}

            #
            # Certificate Length
            #

            cert_length = self.read_u24()

            entry["certificate"] = self.read_bytes(
                cert_length
            )

            #
            # Extensions
            #

            extensions_length = self.read_u16()

            entry["extensions"] = self.read_bytes(
                extensions_length
            )

            certificates.append(entry)

        return certificates
        
        
def print_record(record):

    print()

    print("========== TLS RECORD ==========")

    print(f"Content Type : {record['content_type']}")

    print(f"Version      : 0x{record['version']:04X}")

    print(f"Length       : {record['length']}")

    print("===============================")

    print()
    
def handshake_name(handshake_type):

    names = {

        1: "ClientHello",

        2: "ServerHello",

        11: "Certificate",

        15: "CertificateVerify",

        20: "Finished",

        8: "EncryptedExtensions"

    }

    return names.get(handshake_type, f"Unknown ({handshake_type})")
    
def print_handshake(handshake):

    print()

    print("======= HANDSHAKE =======")

    print(
        f"Type   : {handshake_name(handshake['type'])}"
    )

    print(
        f"Length : {handshake['length']}"
    )

    print("=========================")

    print()
    
def group_name(group):

    return GROUP_MAP.get(
        group,
        f"Unknown (0x{group:04X})"
    )
    
def version_name(version):

    versions = {

        0x0301: "TLS 1.0",

        0x0302: "TLS 1.1",

        0x0303: "TLS 1.2",

        0x0304: "TLS 1.3",

    }

    return versions.get(
        version,
        f"Unknown (0x{version:04X})"
    )
    
def print_supported_versions(versions):

    print()

    print("==== SUPPORTED VERSIONS ====")

    for version in versions["versions"]:

        print(
            version_name(version)
        )

    print("============================")

    print()

def print_keyshare(keyshare):

    print()

    print("======= KEY SHARE =======")

    for group in keyshare["groups"]:

        print(
            f"Group : {group_name(group)}"
        )

    print("=========================")

    print()
    
def print_supported_groups(groups):

    print()

    print("==== SUPPORTED GROUPS ====")

    for group in groups["supported_groups"]:

        print(
            f"{group_name(group)}"
        )

    print("==========================")

    print()

def extension_name(ext):

    names = {

        0x0000: "Server Name",

        0x000A: "Supported Groups",

        0x000D: "Signature Algorithms",

        0x002B: "Supported Versions",

        0x0033: "Key Share",

        0x0010: "ALPN"

    }

    return names.get(
        ext,
        f"Unknown (0x{ext:04X})"
    )
    
def print_extensions(extensions):

    print()

    print("======= EXTENSIONS =======")

    for ext in extensions:

        print(
            f"{extension_name(ext['type'])} "
            f"(0x{ext['type']:04X})"
        )

    print("==========================")

    print()
    
def print_server_keyshare(keyshare):

    print()

    print("==== SERVER KEY SHARE ====")

    print(
        f"Negotiated Group : {group_name(keyshare['group'])}"
    )

    print("==========================")

    print()
