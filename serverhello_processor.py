from tls_constants import *
from cipher_names import CIPHER_NAMES
class ServerHelloProcessor:

    def __init__(self, session, pqc):

        self.session = session

        self.pqc = pqc

    def process(self, server_hello):

        print()
        self.session.server_random = server_hello.random

        self.session.cipher_suite = CIPHER_NAMES.get(
            server_hello.cipher_suite,
            hex(server_hello.cipher_suite)
        )

        self.session.server_session_id = server_hello.session_id
        print("========== SERVERHELLO PROCESSOR ==========")

        for extension in server_hello.extensions:
            
            if extension.extension_type == EXT_SUPPORTED_VERSIONS:

                print("Supported Versions object:")
                print(type(extension.parsed))
                print(vars(extension.parsed))
            
            if extension.extension_type != EXT_KEY_SHARE:
                continue

            keyshare = extension.parsed

            for entry in keyshare.entries:

                print()

                print(
                    f"Server KeyShare Group : {hex(entry.group)}"
                )

                print(
                    f"Length : {len(entry.key_exchange)} bytes"
                )

                if entry.group == GROUP_HYBRID:

                    self.session.group_name = "X25519MLKEM768"

                    self.session.status = "PQC Protected"

                    self.process_hybrid(entry.key_exchange)

                elif entry.group == GROUP_X25519:

                    self.session.group_name = "X25519"

                    self.session.status = "Classical TLS"
                
            self.session.dump()

    def process_hybrid(self, data):

        server_x25519 = data[:32]

        mlkem_ciphertext = data[32:]

        self.session.server_x25519_public = server_x25519

        self.session.mlkem_ciphertext = mlkem_ciphertext

        print()

        print("========== HYBRID SERVER KEY ==========")

        print("Server X25519 :", len(server_x25519))

        print("ML-KEM CT     :", len(mlkem_ciphertext))
