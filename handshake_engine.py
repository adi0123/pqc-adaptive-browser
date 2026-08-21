import time
from tls_session import TLSSession

class HandshakeEngine:

    def __init__(self, session, pqc):

        self.session = session
        self.pqc = pqc

    def compute(self):

        print()
        print("========== HANDSHAKE ENGINE ==========")

        overall_start = time.perf_counter()

        self.compute_x25519()

        self.compute_mlkem()

        self.combine_shared_secret()
        
        self.derive_tls_secrets()
        
        overall_end = time.perf_counter()

        self.session.total_handshake_time = (
            overall_end - overall_start
        )

        print()
        print("Handshake Complete")

    # ---------------------------------------

    def compute_x25519(self):

        print()
        print("Computing X25519 Shared Secret...")
        start = time.perf_counter()
        shared = self.pqc.compute_x25519_shared(

            self.session.x25519_private,

            self.session.server_x25519_public

        )

        self.session.x25519_shared = shared
        end = time.perf_counter()

        self.session.time_x25519 = end - start
        print("Length :", len(shared))

        print(shared.hex())

    # ---------------------------------------

    def compute_mlkem(self):

        print()
        print("Computing ML-KEM Shared Secret...")
        start = time.perf_counter()
        shared = self.pqc.decapsulate_mlkem(

            self.session.mlkem_ciphertext

        )

        self.session.mlkem_shared = shared
        end = time.perf_counter()

        self.session.time_mlkem = end - start
        print("Length :", len(shared))

        print(shared.hex())

    # ---------------------------------------

    def combine_shared_secret(self):

        print()
        print("Combining Hybrid Secret...")
        start = time.perf_counter()
        hybrid = self.pqc.combine_hybrid_secret(

            self.session.x25519_shared,

            self.session.mlkem_shared

        )

        self.session.hybrid_shared_secret = hybrid
        end = time.perf_counter()

        self.session.time_hybrid = end - start
        print()

        print("Hybrid Secret Length :", len(hybrid))

        print(hybrid.hex())
        
    def derive_tls_secrets(self):

        import hashlib

        print()
        print("========== TLS KEY SCHEDULE ==========")
        start = time.perf_counter()
        #
        # Transcript Hash
        #

        transcript = (

            self.session.client_hello_bytes +

            self.session.server_hello_bytes

        )

        transcript_hash = hashlib.sha256(

            transcript

        ).digest()

        self.session.transcript_hash = transcript_hash

        print()

        print("Transcript Hash")

        print(transcript_hash.hex())
        
        #
        # Early Secret
        #

        zero_key = bytes(32)

        early_secret = self.pqc.hkdf_extract(

            salt=zero_key,

            ikm=zero_key

        )

        print()
        print("Early Secret")

        print(early_secret.hex())
        
        #
        # Derived Secret
        #

        empty_hash = hashlib.sha256(

            b""

        ).digest()

        derived_secret = self.pqc.derive_secret(

            early_secret,

            "derived",

            empty_hash

        )

        print()
        print("Derived Secret")

        print(derived_secret.hex())
        
        #
        # Handshake Secret
        #

        handshake_secret = self.pqc.hkdf_extract(

            derived_secret,

            self.session.hybrid_shared_secret

        )

        self.session.handshake_secret = handshake_secret

        print()
        print("Handshake Secret")

        print(handshake_secret.hex())
        
        #
        # Client Handshake Traffic Secret
        #

        client_hs = self.pqc.derive_secret(

            handshake_secret,

            "c hs traffic",

            transcript_hash

        )
    
        self.session.client_handshake_traffic_secret = client_hs

        print()
        print("Client Handshake Traffic Secret")

        print(client_hs.hex())
        
        #
        # Server Handshake Traffic Secret
        #

        server_hs = self.pqc.derive_secret(

            handshake_secret,

            "s hs traffic",

            transcript_hash

        )

        self.session.server_handshake_traffic_secret = server_hs

        print()
        print("Server Handshake Traffic Secret")

        print(server_hs.hex())
        
        #
        # Derive Secret (before Master Secret)
        #

        derived2 = self.pqc.derive_secret(

            handshake_secret,

            "derived",

            empty_hash

        )

        print()
        print("Derived Secret #2")

        print(derived2.hex())
        
        #
        # Master Secret
        #

        master_secret = self.pqc.hkdf_extract(

            derived2,

            zero_key

        )

        self.session.master_secret = master_secret

        print()
        print("Master Secret")

        print(master_secret.hex())
        
        #
        # Client Application Traffic Secret
        #

        client_app = self.pqc.derive_secret(

            master_secret,

            "c ap traffic",

            transcript_hash

        )

        self.session.client_application_secret = client_app

        print()
        print("Client Application Traffic Secret")

        print(client_app.hex())
        
        #
        # Server Application Traffic Secret
        #

        server_app = self.pqc.derive_secret(

            master_secret,

            "s ap traffic",

            transcript_hash

        )

        self.session.server_application_secret = server_app

        print()
        print("Server Application Traffic Secret")
        end = time.perf_counter()

        self.session.time_key_schedule = end - start
        print(server_app.hex())

