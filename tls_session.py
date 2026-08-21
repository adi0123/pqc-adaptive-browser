class TLSSession:

    def __init__(self):

        #
        # Client values
        #

        self.client_random = None

        self.server_random = None

        #
        # X25519
        #

        self.x25519_private = None

        self.x25519_public = None

        self.server_x25519_public = None

        self.x25519_shared = None

        #
        # ML-KEM
        #

        self.mlkem_private = None

        self.mlkem_public = None

        self.mlkem_ciphertext = None

        self.mlkem_shared = None

        #
        # Hybrid
        #

        self.hybrid_shared_secret = None
        self.hybrid_public = None
        #
        # TLS
        #

        self.cipher_suite = None

        self.handshake_secret = None

        self.master_secret = None
        
        self.client_session_id = None
        
        
        self.server_session_id = None
        
        self.client_handshake_traffic_secret = None

        self.server_handshake_traffic_secret = None

        self.client_application_secret = None

        self.server_application_secret = None
        
        #
        # Handshake Transcript
        #

        self.client_hello_bytes = None

        self.server_hello_bytes = None

        self.transcript_hash = None
        
        #
        # Performance Metrics
        #

        self.time_x25519 = 0

        self.time_mlkem = 0

        self.time_hybrid = 0

        self.time_key_schedule = 0

        self.total_handshake_time = 0
        
       
        
        #
        # TLS
        #

        self.hostname = None

        self.tls_version = None

        self.group_name = None

        self.status = None

        self.cipher_suite = None

        self.handshake_secret = None

        self.master_secret = None
        
        
    def dump(self):

        print()

        print("========== TLS SESSION ==========")

        print(
            "Client Random :",
            self.client_random.hex()
            if self.client_random
            else "None"
        )
        
        print(
            "Server Random :",
            self.server_random.hex()
            if self.server_random
            else "None"
        )

        

        print()

        print("X25519")

        print("  Client Public :", len(self.x25519_public))

        print(

            "Server Public :",

            len(self.server_x25519_public)

            if self.server_x25519_public

            else 0

        )

        print()

        print("ML-KEM")

        print(
            "Public Key :",
            len(self.mlkem_public)
            if self.mlkem_public
            else 0
        )
        
        print(
            "Ciphertext :",
            len(self.mlkem_ciphertext)
            if self.mlkem_ciphertext
            else 0
        )
        
        print()

        print(
            "Cipher Suite :",
            self.cipher_suite if self.cipher_suite else "None"
        )
        
        print()

        print("Host         :", self.hostname)

        print("TLS Version  :", self.tls_version)

        print("Cipher Suite :", self.cipher_suite)

        print("Key Exchange :", self.group_name)

        print("Status       :", self.status)
        
        
        
        
