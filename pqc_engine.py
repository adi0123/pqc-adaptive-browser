import oqs
import time

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

import hmac
import hashlib


class PQCEngine:

    # =====================================================
    # ML-KEM PARAMETERS
    # =====================================================

    MLKEM_PARAMETERS = {

        "ML-KEM-512": {
            "nist_level": 1,
            "public_key_size": 800,
            "ciphertext_size": 768,
            "shared_secret_size": 32,
        },

        "ML-KEM-768": {
            "nist_level": 3,
            "public_key_size": 1184,
            "ciphertext_size": 1088,
            "shared_secret_size": 32,
        },

        "ML-KEM-1024": {
            "nist_level": 5,
            "public_key_size": 1568,
            "ciphertext_size": 1568,
            "shared_secret_size": 32,
        },
    }

    # =====================================================
    # Constructor
    # =====================================================

    def __init__(self, algorithm="ML-KEM-768"):

        if algorithm not in self.MLKEM_PARAMETERS:
            raise ValueError(
                f"Unsupported ML-KEM algorithm: {algorithm}"
            )

        self.algorithm = algorithm

        self.kem = oqs.KeyEncapsulation(self.algorithm)

        self.x25519_private = None
        self.x25519_public  = None
        self.mlkem_private  = None
        self.mlkem_public   = None

        self.x25519_public_size   = 0
        self.mlkem_public_size    = 0
        self.hybrid_public_size   = 0
        self.mlkem_ciphertext_size = 0
        self.hybrid_secret_size   = 0

        self.keygen_time        = 0.0
        self.x25519_keygen_time = 0.0
        self.mlkem_keygen_time  = 0.0
        self.decapsulation_time = 0.0

    # =====================================================
    # Change ML-KEM Algorithm
    # =====================================================

    def set_algorithm(self, algorithm):

        if algorithm not in self.MLKEM_PARAMETERS:
            raise ValueError(
                f"Unsupported ML-KEM algorithm: {algorithm}"
            )

        try:
            del self.kem
        except Exception:
            pass

        self.algorithm = algorithm
        self.kem       = oqs.KeyEncapsulation(self.algorithm)

        self.mlkem_private         = None
        self.mlkem_public          = None
        self.mlkem_public_size     = 0
        self.mlkem_ciphertext_size = 0

    # =====================================================
    # Algorithm Information
    # =====================================================

    def get_algorithm(self):
        return self.algorithm

    def get_security_level(self):
        return self.MLKEM_PARAMETERS[self.algorithm]["nist_level"]

    def get_expected_public_key_size(self):
        return self.MLKEM_PARAMETERS[self.algorithm]["public_key_size"]

    def get_expected_ciphertext_size(self):
        return self.MLKEM_PARAMETERS[self.algorithm]["ciphertext_size"]

    # =====================================================
    # Generate X25519 Keypair ONLY
    # ← THIS IS NOW A PROPER CLASS METHOD (not nested)
    # Called by proxy.py BEFORE PQC mode is decided
    # =====================================================

    def generate_x25519_keypair(self):
        """
        Generate only the X25519 keypair.
        Used for the initial classical TLS ClientHello
        before the adaptive ML-KEM selection is applied.
        """
        start = time.perf_counter()

        self.x25519_private = x25519.X25519PrivateKey.generate()

        self.x25519_public = self.x25519_private.public_key()

        x25519_public_bytes = self.x25519_public.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )

        self.x25519_public_size = len(x25519_public_bytes)

        self.x25519_keygen_time = time.perf_counter() - start

        print(
            f"[PQCEngine] X25519 keypair generated: "
            f"{self.x25519_public_size} bytes "
            f"in {self.x25519_keygen_time * 1000:.3f} ms"
        )

        return x25519_public_bytes

    # =====================================================
    # Generate Hybrid KeyPair (X25519 + ML-KEM)
    # Called by ClientHelloModifier when PQC mode is active
    # =====================================================

    def generate_hybrid_keypair(self):

        # --------------------------------------------------
        # Step 1: Generate X25519
        # --------------------------------------------------
        start_x25519 = time.perf_counter()

        self.x25519_private = x25519.X25519PrivateKey.generate()

        self.x25519_public = self.x25519_private.public_key()

        x25519_public_bytes = self.x25519_public.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )

        self.x25519_public_size = len(x25519_public_bytes)

        self.x25519_keygen_time = (
            time.perf_counter() - start_x25519
        )

        # --------------------------------------------------
        # Step 2: Generate ML-KEM
        # --------------------------------------------------
        start_mlkem = time.perf_counter()

        self.mlkem_public = self.kem.generate_keypair()

        self.mlkem_private = self.kem.export_secret_key()

        self.mlkem_public_size = len(self.mlkem_public)

        self.mlkem_keygen_time = (
            time.perf_counter() - start_mlkem
        )

        # --------------------------------------------------
        # Step 3: Combine into Hybrid Public Key
        # Layout: ML-KEM public key || X25519 public key
        # --------------------------------------------------
        hybrid_public = self.mlkem_public + x25519_public_bytes

        self.hybrid_public_size = len(hybrid_public)

        return hybrid_public

    # =====================================================
    # Getters
    # =====================================================

    def get_x25519_private(self):
        return self.x25519_private

    def get_mlkem_private(self):
        return self.mlkem_private

    def get_x25519_public(self):
        return self.x25519_public

    def get_mlkem_public(self):
        return self.mlkem_public

    # =====================================================
    # X25519 Shared Secret
    # =====================================================

    def compute_x25519_shared(self, private_key, peer_public_bytes):

        peer_public = x25519.X25519PublicKey.from_public_bytes(
            peer_public_bytes
        )

        return private_key.exchange(peer_public)

    # =====================================================
    # ML-KEM Decapsulation
    # =====================================================

    def decapsulate_mlkem(self, ciphertext):

        start = time.perf_counter()

        shared_secret = self.kem.decap_secret(ciphertext)

        self.decapsulation_time    = time.perf_counter() - start
        self.mlkem_ciphertext_size = len(ciphertext)

        return shared_secret

    # =====================================================
    # Hybrid Secret
    # =====================================================

    def combine_hybrid_secret(self, x25519_secret, mlkem_secret):

        hybrid = x25519_secret + mlkem_secret

        self.hybrid_secret_size = len(hybrid)

        return hybrid

    # =====================================================
    # TLS 1.3 HKDF Extract
    # =====================================================

    def hkdf_extract(self, salt, ikm):

        return hmac.new(
            salt,
            ikm,
            hashlib.sha256
        ).digest()

    # =====================================================
    # HKDF Expand Label
    # =====================================================

    def hkdf_expand_label(self, secret, label, context, length):

        full_label = b"tls13 " + label.encode()

        hkdf_label  = length.to_bytes(2, "big")
        hkdf_label += bytes([len(full_label)]) + full_label
        hkdf_label += bytes([len(context)])    + context

        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=length,
            info=hkdf_label
        )

        return hkdf.derive(secret)

    # =====================================================
    # TLS 1.3 Derive Secret
    # =====================================================

    def derive_secret(self, secret, label, transcript_hash):

        return self.hkdf_expand_label(
            secret=secret,
            label=label,
            context=transcript_hash,
            length=32
        )

    # =====================================================
    # Statistics
    # =====================================================

    def get_statistics(self):

        return {
            "algorithm":       self.algorithm,
            "security_level":  self.get_security_level(),
            "x25519_public":   self.x25519_public_size,
            "mlkem_public":    self.mlkem_public_size,
            "hybrid_public":   self.hybrid_public_size,
            "ciphertext":      self.mlkem_ciphertext_size,
            "hybrid_secret":   self.hybrid_secret_size,
            "x25519_keygen_ms": self.x25519_keygen_time * 1000,
            "mlkem_keygen_ms":  self.mlkem_keygen_time  * 1000,
            "decapsulation_ms": self.decapsulation_time  * 1000,
        }
