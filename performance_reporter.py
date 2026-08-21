class PerformanceReporter:

    def __init__(self, session, pqc):

        self.session = session
        self.pqc = pqc
        
    def print_report(self):

        print()
        print("=" * 60)
        stats = self.pqc.get_statistics()
        print("         HYBRID PQC TLS PERFORMANCE REPORT")
        print("=" * 60)

        print()

        print(
            f"X25519 Shared Secret       : "
            f"{self.session.time_x25519 * 1000:.3f} ms"
        )

        print(
            f"ML-KEM Decapsulation      : "
            f"{self.session.time_mlkem * 1000:.3f} ms"
        )

        print(
            f"Hybrid Combination        : "
            f"{self.session.time_hybrid * 1000:.6f} ms"
        )

        print(
            f"TLS Key Schedule          : "
            f"{self.session.time_key_schedule * 1000:.3f} ms"
        )

        print("-" * 60)

        print(
            f"Total Handshake           : "
            f"{self.session.total_handshake_time * 1000:.3f} ms"
        )

        print()

        print("Bandwidth")

        print(
            f"ML-KEM Public Key         : "
            f"{stats.get('mlkem_public', 0)} bytes"
        )

        print(
            f"ML-KEM Ciphertext         : "
            f"{stats.get('ciphertext', 0)} bytes"
        )

        print(
            f"X25519 Public Key         : "
            f"{stats.get('x25519_public', 0)} bytes"
        )

        print(
            f"Hybrid Public Key         : "
            f"{stats.get('hybrid_public', 0)} bytes"
        )

        print(
            f"Hybrid Shared Secret      : "
            f"{stats.get('hybrid_secret', 0)} bytes"
        )
        
        print()

        print("=" * 60)
