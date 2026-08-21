from tls_constants import *
from pqc_engine import PQCEngine
from tls_structures import KeyShareEntry


class ClientHelloModifier:

    def __init__(self, session, pqc):

        self.pqc = pqc
        self.session = session

    # =====================================================
    # Public API
    # =====================================================

    def modify(self, client_hello):

        self.session.client_random = (
            client_hello.random
        )

        self.session.client_session_id = (
            client_hello.session_id
        )

        #
        # Insert selected PQC group
        #

        self._insert_hybrid_group(
            client_hello
        )

        #
        # Insert selected PQC key share
        #

        self._insert_hybrid_keyshare(
            client_hello
        )

        return client_hello

    # =====================================================
    # Insert Hybrid Group
    # =====================================================

    def _insert_hybrid_group(
        self,
        client_hello
    ):

        #
        # IMPORTANT
        #
        # Currently your TLS constants contain
        # GROUP_HYBRID for X25519MLKEM768.
        #
        # Therefore this stage keeps GROUP_HYBRID as
        # the negotiated experimental group.
        #
        # The adaptive ML-KEM selection happens inside
        # PQCEngine.
        #
        # For a controlled server later, we can define
        # separate experimental group IDs for:
        #
        # X25519 + ML-KEM-512
        # X25519 + ML-KEM-768
        # X25519 + ML-KEM-1024
        #
        # Do NOT pretend those are standardized groups.
        #

        for extension in client_hello.extensions:

            if (
                extension.extension_type
                != EXT_SUPPORTED_GROUPS
            ):
                continue

            supported_groups = (
                extension.parsed
            )

            #
            # Already present
            #

            if (
                GROUP_HYBRID
                in supported_groups.groups
            ):

                print(
                    "[Modifier] Hybrid group already present"
                )

                return

            #
            # Insert after X25519
            #

            if GROUP_X25519 in supported_groups.groups:

                index = (
                    supported_groups.groups.index(
                        GROUP_X25519
                    )
                )

                supported_groups.groups.insert(
                    index + 1,
                    GROUP_HYBRID
                )

            else:

                supported_groups.groups.append(
                    GROUP_HYBRID
                )

            print(
                "[Modifier] Hybrid group inserted"
            )

            print(
                "[Modifier] Selected ML-KEM:",
                self.pqc.get_algorithm()
            )

            return

        print(
            "[Modifier] Supported Groups extension not found"
        )

    # =====================================================
    # Insert Hybrid KeyShare
    # =====================================================

    def _insert_hybrid_keyshare(
        self,
        client_hello
    ):

        for extension in client_hello.extensions:

            if (
                extension.extension_type
                != EXT_KEY_SHARE
            ):
                continue

            keyshare = extension.parsed

            #
            # Check whether hybrid keyshare already exists
            #

            for entry in keyshare.entries:

                if entry.group == GROUP_HYBRID:

                    print(
                        "[Modifier] Hybrid KeyShare already present"
                    )

                    return

            print(
                "[Modifier] KeyShare extension found"
            )

            #
            # =================================================
            # Generate Adaptive Hybrid Key
            # =================================================
            #

            public_key = (
                self.pqc.generate_hybrid_keypair()
            )

            #
            # -------------------------------------------------
            # Correct key layout:
            #
            # ML-KEM public key || X25519 public key
            # -------------------------------------------------
            #

            mlkem_size = (
                self.pqc.get_expected_public_key_size()
            )

            x25519_size = 32

            expected_size = (
                mlkem_size +
                x25519_size
            )

            if len(public_key) != expected_size:

                raise ValueError(
                    "Hybrid public key size mismatch: "
                    f"expected {expected_size}, "
                    f"got {len(public_key)}"
                )

            #
            # Correct extraction
            #

            mlkem_public = (
                public_key[:-32]
            )

            x25519_public = (
                public_key[-32:]
            )

            #
            # Save session state
            #

            self.session.x25519_private = (
                self.pqc.get_x25519_private()
            )

            self.session.mlkem_private = (
                self.pqc.get_mlkem_private()
            )

            self.session.mlkem_public = (
                mlkem_public
            )

            self.session.hybrid_public = (
                public_key
            )

            self.session.x25519_public = (
                x25519_public
            )

            #
            # Save selected algorithm
            #

            self.session.mlkem_algorithm = (
                self.pqc.get_algorithm()
            )

            self.session.mlkem_security_level = (
                self.pqc.get_security_level()
            )

            #
            # Debug information
            #

            print()
            print(
                "========== ADAPTIVE ML-KEM =========="
            )

            print(
                "Algorithm       :",
                self.pqc.get_algorithm()
            )

            print(
                "NIST Level      :",
                self.pqc.get_security_level()
            )

            print(
                "ML-KEM Public   :",
                len(mlkem_public),
                "bytes"
            )

            print(
                "X25519 Public   :",
                len(x25519_public),
                "bytes"
            )

            print(
                "Hybrid Public   :",
                len(public_key),
                "bytes"
            )

            print(
                "Expected Hybrid :",
                expected_size,
                "bytes"
            )

            print(
                "======================================"
            )

            #
            # =================================================
            # Create KeyShare
            # =================================================
            #

            hybrid_entry = KeyShareEntry(

                group=GROUP_HYBRID,

                key_exchange=public_key

            )

            #
            # Insert after X25519
            #

            for i, entry in enumerate(
                keyshare.entries
            ):

                if entry.group == GROUP_X25519:

                    keyshare.entries.insert(
                        i + 1,
                        hybrid_entry
                    )

                    print(
                        "[Modifier] Adaptive Hybrid "
                        "KeyShare inserted"
                    )

                    return

            #
            # Fallback
            #

            keyshare.entries.append(
                hybrid_entry
            )

            print(
                "[Modifier] Adaptive Hybrid "
                "KeyShare appended"
            )

            return

        print(
            "[Modifier] KeyShare extension not found"
        )
