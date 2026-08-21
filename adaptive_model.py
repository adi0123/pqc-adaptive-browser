class AdaptivePQCModel:

    ALGORITHMS = [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024"
    ]

    SECURITY_LEVELS = {
        "ML-KEM-512": 1,
        "ML-KEM-768": 3,
        "ML-KEM-1024": 5
    }

    PUBLIC_KEY_SIZES = {
        "ML-KEM-512": 800,
        "ML-KEM-768": 1184,
        "ML-KEM-1024": 1568
    }

    CIPHERTEXT_SIZES = {
        "ML-KEM-512": 768,
        "ML-KEM-768": 1088,
        "ML-KEM-1024": 1568
    }

    def __init__(self):

        self.last_decision = None

    # =====================================================
    # Select ML-KEM
    # =====================================================

    def select_algorithm(
        self,
        bandwidth_mbps,
        latency_ms,
        packet_size,
        security_level,
        server_support
    ):

        #
        # -------------------------------------------------
        # Security constraint
        # -------------------------------------------------
        #

        candidates = []

        for algorithm in self.ALGORITHMS:

            level = self.SECURITY_LEVELS[
                algorithm
            ]

            if level < security_level:
                continue

            if algorithm not in server_support:
                continue

            candidates.append(
                algorithm
            )

        #
        # No valid candidate
        #

        if not candidates:

            #
            # Fail safe:
            #
            # Use strongest supported algorithm.
            #

            supported = [
                a for a in self.ALGORITHMS
                if a in server_support
            ]

            if not supported:

                return None

            return max(
                supported,
                key=lambda x:
                    self.SECURITY_LEVELS[x]
            )

        #
        # -------------------------------------------------
        # Network-aware selection
        # -------------------------------------------------
        #

        #
        # Strong security requirement:
        # don't downgrade.
        #

        if security_level >= 5:

            selected = "ML-KEM-1024"

        elif security_level >= 3:

            #
            # If network is poor, prefer 768
            # over 1024.
            #

            selected = "ML-KEM-768"

        else:

            #
            # Security level 1.
            #
            # On constrained networks choose 512.
            #

            selected = "ML-KEM-512"

        #
        # Check support
        #

        if selected not in candidates:

            #
            # Choose smallest candidate satisfying
            # security requirement.
            #

            selected = min(
                candidates,
                key=lambda x:
                    self.PUBLIC_KEY_SIZES[x]
            )

        self.last_decision = selected

        return selected
