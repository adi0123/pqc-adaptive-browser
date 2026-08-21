class TLSAnalyzer:
    
    HYBRID_GROUPS = {
        0x6399,
        0x11EC,
    }

    CLASSICAL_GROUPS = {
        0x001D,
        0x0017,
        0x0018,
        0x0019,
    }
    
    def __init__(self):

        self.client_groups = []

        self.server_group = None

        self.supported_versions = []

        self.certificate = None
    
    def set_client_groups(self, groups):

        self.client_groups = groups


    def set_server_group(self, group):

        self.server_group = group


    def set_supported_versions(self, versions):

        self.supported_versions = versions


    def set_certificate(self, certificate):

        self.certificate = certificate
    
    def is_hybrid_group(self):
        return self.server_group in self.HYBRID_GROUPS
        
    def is_classical_group(self):
        return self.server_group in self.CLASSICAL_GROUPS
        
    def get_handshake_type(self):

        if self.is_hybrid_group():

            return "Hybrid PQC"

        if self.is_classical_group():

            return "Classical"

        return "Unknown"
    def get_tls_version(self):

        if not self.supported_versions:

            return "Unknown"

        version = max(self.supported_versions)

        versions = {

            0x0301: "TLS 1.0",

            0x0302: "TLS 1.1",

            0x0303: "TLS 1.2",

            0x0304: "TLS 1.3",

        }

        return versions.get(
            version,
            "Unknown"
        )
        
    def has_forward_secrecy(self):

        if self.server_group is None:

            return False

        return True
    
    def is_quantum_resistant(self):

        return self.is_hybrid_group()
        
    def get_migration_status(self):

        if self.is_hybrid_group():

            return "Hybrid Migration"

        if self.is_classical_group():

            return "Classical Only"

        return "Unknown"
        
    def get_certificate_type(self):

        if self.certificate is None:

            return "Unknown"

        return self.certificate.get_public_key_type()
        
    def get_certificate_key_size(self):

        if self.certificate is None:

            return None

        return self.certificate.get_key_size()
        
    def get_certificate_strength(self):

        key_type = self.get_certificate_type()

        key_size = self.get_certificate_key_size()

        if key_type == "RSA":

            if key_size >= 3072:

                return "Strong"

            if key_size >= 2048:

                return "Acceptable"

            return "Weak"

        if key_type == "ECDSA":

            if key_size >= 384:

                return "Strong"

            return "Acceptable"

        if key_type == "Ed25519":

            return "Strong"

        return "Unknown"
    
    def get_security_rating(self):

        score = 0

        #
        # TLS Version
        #

        if self.get_tls_version() == "TLS 1.3":

            score += 30

        #
        # Forward Secrecy
        #

        if self.has_forward_secrecy():

            score += 20

        #
        # PQC
        #

        if self.is_quantum_resistant():

            score += 30

        #
        # Certificate
        #

        strength = self.get_certificate_strength()

        if strength == "Strong":

            score += 20

        elif strength == "Acceptable":

            score += 15

        if score >= 90:

            return "HIGH"

        if score >= 70:

            return "MEDIUM"

        return "LOW"
        
def print_analysis(analyzer):

    print()

    print("========== TLS ANALYSIS ==========")

    print(
        f"TLS Version        : {analyzer.get_tls_version()}"
    )

    print(
        f"Handshake Type     : {analyzer.get_handshake_type()}"
    )

    print(
        f"Forward Secrecy    : {analyzer.has_forward_secrecy()}"
    )

    print(
        f"Quantum Resistant  : {analyzer.is_quantum_resistant()}"
    )

    print(
        f"Migration Status   : {analyzer.get_migration_status()}"
    )
    
    print(
        f"Certificate Type  : {analyzer.get_certificate_type()}"
    )

    print(
        f"Certificate Size  : {analyzer.get_certificate_key_size()}"
    )

    print(
        f"Certificate Grade : {analyzer.get_certificate_strength()}"
    )

    print(
        f"Security Rating   : {analyzer.get_security_rating()}"
    )

    print("==================================")

    print()
