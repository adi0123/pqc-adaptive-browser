from cryptography import x509

from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519

class X509Parser:

    def __init__(self, der_bytes):

        self.certificate = x509.load_der_x509_certificate(
            der_bytes
        )
    def get_subject(self):

    	return self.certificate.subject.rfc4514_string()
    def get_issuer(self):

    	return self.certificate.issuer.rfc4514_string()
    	
    def get_serial_number(self):

    	return hex(
        	self.certificate.serial_number
    	)
    def get_valid_from(self):

    	return self.certificate.not_valid_before


    def get_valid_until(self):

    	return self.certificate.not_valid_after
    	
    def get_signature_algorithm(self):

        algo = self.certificate.signature_hash_algorithm

        if algo is None:
            return "Ed25519"

        return algo.name
    	
    	
    def get_public_key_type(self):

    	key = self.certificate.public_key()

    	if isinstance(key, rsa.RSAPublicKey):

        	return "RSA"

    	if isinstance(key, ec.EllipticCurvePublicKey):

        	return "ECDSA"

    	if isinstance(key, ed25519.Ed25519PublicKey):

        	return "Ed25519"

    	return "Unknown"
    	
    def get_key_size(self):

    	key = self.certificate.public_key()

    	if hasattr(key, "key_size"):

        	return key.key_size

    	return None
    def get_extensions(self):

        return self.certificate.extensions
        
    def print_extensions(parser):

        print()

        print("========== CERTIFICATE EXTENSIONS ==========")

        for extension in parser.get_extensions():

            print(extension.oid._name)

        print("============================================")

        print()
    	
def print_certificate_info(parser):

    print()

    print("========== X.509 CERTIFICATE ==========")

    print(f"Subject             : {parser.get_subject()}")

    print(f"Issuer              : {parser.get_issuer()}")

    print(f"Serial Number       : {parser.get_serial_number()}")

    print(f"Valid From          : {parser.get_valid_from()}")

    print(f"Valid Until         : {parser.get_valid_until()}")

    print(f"Signature Algorithm : {parser.get_signature_algorithm()}")

    print(f"Public Key Type     : {parser.get_public_key_type()}")

    size = parser.get_key_size()

    if size is None:
        print("Key Size            : N/A")
    else:
        print(f"Key Size            : {size} bits")

    print("======================================")

    print()

