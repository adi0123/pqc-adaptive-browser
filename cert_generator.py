import os
import subprocess

CERT_DIR = "proxy_certs"
CA_CERT  = "proxy_ca.crt"
CA_KEY   = "proxy_ca.key"

os.makedirs(CERT_DIR, exist_ok=True)

def get_cert_for_host(hostname):
    """
    Generates a TLS certificate for 'hostname'
    signed by our local CA.
    Returns (cert_path, key_path)
    """
    cert_path = os.path.join(CERT_DIR, f"{hostname}.crt")
    key_path  = os.path.join(CERT_DIR, f"{hostname}.key")

    # Return existing cert if already generated
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    print(f"[CERT] Generating certificate for {hostname}")

    # Step 1: Generate key for this domain
    subprocess.run([
        "openssl", "genrsa",
        "-out", key_path, "2048"
    ], capture_output=True, check=True)

    # Step 2: Generate CSR (certificate signing request)
    csr_path = os.path.join(CERT_DIR, f"{hostname}.csr")
    subprocess.run([
        "openssl", "req",
        "-new",
        "-key",  key_path,
        "-out",  csr_path,
        "-subj", f"/CN={hostname}"
    ], capture_output=True, check=True)

    # Step 3: Sign CSR with our CA
    ext_file = os.path.join(CERT_DIR, f"{hostname}.ext")
    with open(ext_file, "w") as f:
        f.write(f"subjectAltName=DNS:{hostname},DNS:*.{hostname}\n")
        f.write("basicConstraints=CA:FALSE\n")

    subprocess.run([
        "openssl", "x509",
        "-req",
        "-in",       csr_path,
        "-CA",       CA_CERT,
        "-CAkey",    CA_KEY,
        "-CAcreateserial",
        "-out",      cert_path,
        "-days",     "365",
        "-extfile",  ext_file
    ], capture_output=True, check=True)

    print(f"[CERT] Certificate ready for {hostname}")
    return cert_path, key_path
