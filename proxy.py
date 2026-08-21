import os
import json
import socket
import time
import threading
import ssl
import statistics

from debug_config import vprint

from tls_parser import TLSParser
from tls_constants import *

from serverhello_processor import ServerHelloProcessor
from tls_session import TLSSession
from pqc_engine import PQCEngine

from tls_printer import (
    print_record,
    print_handshake,
    print_extensions,
)

from cert_generator import get_cert_for_host
from session_exporter import SessionExporter
from csv_logger import CSVLogger
from handshake_engine import HandshakeEngine
from tls_serializer import TLSSerializer
from performance_reporter import PerformanceReporter
from clienthello_modifier import ClientHelloModifier

from tls_structures import (
    TLSRecord,
    Handshake,
    ClientHello,
    TLSExtension,
    SupportedVersions,
    SupportedGroups,
    KeyShare,
    KeyShareEntry,
    SignatureAlgorithms,
    ALPN,
    ServerName,
    PSKKeyExchangeModes,
)


# ============================================================
# TLS SIGNATURE ALGORITHMS
# ============================================================

SIGNATURE_ALGORITHMS_OFFERED = [
    0x0403,  # ECDSA P-256 + SHA256
    0x0503,  # ECDSA P-384 + SHA384
    0x0603,  # ECDSA P-521 + SHA512
    0x0807,  # Ed25519
    0x0808,  # Ed448
    0x0804,  # RSA-PSS RSAE SHA256
    0x0805,  # RSA-PSS RSAE SHA384
    0x0806,  # RSA-PSS RSAE SHA512
    0x0401,  # RSA PKCS1 SHA256
    0x0501,  # RSA PKCS1 SHA384
    0x0601,  # RSA PKCS1 SHA512
]


# ============================================================
# SETTINGS
# ============================================================

SETTINGS_FILE = "settings.json"

# Saved adaptive model.
#
# Change this filename ONLY if your trained model has another
# filename.
ADAPTIVE_MODEL_FILE = "adaptive_model.pkl"


# ============================================================
# THREAD SAFETY
# ============================================================

_csv_logger_lock = threading.Lock()


# ============================================================
# ADAPTIVE ML-KEM SELECTOR
# ============================================================

class AdaptiveMLKEMSelector:

    """
    Adaptive ML-KEM selection layer.

    The model chooses between:

        ML-KEM-512
        ML-KEM-768
        ML-KEM-1024

    based on connection/server/network features.

    The selector deliberately keeps the actual decision separate
    from the TLS code so that the ML model can later be replaced
    without modifying the TLSProxy implementation.
    """

    VALID_ALGORITHMS = [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
    ]

    def __init__(self, model_file=ADAPTIVE_MODEL_FILE):

        self.model_file = model_file
        self.model = None

        self._load_model()

    # --------------------------------------------------------
    # Load trained model
    # --------------------------------------------------------

    def _load_model(self):

        if not os.path.exists(self.model_file):

            print(
                f"[Adaptive] Model file not found: "
                f"{self.model_file}"
            )

            print(
                "[Adaptive] Using policy fallback until "
                "the trained model is available."
            )

            return

        try:

            import joblib

            self.model = joblib.load(
                self.model_file
            )

            print(
                f"[Adaptive] Model loaded: "
                f"{self.model_file}"
            )

        except Exception as e:

            print(
                f"[Adaptive] Failed to load model: {e}"
            )

            self.model = None

    # --------------------------------------------------------
    # Server security classification
    # --------------------------------------------------------

    def estimate_security_level(self, hostname):

        """
        Initial security-policy layer.

        This is intentionally kept separate from the ML model.

        The thesis can later replace this with a proper
        server-security dataset / classification mechanism.
        """

        hostname = hostname.lower()

        # High-security domains.
        high_security_keywords = [
            "bank",
            "banking",
            "finance",
            "financial",
            "payment",
            "payments",
            "wallet",
            "secure",
            "gov",
            "mil",
            "defence",
            "defense",
        ]

        for keyword in high_security_keywords:

            if keyword in hostname:

                return 3

        # Medium-security / infrastructure domains.

        medium_security_keywords = [
            "mail",
            "gmail",
            "outlook",
            "office",
            "cloud",
            "api",
            "login",
            "account",
            "auth",
        ]

        for keyword in medium_security_keywords:

            if keyword in hostname:

                return 2

        # Default.

        return 1

    # --------------------------------------------------------
    # Fallback policy
    # --------------------------------------------------------

    def policy_fallback(self, features):

        security_level = features.get(
            "security_level",
            2
        )

        bandwidth = features.get(
            "bandwidth_bytes",
            0
        )

        latency = features.get(
            "network_latency_ms",
            0
        )

        packet_size = features.get(
            "packet_size_bytes",
            0
        )

        # ----------------------------------------------------
        # High security
        # ----------------------------------------------------

        if security_level >= 3:

            return "ML-KEM-1024"

        # ----------------------------------------------------
        # Medium security
        # ----------------------------------------------------

        if security_level == 2:

            # On severely constrained networks, 768 avoids
            # unnecessary bandwidth overhead.

            if (
                bandwidth > 0
                and bandwidth < 5000
            ):

                return "ML-KEM-768"

            return "ML-KEM-768"

        # ----------------------------------------------------
        # Low/default security
        # ----------------------------------------------------

        if security_level <= 1:

            return "ML-KEM-512"

        # Safe default.

        return "ML-KEM-768"

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    def predict(self, features):

        """
        Return selected ML-KEM algorithm.
        """

        # ----------------------------------------------------
        # If trained model exists
        # ----------------------------------------------------

        if self.model is not None:

            try:

                # Keep feature order consistent with the
                # training dataset.

                feature_names = [
                    "bandwidth_bytes",
                    "network_latency_ms",
                    "packet_size_bytes",
                    "handshake_history_ms",
                    "security_level",
                    "x25519_ms",
                    "mlkem_ms",
                    "hybrid_ms",
                ]

                values = [
                    features.get(name, 0)
                    for name in feature_names
                ]

                prediction = self.model.predict(
                    [values]
                )[0]

                prediction = str(
                    prediction
                )

                # Handle models trained using numeric labels.

                numeric_map = {
                    "0": "ML-KEM-512",
                    "1": "ML-KEM-768",
                    "2": "ML-KEM-1024",
                }

                if prediction in numeric_map:

                    prediction = numeric_map[
                        prediction
                    ]

                if prediction in self.VALID_ALGORITHMS:

                    return prediction

                print(
                    "[Adaptive] Unknown model output:",
                    prediction
                )

            except Exception as e:

                print(
                    f"[Adaptive] Model prediction failed: {e}"
                )

                print(
                    "[Adaptive] Falling back to policy."
                )

        # ----------------------------------------------------
        # Fallback
        # ----------------------------------------------------

        return self.policy_fallback(
            features
        )

    # --------------------------------------------------------
    # Public selection method
    # --------------------------------------------------------

    def select(self, hostname, features):

        security_level = self.estimate_security_level(
            hostname
        )

        features = dict(features)

        features["security_level"] = security_level

        algorithm = self.predict(
            features
        )

        print()
        print("==============================================")
        print("           ADAPTIVE ML-KEM SELECTION")
        print("==============================================")
        print(f"Host              : {hostname}")
        print(f"Security Level    : {security_level}")
        print(
            f"Bandwidth         : "
            f"{features.get('bandwidth_bytes', 0)} B"
        )
        print(
            f"Network Latency   : "
            f"{features.get('network_latency_ms', 0):.3f} ms"
        )
        print(
            f"Packet Size       : "
            f"{features.get('packet_size_bytes', 0)} B"
        )
        print(
            f"Historical HS     : "
            f"{features.get('handshake_history_ms', 0):.3f} ms"
        )
        print(
            f"Selected Algorithm: {algorithm}"
        )
        print("==============================================")
        print()

        return algorithm


# ============================================================
# TLS PROXY
# ============================================================

class TLSProxy:

    def __init__(self):

        self.listen_host = "127.0.0.1"

        self.listen_port = 8443

        # Existing logging system.

        self.csv_logger = CSVLogger()

        self.session_exporter = SessionExporter()

        # Adaptive model.

        self.adaptive_selector = (
            AdaptiveMLKEMSelector()
        )

        # Keep recent handshake observations.

        self.handshake_history = []

        self.handshake_history_lock = (
            threading.Lock()
        )

    # ========================================================
    # SOCKET
    # ========================================================

    def create_socket(self):

        server = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind(
            (
                self.listen_host,
                self.listen_port
            )
        )

        server.listen(128)

        print(
            f"Listening on "
            f"{self.listen_host}:{self.listen_port}"
        )

        return server

    # ========================================================
    # SERVER CONNECTION
    # ========================================================

    def connect_server(
        self,
        host,
        port,
        timeout=10,
        retries=2
    ):

        last_error = None

        for attempt in range(
            retries + 1
        ):

            try:

                server_socket = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                )

                server_socket.settimeout(
                    timeout
                )

                server_socket.connect(
                    (
                        host,
                        port
                    )
                )

                server_socket.settimeout(
                    None
                )

                return server_socket

            except socket.gaierror as e:

                last_error = e

                is_transient = (
                    getattr(
                        e,
                        "errno",
                        None
                    )
                    == socket.EAI_AGAIN
                )

                if (
                    not is_transient
                    or attempt == retries
                ):

                    raise

                vprint(
                    f"[DNS] Transient resolution "
                    f"failure for {host}, "
                    f"retrying "
                    f"({attempt + 1}/{retries})..."
                )

                time.sleep(
                    0.3 * (attempt + 1)
                )

        raise last_error

    # ========================================================
    # RECEIVE EXACT BYTES
    # ========================================================

    def recv_exact(
        self,
        sock,
        size
    ):

        data = b""

        while len(data) < size:

            chunk = sock.recv(
                size - len(data)
            )

            if not chunk:

                return None

            data += chunk

        return data

    # ========================================================
    # TLS RECORD
    # ========================================================

    def receive_tls_record(
        self,
        sock
    ):

        header = self.recv_exact(
            sock,
            5
        )

        if header is None:

            return None

        record_length = int.from_bytes(
            header[3:5],
            "big"
        )

        payload = self.recv_exact(
            sock,
            record_length
        )

        if payload is None:

            return None

        return (
            header
            + payload
        )

    # ========================================================
    # CRYPTO MODE
    # ========================================================

    def _get_crypto_mode(self):

        try:

            with open(
                SETTINGS_FILE,
                "r"
            ) as f:

                settings = json.load(f)

            return settings.get(
                "crypto_mode",
                "Classical TLS"
            )

        except Exception:

            return "Classical TLS"

    # ========================================================
    # HISTORICAL HANDSHAKE FEATURE
    # ========================================================

    def _get_historical_handshake_time(self):

        with self.handshake_history_lock:

            if not self.handshake_history:

                return 0.0

            return statistics.mean(
                self.handshake_history[-20:]
            )

    # ========================================================
    # ADAPTIVE FEATURES
    # ========================================================

    def _build_adaptive_features(
        self,
        hostname,
        client_hello_size=0,
        network_latency_ms=0.0
    ):

        """
        Construct the feature vector for the adaptive model.

        These features become part of the thesis dataset.

        Current features:

        1. bandwidth_bytes
        2. network_latency_ms
        3. packet_size_bytes
        4. handshake_history_ms
        5. security_level
        6. x25519_ms
        7. mlkem_ms
        8. hybrid_ms

        At the first connection the crypto timing fields are
        unavailable, therefore they are initialized to zero.
        """

        historical_ms = (
            self._get_historical_handshake_time()
        )

        return {

            "bandwidth_bytes":
                client_hello_size,

            "network_latency_ms":
                network_latency_ms,

            "packet_size_bytes":
                client_hello_size,

            "handshake_history_ms":
                historical_ms,

            "security_level":
                0,

            "x25519_ms":
                0.0,

            "mlkem_ms":
                0.0,

            "hybrid_ms":
                0.0,
        }

    # ========================================================
    # BUILD ADAPTIVE CLIENT HELLO
    # ========================================================

    def _build_pqc_client_hello(
        self,
        hostname,
        session,
        pqc,
        modifier,
        selected_algorithm=None
    ):

        mode = self._get_crypto_mode()

        session.requested_mode = mode

        # ----------------------------------------------------
        # Classical X25519
        # ----------------------------------------------------

        x25519_public = (
            pqc.generate_x25519_keypair()
        )

        session.x25519_private = (
            pqc.get_x25519_private()
        )

        session.x25519_public = (
            x25519_public
        )

        # ----------------------------------------------------
        # TLS random/session ID
        # ----------------------------------------------------

        client_random = os.urandom(32)

        client_session_id = os.urandom(32)

        session.client_random = (
            client_random
        )

        session.client_session_id = (
            client_session_id
        )

        # ----------------------------------------------------
        # ClientHello
        # ----------------------------------------------------

        client_hello = ClientHello(

            legacy_version=TLS12,

            random=client_random,

            session_id=client_session_id,

            cipher_suites=[
                0x1301,
                0x1302,
                0x1303,
            ],

            compression_methods=[0],

            extensions_length=0,

            extensions=[

                TLSExtension(
                    extension_type=EXT_SERVER_NAME,
                    length=0,
                    data=b"",
                    parsed=ServerName(
                        hostname=hostname
                    ),
                ),

                TLSExtension(
                    extension_type=EXT_SUPPORTED_VERSIONS,
                    length=0,
                    data=b"",
                    parsed=SupportedVersions(
                        versions=[TLS13]
                    ),
                ),

                TLSExtension(
                    extension_type=EXT_SUPPORTED_GROUPS,
                    length=0,
                    data=b"",
                    parsed=SupportedGroups(
                        groups=[
                            GROUP_X25519
                        ]
                    ),
                ),

                TLSExtension(
                    extension_type=EXT_SIGNATURE_ALGORITHMS,
                    length=0,
                    data=b"",
                    parsed=SignatureAlgorithms(
                        algorithms=list(
                            SIGNATURE_ALGORITHMS_OFFERED
                        )
                    ),
                ),

                TLSExtension(
                    extension_type=EXT_KEY_SHARE,
                    length=0,
                    data=b"",
                    parsed=KeyShare(
                        entries=[

                            KeyShareEntry(
                                group=GROUP_X25519,

                                key_exchange=(
                                    x25519_public
                                ),
                            )

                        ]
                    ),
                ),

                TLSExtension(
                    extension_type=EXT_PSK_KEY_EXCHANGE_MODES,
                    length=0,
                    data=b"",
                    parsed=PSKKeyExchangeModes(
                        modes=[PSK_DHE_KE]
                    ),
                ),

                TLSExtension(
                    extension_type=EXT_ALPN,
                    length=0,
                    data=b"",
                    parsed=ALPN(
                        protocols=["http/1.1"]
                    ),
                ),
            ],
        )

        # ----------------------------------------------------
        # PQC
        # ----------------------------------------------------

        if (
            mode == "PQC Hybrid"
            and selected_algorithm
        ):

            # Tell PQCEngine which ML-KEM variant is being used.

            pqc.set_algorithm(
                selected_algorithm
            )

            modifier.modify(
                client_hello
            )

            session.selected_mlkem = (
                selected_algorithm
            )

            vprint(
                "[Builder] Adaptive PQC mode -> "
                f"{selected_algorithm}"
            )

        elif mode == "PQC Hybrid":

            # Safe default.

            pqc.set_algorithm(
                "ML-KEM-768"
            )

            modifier.modify(
                client_hello
            )

            session.selected_mlkem = (
                "ML-KEM-768"
            )

            vprint(
                "[Builder] PQC mode -> "
                "default ML-KEM-768"
            )

        else:

            session.selected_mlkem = (
                "Classical"
            )

            vprint(
                "[Builder] Classical TLS mode "
                "-> X25519 only"
            )

        # ----------------------------------------------------
        # Serialize
        # ----------------------------------------------------

        record = TLSRecord(

            content_type=CONTENT_HANDSHAKE,

            version=TLS10,

            length=0,

            handshake=Handshake(

                handshake_type=(
                    HANDSHAKE_CLIENT_HELLO
                ),

                length=0,

                body=client_hello,
            ),
        )

        client_hello_bytes = (
            TLSSerializer().serialize(
                record
            )
        )

        session.client_hello_bytes = (
            client_hello_bytes
        )

        return client_hello_bytes

    # ========================================================
    # SUMMARY
    # ========================================================

    def _print_summary_box(
        self,
        hostname,
        session,
        pqc,
        status="SUCCESS"
    ):

        stats = pqc.get_statistics()

        handshake_ms = (
            session.total_handshake_time
            or 0
        ) * 1000

        lines = []

        lines.append(
            "=" * 55
        )

        lines.append(
            f"Host              : {hostname}"
        )

        lines.append(
            f"Mode              : "
            f"{session.requested_mode or 'Classical TLS'}"
        )

        lines.append(
            f"ML-KEM            : "
            f"{getattr(session, 'selected_mlkem', 'N/A')}"
        )

        lines.append(
            f"TLS               : "
            f"{session.tls_version or '-'}"
        )

        lines.append(
            f"Cipher            : "
            f"{session.cipher_suite or '-'}"
        )

        lines.append(
            f"Key Exchange      : "
            f"{session.group_name or '-'}"
        )

        lines.append("")

        lines.append(
            f"Handshake Time    : "
            f"{handshake_ms:.3f} ms"
        )

        lines.append("")

        lines.append(
            "Bandwidth"
        )

        lines.append(
            f"  X25519 Public    : "
            f"{stats.get('x25519_public', 0)} B"
        )

        lines.append(
            f"  ML-KEM Public    : "
            f"{stats.get('mlkem_public', 0)} B"
        )

        lines.append(
            f"  Ciphertext       : "
            f"{stats.get('ciphertext', 0)} B"
        )

        lines.append(
            f"  Hybrid Public    : "
            f"{stats.get('hybrid_public', 0)} B"
        )

        lines.append("")

        lines.append(
            f"Status            : {status}"
        )

        lines.append(
            "=" * 55
        )

        print(
            "\n".join(lines)
        )

    # ========================================================
    # PIPE
    # ========================================================

    def pipe(
        self,
        source,
        destination
    ):

        try:

            while True:

                record = (
                    self.receive_tls_record(
                        source
                    )
                )

                if record is None:

                    break

                try:

                    parser = TLSParser(
                        record
                    )

                    parsed = parser.parse()

                    print(
                        "\n========== "
                        "FORWARDED RECORD "
                        "=========="
                    )

                    print_record(
                        parsed
                    )

                    if parsed.handshake:

                        print_handshake(
                            parsed.handshake
                        )

                except Exception:

                    pass

                destination.sendall(
                    record
                )

        except Exception:

            pass

    # ========================================================
    # START
    # ========================================================

    def start(self):

        server = (
            self.create_socket()
        )

        while True:

            client_socket, client_address = (
                server.accept()
            )

            thread = threading.Thread(

                target=self.handle_connection,

                args=(
                    client_socket,
                    client_address
                ),

                daemon=True,
            )

            thread.start()

    # ========================================================
    # CONNECTION HANDLER
    # ========================================================

    def handle_connection(
        self,
        client_socket,
        client_address
    ):

        # ----------------------------------------------------
        # Per connection state
        # ----------------------------------------------------

        session = TLSSession()

        pqc = PQCEngine()

        modifier = ClientHelloModifier(
            session,
            pqc
        )

        server_processor = (
            ServerHelloProcessor(
                session,
                pqc
            )
        )

        handshake_engine = (
            HandshakeEngine(
                session,
                pqc
            )
        )

        reporter = (
            PerformanceReporter(
                session,
                pqc
            )
        )

        browser_ssl = None

        raw_server_socket = None

        server_ssl = None

        print(
            f"\nClient Connected: "
            f"{client_address}"
        )

        # ====================================================
        # STEP 1
        # RECEIVE CONNECT
        # ====================================================

        try:

            client_socket.settimeout(
                15
            )

            data = client_socket.recv(
                4096
            )

            client_socket.settimeout(
                None
            )

        except Exception:

            data = None

        if not data:

            client_socket.close()

            return

        # ----------------------------------------------------
        # Parse CONNECT
        # ----------------------------------------------------

        try:

            request = data.decode(
                errors="ignore"
            )

            first_line = (
                request.split(
                    "\r\n"
                )[0]
            )

            host_port = (
                first_line.split()[1]
            )

            hostname, port = (
                host_port.split(":")
            )

            port = int(port)

        except Exception as e:

            print(
                f"[ERROR] Malformed CONNECT: "
                f"{e}"
            )

            client_socket.close()

            return

        print(
            f"CONNECT → "
            f"{hostname}:{port}"
        )

        # ====================================================
        # STEP 2
        # HTTP 200
        # ====================================================

        client_socket.sendall(
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )

        # ====================================================
        # STEP 3
        # BROWSER TLS
        # ====================================================

        try:

            cert_path, key_path = (
                get_cert_for_host(
                    hostname
                )
            )

            ssl_ctx_browser = (
                ssl.SSLContext(
                    ssl.PROTOCOL_TLS_SERVER
                )
            )

            ssl_ctx_browser.load_cert_chain(

                certfile=cert_path,

                keyfile=key_path
            )

            client_socket.settimeout(
                15
            )

            browser_ssl = (
                ssl_ctx_browser.wrap_socket(

                    client_socket,

                    server_side=True
                )
            )

            browser_ssl.settimeout(
                None
            )

            vprint(
                "[SSL] Browser TLS established"
            )

        except Exception as e:

            print(
                f"[SSL ERROR - browser side] "
                f"{e}"
            )

            client_socket.close()

            return

        # ====================================================
        # STEP 4
        # CONNECT TO REAL SERVER
        # ====================================================

        try:

            # Measure TCP connection latency.

            tcp_start = (
                time.perf_counter()
            )

            raw_server_socket = (
                self.connect_server(
                    hostname,
                    port
                )
            )

            tcp_end = (
                time.perf_counter()
            )

            network_latency_ms = (
                tcp_end - tcp_start
            ) * 1000

            raw_server_socket.settimeout(
                15
            )

            session.hostname = (
                hostname
            )

            # =================================================
            # ADAPTIVE MODEL
            # =================================================

            crypto_mode = (
                self._get_crypto_mode()
            )

            if crypto_mode == "PQC Hybrid":

                adaptive_features = (
                    self._build_adaptive_features(

                        hostname,

                        client_hello_size=0,

                        network_latency_ms=(
                            network_latency_ms
                        )
                    )
                )

                selected_algorithm = (
                    self.adaptive_selector.select(

                        hostname,

                        adaptive_features
                    )
                )

            else:

                selected_algorithm = (
                    "Classical"
                )

            # =================================================
            # BUILD CLIENT HELLO
            # =================================================

            hello_start = (
                time.perf_counter()
            )

            pqc_client_hello = (
                self._build_pqc_client_hello(

                    hostname,

                    session,

                    pqc,

                    modifier,

                    selected_algorithm
                    if crypto_mode
                    == "PQC Hybrid"
                    else None
                )
            )

            hello_build_time = (
                time.perf_counter()
                - hello_start
            ) * 1000

            print(
                f"[Adaptive] "
                f"ClientHello build time: "
                f"{hello_build_time:.3f} ms"
            )

            # Update adaptive feature size.

            session.adaptive_client_hello_size = (
                len(pqc_client_hello)
            )

            # Send ClientHello.

            handshake_send_start = (
                time.perf_counter()
            )

            raw_server_socket.sendall(
                pqc_client_hello
            )

            # =================================================
            # SERVER HELLO
            # =================================================

            server_record = (
                self.receive_tls_record(
                    raw_server_socket
                )
            )

            handshake_receive_end = (
                time.perf_counter()
            )

            if server_record is None:

                raise ConnectionError(
                    "Server closed connection "
                    "before ServerHello"
                )

            session.server_hello_bytes = (
                server_record
            )

            server_parser = TLSParser(
                server_record
            )

            server_parsed = (
                server_parser.parse()
            )

            if server_parsed.handshake:

                server_processor.process(

                    server_parsed.handshake.body

                )

                handshake_engine.compute()

                reporter.print_report()

                # ------------------------------------------------
                # Store handshake observation
                # ------------------------------------------------

                if (
                    session.total_handshake_time
                    is not None
                ):

                    with self.handshake_history_lock:

                        self.handshake_history.append(

                            session.total_handshake_time
                            * 1000

                        )

                        # Keep only latest 100.

                        if len(
                            self.handshake_history
                        ) > 100:

                            self.handshake_history = (
                                self.handshake_history[-100:]
                            )

                # ------------------------------------------------
                # Log
                # ------------------------------------------------

                with _csv_logger_lock:

                    self.csv_logger.log(
                        session,
                        pqc
                    )

                self.session_exporter.export(
                    session
                )

                self._print_summary_box(

                    hostname,

                    session,

                    pqc,

                    status="SUCCESS"
                )

            else:

                self._print_summary_box(

                    hostname,

                    session,

                    pqc,

                    status=(
                        "FAILED "
                        "(no ServerHello)"
                    )
                )

        except Exception as e:

            print(
                f"[PQC ERROR - server side] "
                f"{hostname}: {e}"
            )

            try:

                browser_ssl.close()

            except Exception:

                pass

            if raw_server_socket:

                try:

                    raw_server_socket.close()

                except Exception:

                    pass

            return

        finally:

            if raw_server_socket:

                try:

                    raw_server_socket.close()

                except Exception:

                    pass

        # ====================================================
        # STEP 6
        # ACTUAL SERVER TLS
        # ====================================================

        data_server_socket = None

        try:

            ssl_ctx_server = (
                ssl.SSLContext(
                    ssl.PROTOCOL_TLS_CLIENT
                )
            )

            ssl_ctx_server.check_hostname = True

            ssl_ctx_server.verify_mode = (
                ssl.CERT_REQUIRED
            )

            # ------------------------------------------------
            # Certificate verification
            # ------------------------------------------------

            try:

                import certifi

                ssl_ctx_server.load_verify_locations(

                    cafile=certifi.where()

                )

                vprint(
                    "[SSL] Using certifi CA bundle: "
                    f"{certifi.where()}"
                )

            except ImportError:

                print(
                    "[SSL WARNING] certifi not "
                    "installed; using OS CA store."
                )

            # ------------------------------------------------
            # Fresh connection for actual data
            # ------------------------------------------------

            data_server_socket = (
                self.connect_server(
                    hostname,
                    port
                )
            )

            server_ssl = (
                ssl_ctx_server.wrap_socket(

                    data_server_socket,

                    server_hostname=hostname
                )
            )

            vprint(
                "[SSL] Server TLS established "
                "for data transfer"
            )

        except Exception as e:

            print(
                f"[SSL ERROR - server data] "
                f"{e}"
            )

            try:

                browser_ssl.close()

            except Exception:

                pass

            try:

                if data_server_socket:

                    data_server_socket.close()

            except Exception:

                pass

            return

        # ====================================================
        # STEP 7
        # APPLICATION DATA FORWARDING
        # ====================================================

        def forward(
            src,
            dst,
            label
        ):

            try:

                while True:

                    data = src.recv(
                        8192
                    )

                    if not data:

                        break

                    dst.sendall(
                        data
                    )

            except Exception:

                pass

            finally:

                try:

                    src.close()

                except Exception:

                    pass

                try:

                    dst.close()

                except Exception:

                    pass

        t1 = threading.Thread(

            target=forward,

            args=(
                browser_ssl,
                server_ssl,
                "browser→server"
            )
        )

        t2 = threading.Thread(

            target=forward,

            args=(
                server_ssl,
                browser_ssl,
                "server→browser"
            )
        )

        t1.start()

        t2.start()

        t1.join()

        t2.join()

        print(
            f"[DONE] Connection closed: "
            f"{hostname}"
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    proxy = TLSProxy()

    proxy.start()
