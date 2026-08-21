import json
import os


class SessionExporter:

    def export(self, session):

        os.makedirs("proxy_logs", exist_ok=True)

        data = {

            "host": session.hostname,

            "tls_version": session.tls_version,

            "cipher_suite": session.cipher_suite,

            "key_exchange": session.group_name,

            "status": session.status,

            "handshake_time_ms": round(
                session.total_handshake_time * 1000,
                3
            ),

            "hybrid_public_key": len(session.hybrid_public)
            if session.hybrid_public
            else 0,

            "mlkem_public_key": len(session.mlkem_public)
            if session.mlkem_public
            else 0,

            "x25519_public_key": len(session.x25519_public)
            if session.x25519_public
            else 0

        }

        with open(
            "proxy_logs/current_session.json",
            "w"
        ) as f:

            json.dump(
                data,
                f,
                indent=4
            )

        print()
        print("========== SESSION EXPORTED ==========")
        print("Saved -> proxy_logs/current_session.json")
        print()


