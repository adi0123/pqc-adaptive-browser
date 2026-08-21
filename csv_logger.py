import csv
import os


class CSVLogger:

    def __init__(self, filename="results.csv"):

        self.filename = filename

        if not os.path.exists(filename):

            with open(filename, "w", newline="") as file:

                writer = csv.writer(file)

                writer.writerow([
                    "Run",
                    "X25519_ms",
                    "MLKEM_ms",
                    "Hybrid_ms",
                    "KeySchedule_ms",
                    "Handshake_ms",
                    "X25519_Public",
                    "MLKEM_Public",
                    "Ciphertext",
                    "Hybrid_Public",
                    "Hybrid_Secret"
                ])

        self.run_number = self.count_runs()

    def count_runs(self):

        with open(self.filename) as file:

            return max(sum(1 for _ in file) - 1, 0)

    def log(self, session, pqc):

        stats = pqc.get_statistics()

        self.run_number += 1

        with open(self.filename, "a", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([

                self.run_number,

                session.time_x25519 * 1000,

                session.time_mlkem * 1000,

                session.time_hybrid * 1000,

                session.time_key_schedule * 1000,

                session.total_handshake_time * 1000,

                stats.get("x25519_public", 0),

                stats.get("mlkem_public", 0),

                stats.get("ciphertext", 0),

                stats.get("hybrid_public", 0),

                stats.get("hybrid_secret", 0)

            ])
