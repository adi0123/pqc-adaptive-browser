import socket
import threading
import subprocess
import os
import re
from datetime import datetime

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888

checked_hosts = set()

GROUP_MAP = {
    0x001D: "X25519",
    0x11EC: "X25519MLKEM768",
}

def group_name(group_id):
    return GROUP_MAP.get(group_id, f"Unknown (0x{group_id:04x})")

def determine_status(group):
    if group == 0x11EC:
        return "PQC Protected"

    if group == 0x001D:
        return "Classical TLS"

    return "Negotiation Unknown"

def extract_selected_group(server_hello_text):
    """
    Parses the ServerHello KeyShare extension.

    Returns:

        0x11EC

    or

        0x001D

    or

        None
    """

    return None


def extract_server_hello(output):
    """
    Extract only the ServerHello portion from the OpenSSL -msg output.

    Returns:
        str : ServerHello block
        None : if ServerHello cannot be located
    """

    start = output.find("<<< TLS 1.3, Handshake")

    if start == -1:
        return None

    end = output.find("<<< TLS 1.3, Handshake", start + 1)

    if end == -1:
        return output[start:]

    return output[start:end]

def tls_metadata_scan(host):

    try:

        result = subprocess.run(
            [
                "openssl",
                "s_client",
                "-connect",
                f"{host}:443",
                "-servername",
                host,
                "-groups",
                "X25519MLKEM768:X25519"
            ],
            input="Q\n",
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout + result.stderr
        server_hello = extract_server_hello(output)
        
        print("=" * 80)
        print(output)
        print("=" * 80)
        tls_version = "Unknown"
        cipher_suite = "Unknown"
        selected_group = "Unknown"

        #
        # Extract TLS Version
        #

        tls_match = re.search(
            r"New,\s*(TLSv[0-9.]+)",
            output
        )

        if tls_match:
            tls_version = tls_match.group(1)

        #
        # Extract Cipher Suite
        #

        cipher_match = re.search(
            r"Cipher is ([A-Z0-9_]+)",
            output
        )

        if cipher_match:
            cipher_suite = cipher_match.group(1)

        #
        # Extract Server Temp Key
        #

        group_match = re.search(
            r"Server Temp Key:\s*([^\n\r]+)",
            output
        )

        if group_match:
            selected_group = group_match.group(1).strip()

        #
        # Determine Status
        #

        if "MLKEM" in selected_group.upper():

            status = "PQC Protected"

        elif selected_group != "Unknown":

            status = "Classical TLS"

        else:

            status = "Negotiation Unknown"

        #
        # Save Inventory
        #

        os.makedirs(
            "proxy_logs",
            exist_ok=True
        )

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        with open(
            "proxy_logs/tls_inventory.log",
            "a"
        ) as f:

            f.write(
                "\n"
                "========================================\n"
                f"Timestamp: {timestamp}\n"
                f"Host: {host}\n"
                f"TLS Version: {tls_version}\n"
                f"Cipher Suite: {cipher_suite}\n"
                f"Selected Group: {selected_group}\n"
                f"Status: {status}\n"
                "========================================\n"
            )

        print(
            f"[TLS] {host} | "
            f"{tls_version} | "
            f"{cipher_suite} | "
            f"{selected_group} | "
            f"{status}"
        )

    except Exception as e:

        print(
            "[TLS SCAN ERROR]",
            e
        )

def relay(source, destination):
    try:
        while True:
            data = source.recv(8192)

            if not data:
                break

            destination.sendall(data)

    except:
        pass

    finally:
        source.close()
        destination.close()

def log_connection(host, port):

    os.makedirs(
        "proxy_logs",
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    log_line = (
        f"{timestamp} | "
        f"{host}:{port}\n"
    )

    with open(
        "proxy_logs/connections.log",
        "a"
    ) as f:

        f.write(log_line)

def handle_client(client_socket):

    try:

        request = client_socket.recv(4096).decode(
            errors="ignore"
        )

        first_line = request.split("\r\n")[0]

        print(
            f"[REQUEST] {first_line}"
        )

        if not first_line.startswith(
            "CONNECT"
        ):
            client_socket.close()
            return

        target = first_line.split()[1]

        host, port = target.split(":")

        port = int(port)

        print(
            f"[CONNECT] {host}:{port}"
        )
        
        log_connection(
            host,
            port
        )

        if host not in checked_hosts:

            checked_hosts.add(host)

            threading.Thread(
                target=tls_metadata_scan,
                args=(host,),
                daemon=True
            ).start()
        
        remote_socket = socket.create_connection(
            (host, port)
        )

        client_socket.sendall(
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )

        threading.Thread(
            target=relay,
            args=(client_socket, remote_socket),
            daemon=True
        ).start()

        threading.Thread(
            target=relay,
            args=(remote_socket, client_socket),
            daemon=True
        ).start()

    except Exception as e:

        print(
            "[ERROR]",
            e
        )

        client_socket.close()


def start_proxy():

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
        (LISTEN_HOST, LISTEN_PORT)
    )

    server.listen(100)

    print(
        f"[PROXY] Listening on {LISTEN_HOST}:{LISTEN_PORT}"
    )

    while True:

        client_socket, addr = server.accept()

        print(
            f"[CLIENT] {addr}"
        )

        threading.Thread(
            target=handle_client,
            args=(client_socket,),
            daemon=True
        ).start()


if __name__ == "__main__":
    start_proxy()
