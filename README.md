<img width="1920" height="1080" alt="1" src="https://github.com/user-attachments/assets/0384478d-24d8-467e-b40b-63af13307a97" /># 🛡️ ZenithBrowser — Adaptive Post-Quantum Cryptography Web Browser

> **An experimental web browser with an integrated TLS proxy, hybrid post-quantum key exchange, TLS 1.3 handshake analysis, performance measurement, and a Random Forest-based adaptive cryptographic selection model.**

---

## 📌 Overview

**ZenithBrowser** is an experimental web browser developed to study and demonstrate the integration of **Post-Quantum Cryptography (PQC)** into modern web communication.

The project was developed from scratch with the goal of understanding what happens inside a browser during a secure HTTPS connection and investigating how **post-quantum key exchange** can be integrated into the TLS handshake.

The project combines:

* 🌐 A custom Python-based web browser
* 🔐 A local TLS interception proxy
* 🔑 Classical **X25519** key exchange
* 🛡️ Post-quantum **ML-KEM-768**
* 🔗 Hybrid **X25519 + ML-KEM-768** key exchange
* 📡 TLS 1.3 ClientHello and ServerHello processing
* 🧩 Custom TLS message parsing and serialization
* 🔬 Handshake performance measurement
* 📊 Bandwidth and cryptographic statistics collection
* 🤖 A **Random Forest-based adaptive cryptographic model**
* 📁 CSV-based experimental data logging
* 📈 Classical vs PQC performance comparison

Rather than simply using an existing browser and calling a cryptographic library, this project implements the important components required to **observe, modify, analyze, and measure the TLS handshake**.

---

# 🎯 Project Motivation

Modern public-key cryptography used by HTTPS, such as elliptic-curve cryptography, is considered secure against classical computers. However, sufficiently powerful quantum computers could threaten widely used public-key cryptographic algorithms.

This creates the need for **Post-Quantum Cryptography (PQC)**.

The main question explored by this project is:

> **Can post-quantum cryptography be integrated into browser-based HTTPS communication while measuring and adapting to its performance overhead?**

The project therefore focuses on three major areas:

1. Understanding the existing TLS 1.3 handshake.
2. Integrating **ML-KEM-768** with classical X25519 to create a hybrid key exchange.
3. Using measured network and cryptographic performance to support adaptive cryptographic selection.

---

# 🏗️ High-Level Architecture

The overall architecture of ZenithBrowser can be represented as:

```text
                         ┌───────────────────────┐
                         │      ZenithBrowser    │
                         │   Custom Web Browser  │
                         └───────────┬───────────┘
                                     │
                                     │ HTTPS / CONNECT
                                     ▼
                         ┌───────────────────────┐
                         │      TLS Proxy        │
                         │                       │
                         │  ClientHello Builder  │
                         │  ClientHello Modifier │
                         │  TLS Parser           │
                         │  TLS Serializer       │
                         │  Handshake Engine     │
                         └───────────┬───────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
             Classical TLS                     PQC Hybrid TLS
              X25519 only                  X25519 + ML-KEM-768
                    │                                 │
                    └────────────────┬────────────────┘
                                     ▼
                         ┌───────────────────────┐
                         │    Real Web Server    │
                         │   TLS 1.3 Endpoint    │
                         └───────────────────────┘
                                     │
                                     ▼
                              HTTPS Application
                                  Data
```

---

# 🌐 1. Building Our Own Web Browser

The project begins with **ZenithBrowser**, a custom browser application written in Python.

The browser provides the basic functionality required to:

* Enter a URL
* Connect to websites
* Send HTTP/HTTPS requests
* Display received web content
* Maintain browsing history
* Display browser controls
* Support browser configuration
* Communicate through the local TLS proxy

The browser acts as the user-facing component of the project.

Instead of modifying an existing commercial browser internally, the project provides our own controlled environment where the HTTPS communication path can be studied.

---

# 🔐 2. TLS Proxy Architecture

A major component of the project is the custom TLS proxy.

The proxy operates between ZenithBrowser and the destination web server.

```text
ZenithBrowser
      │
      │ HTTPS
      ▼
 Local TLS Proxy
      │
      │ Modified TLS handshake
      ▼
 Real Web Server
```

The proxy allows us to inspect and modify TLS handshake messages before they reach the destination server.

This provides the foundation for experimenting with post-quantum key exchange.

---

# 🔄 3. HTTPS CONNECT Handling

When the browser accesses an HTTPS website through the proxy, it first establishes a TCP tunnel using the HTTP `CONNECT` method.

The proxy receives a request such as:

```text
CONNECT example.com:443 HTTP/1.1
```

The proxy responds with:

```text
HTTP/1.1 200 Connection Established
```

After this, the browser can begin TLS communication through the established tunnel.

The proxy then takes responsibility for establishing its own TLS connection with the actual destination server.

---

# 🔑 4. Classical TLS Baseline — X25519

Before introducing post-quantum cryptography, the project establishes a **classical TLS baseline**.

The primary classical key exchange mechanism used is:

**X25519**

X25519 is widely used for elliptic-curve Diffie-Hellman key exchange in TLS 1.3.

The project generates an X25519 key pair and constructs a TLS KeyShare entry containing the public key.

The classical flow is:

```text
Client
  │
  │ X25519 Public Key
  ▼
Server
  │
  │ X25519 Public Key
  ▼
Client
  │
  ▼
Shared Secret
```

This classical implementation provides the baseline against which the hybrid PQC implementation can be measured.

---

# 🛡️ 5. Post-Quantum Cryptography — ML-KEM-768

The project integrates:

**ML-KEM-768**

ML-KEM is the standardized post-quantum Key Encapsulation Mechanism derived from the CRYSTALS-Kyber family.

The project uses the `liboqs`/Open Quantum Safe ecosystem through Python bindings.

The ML-KEM process consists of:

```text
Key Generation
      ↓
Public Key
      ↓
Encapsulation
      ↓
Ciphertext + Shared Secret
      ↓
Decapsulation
      ↓
Shared Secret
```

The implementation generates an ML-KEM key pair and stores the required private key material for later decapsulation.

---

# 🔗 6. Hybrid X25519 + ML-KEM-768 Key Exchange

One of the most important components of the project is the **hybrid key exchange**.

Instead of relying exclusively on either classical or post-quantum cryptography, the project combines:

```text
X25519
   +
ML-KEM-768
   ↓
Hybrid Key Exchange
```

The hybrid public key consists of both components.

Conceptually:

```text
Hybrid Public Key

┌────────────────────┬─────────────────────┐
│     X25519         │     ML-KEM-768      │
│    Public Key      │     Public Key      │
└────────────────────┴─────────────────────┘
```

The project keeps track of:

* X25519 public key size
* ML-KEM public key size
* Hybrid public key size
* ML-KEM ciphertext size
* Combined hybrid secret size

This allows the additional bandwidth overhead introduced by PQC to be measured.

---

# 🧩 7. ClientHello Modification

The `ClientHelloModifier` is responsible for modifying the TLS ClientHello message to introduce the hybrid key exchange.

The original ClientHello contains the classical X25519 configuration.

The modifier adds the hybrid group when PQC mode is enabled.

### Supported Groups

The supported groups extension is modified so that the hybrid group is inserted after X25519.

Conceptually:

```text
Before:

X25519


After:

X25519
X25519MLKEM768
```

This allows the server to see that the client supports the hybrid group.

---

# 🔑 8. Hybrid KeyShare Modification

The KeyShare extension is also modified.

The original KeyShare contains:

```text
X25519
```

The modified KeyShare contains:

```text
X25519
X25519MLKEM768
```

The hybrid KeyShare contains the combined public key generated by the PQC engine.

The implementation also stores the corresponding private key material inside the TLS session so that it can later be used during shared-secret computation.

---

# ⚙️ 9. PQC Engine

The `PQCEngine` provides the cryptographic functionality required by the browser and proxy.

It manages:

* X25519 key generation
* ML-KEM key generation
* X25519 shared-secret computation
* ML-KEM decapsulation
* Hybrid secret construction
* HKDF operations
* TLS 1.3 key derivation
* Cryptographic statistics

The engine therefore acts as the cryptographic abstraction layer of the project.

---

# 🔐 10. Hybrid Shared Secret

The hybrid exchange produces two independent secrets:

```text
X25519 Shared Secret
          +
ML-KEM Shared Secret
          ↓
Hybrid Shared Secret
```

The project combines the two secrets before proceeding with subsequent key derivation.

This provides the experimental foundation for studying hybrid classical/post-quantum key establishment.

---

# 🔬 11. TLS 1.3 HKDF Processing

TLS 1.3 relies heavily on HKDF for deriving traffic secrets.

The project implements the required HKDF operations, including:

* HKDF-Extract
* HKDF-Expand
* TLS 1.3 HKDF labels
* Derive-Secret operations

The project implements the TLS 1.3 label construction:

```text
"tls13 " + label
```

and constructs the corresponding HKDF label structure before performing expansion.

This allows the project to experiment with TLS 1.3-style secret derivation rather than treating the cryptographic handshake as a black box.

---

# 🤝 12. ServerHello Processing

After sending the ClientHello, the proxy receives the ServerHello from the destination server.

The `ServerHelloProcessor` analyzes the response and extracts important TLS information.

The processor is responsible for identifying information such as:

* Selected TLS version
* Selected cipher suite
* Selected key exchange group
* Server key share
* Hybrid negotiation information

This allows the project to determine whether the server selected the intended key exchange mechanism.

---

# 🧠 13. Custom TLS Parser

The project includes a custom TLS parsing layer.

The parser processes TLS records and handshake messages and extracts their internal structures.

The project handles structures including:

* TLS records
* Handshake messages
* ClientHello
* ServerHello
* Extensions
* Supported Versions
* Supported Groups
* Key Share
* Signature Algorithms
* ALPN
* Server Name
* PSK Key Exchange Modes

This provides much greater visibility into the TLS protocol than simply using a high-level SSL API.

---

# 🏗️ 14. TLS Serializer

After parsing and modifying TLS structures, the project needs to reconstruct valid TLS messages.

The `TLSSerializer` converts the internal Python representations back into raw TLS byte sequences.

The workflow therefore becomes:

```text
Raw TLS Bytes
      ↓
TLS Parser
      ↓
Python TLS Structures
      ↓
Modification
      ↓
TLS Serializer
      ↓
Modified TLS Bytes
```

This parser/serializer architecture is one of the core components enabling the experimental TLS modification.

---

# 🔐 15. TLS Certificate Handling

Because ZenithBrowser communicates through a local interception proxy, the proxy needs to generate certificates for the requested hosts.

The project therefore includes certificate generation functionality.

The certificate subsystem handles:

* Proxy CA
* Per-host certificates
* Private keys
* Certificate generation
* Browser-side TLS establishment

The browser sees a certificate generated by the local proxy while the proxy separately establishes TLS with the actual destination server.

---

# 📡 16. Dual TLS Connection Architecture

The project uses two TLS connections.

### Browser → Proxy

```text
ZenithBrowser
      ↓
Local Proxy
```

### Proxy → Real Server

```text
Local Proxy
      ↓
Real Website
```

This architecture allows the proxy to inspect and experimentally modify the handshake with the destination server while maintaining a TLS connection with the browser.

---

# 📊 17. Performance Measurement

A major objective of the project is not simply to implement PQC but also to **measure its overhead**.

The project collects performance information during the handshake.

Important measurements include:

* Total handshake time
* ML-KEM processing time
* X25519 key size
* ML-KEM public-key size
* Hybrid public-key size
* ML-KEM ciphertext size
* Hybrid secret size
* Selected cipher suite
* Selected key exchange group

This allows classical and PQC modes to be compared quantitatively.

---

# 📈 18. Bandwidth Analysis

PQC introduces additional communication overhead because post-quantum keys and ciphertexts are generally larger than classical elliptic-curve keys.

The project therefore records the relevant cryptographic sizes.

For example:

```text
Classical:

X25519 Public Key
        ↓
      32 bytes


Hybrid:

X25519 Public Key
        +
ML-KEM-768 Public Key
        ↓
Larger ClientHello
```

Similarly, ML-KEM ciphertext contributes additional data during the key exchange.

The project records these values for experimental analysis.

---

# 📝 19. CSV Experimental Logging

The project includes a CSV-based logging system.

Handshake measurements are stored in:

```text
results.csv
```

The collected information can be used for:

* Classical vs PQC comparison
* Performance analysis
* Bandwidth analysis
* Model training
* Experimental evaluation
* Generating research results

Keeping the measurements in CSV format also makes the data easy to analyze using Python, Pandas, Excel, or other statistical tools.

---

# ☁️ 20. Cloudflare Experimental Measurements

The project also includes recorded experimental results for Cloudflare:

```text
cloudflare_classical.txt
cloudflare_pqc.txt
```

These files provide measurements for comparing classical and PQC-related communication behavior.

The collected results form part of the experimental dataset used during the development and evaluation of the project.

---

# 🤖 21. Adaptive Cryptographic Model

A major extension of the project is the **adaptive cryptographic selection model**.

Instead of always using one cryptographic mode, the project investigates whether the cryptographic configuration can be selected based on observed network and performance characteristics.

The adaptive system uses measured parameters from the environment and handshake behavior.

The project implements a:

## 🌲 Random Forest Classifier

The adaptive model uses **Random Forest** as the machine-learning algorithm.

Random Forest was selected because it can handle multiple input features and capture nonlinear relationships between network/performance conditions and the desired cryptographic mode.

The general workflow is:

```text
Measured Network / TLS Features
             ↓
       Feature Processing
             ↓
       Random Forest Model
             ↓
    Cryptographic Decision
             ↓
 ┌───────────────────────────┐
 │ Classical TLS             │
 │            OR             │
 │ PQC Hybrid TLS            │
 └───────────────────────────┘
```

The adaptive model therefore extends the project beyond a static PQC implementation and introduces an experimental machine-learning-based decision layer.

---

# 🧠 22. Adaptive Model Training

The project contains:

```text
adaptive_model.py
train_adaptive_model.py
```

The training pipeline uses experimental measurements to build the Random Forest model.

The model is intended to learn relationships between observed conditions and the appropriate cryptographic configuration.

The trained model is used by the adaptive component to make cryptographic-selection decisions.

The project therefore combines:

```text
Networking
      +
TLS
      +
Cryptography
      +
Post-Quantum Cryptography
      +
Machine Learning
```

---

# 🔄 23. Classical vs PQC Modes

The browser/proxy architecture supports two primary modes.

### Classical TLS

```text
X25519
   ↓
TLS 1.3
```

### PQC Hybrid

```text
X25519
   +
ML-KEM-768
   ↓
Hybrid TLS Experiment
```

The selected mode is communicated through the browser's configuration and read by the proxy.

This allows the same browser/proxy architecture to perform controlled comparisons.

---

# ⚙️ 24. Runtime Configuration

The project uses configuration files to communicate runtime settings between components.

For example:

```text
settings.json
```

The proxy reads the selected cryptographic mode before creating the ClientHello.

This allows the browser UI and proxy process to operate as separate components while still sharing the selected cryptographic configuration.

---

# 🧵 25. Multi-Connection Browser Support

Real browsers create many simultaneous network connections while loading a single webpage.

The proxy therefore uses a separate thread for each incoming browser connection.

The architecture is:

```text
                 ┌── Connection 1
Browser ────────┼── Connection 2
                 ├── Connection 3
                 ├── Connection 4
                 └── Connection N
                         ↓
                  Separate Threads
```

Each connection maintains its own:

* TLS session
* PQC engine
* ClientHello modifier
* Handshake engine
* ServerHello processor
* Performance state

This prevents cryptographic and TLS state from different connections from interfering with one another.

---

# 🛠️ 26. Project Components

The main source files are organized around different responsibilities.

| File                       | Purpose                                       |
| -------------------------- | --------------------------------------------- |
| `zenithbrowser.py`         | Main browser implementation                   |
| `zenithbrowser_01.py`      | Browser interface/configuration functionality |
| `proxy.py`                 | Main TLS proxy                                |
| `pqc_proxy.py`             | PQC proxy-related functionality               |
| `pqc_engine.py`            | X25519 and ML-KEM cryptographic engine        |
| `clienthello_modifier.py`  | Modifies ClientHello for hybrid PQC           |
| `serverhello_processor.py` | Processes ServerHello                         |
| `handshake_engine.py`      | TLS handshake processing                      |
| `tls_parser.py`            | TLS message parser                            |
| `tls_serializer.py`        | TLS message serializer                        |
| `tls_structures.py`        | TLS protocol data structures                  |
| `tls_constants.py`         | TLS constants and identifiers                 |
| `tls_builder.py`           | TLS message construction                      |
| `tls_printer.py`           | TLS debugging/printing                        |
| `tls_session.py`           | Per-connection TLS session state              |
| `tls_utils.py`             | TLS utility functions                         |
| `cert_generator.py`        | Proxy certificate generation                  |
| `x509_parser.py`           | X.509 parsing                                 |
| `csv_logger.py`            | Experimental CSV logging                      |
| `performance_reporter.py`  | Performance reporting                         |
| `session_exporter.py`      | Session/result export                         |
| `adaptive_model.py`        | Adaptive Random Forest model                  |
| `train_adaptive_model.py`  | Adaptive model training                       |
| `analyzer.py`              | Experimental result analysis                  |
| `cipher_names.py`          | Cipher-suite naming                           |
| `debug_config.py`          | Debug output configuration                    |
| `kyber_simulation/`        | ML-KEM/Kyber simulation experiments           |
| `codebase.txt`             | Project/code documentation and reference      |

---

# 🧰 27. Technologies Used

### Programming Languages

* Python
* C

### Cryptography

* X25519
* ML-KEM-768
* TLS 1.3
* HKDF
* SHA-256
* HMAC
* X.509

### Post-Quantum Cryptography

* ML-KEM
* Open Quantum Safe
* liboqs

### Networking

* TCP/IP
* HTTP CONNECT
* HTTPS
* TLS
* TLS record processing
* TLS handshake processing

### Machine Learning

* Random Forest
* Supervised learning
* Feature-based cryptographic selection

### Data Analysis

* CSV
* Experimental logging
* Performance measurement
* Comparative analysis

---

# 🧪 28. Experimental Workflow

The complete experimental workflow is:

```text
             Start ZenithBrowser
                     │
                     ▼
               Enter Website
                     │
                     ▼
              HTTP CONNECT
                     │
                     ▼
                TLS Proxy
                     │
                     ▼
          Select Crypto Mode
                     │
          ┌──────────┴──────────┐
          │                     │
          ▼                     ▼
     Classical TLS         PQC Hybrid
       X25519             X25519 + ML-KEM
          │                     │
          └──────────┬──────────┘
                     ▼
              Build ClientHello
                     │
                     ▼
              Send to Server
                     │
                     ▼
              Receive ServerHello
                     │
                     ▼
             Process Handshake
                     │
                     ▼
           Measure Performance
                     │
                     ▼
              Log Statistics
                     │
                     ▼
              results.csv
                     │
                     ▼
             Adaptive Analysis
                     │
                     ▼
              Random Forest
```

---

# 📊 29. Experimental Outputs

The project generates and records multiple types of experimental information.

### TLS Information

* TLS version
* Cipher suite
* Key exchange group

### Cryptographic Information

* X25519 public-key size
* ML-KEM public-key size
* Hybrid public-key size
* ML-KEM ciphertext size
* Hybrid secret size

### Performance Information

* Total handshake duration
* ML-KEM processing time
* Cryptographic operation timings

### Experimental Data

* Classical TLS measurements
* PQC measurements
* Cloudflare measurements
* CSV-based results

These outputs make it possible to quantitatively evaluate the effect of introducing post-quantum cryptography.

# 📸 30. Screenshots
 ZenithBrowser

<img width="1920" height="1080" alt="1" src="https://github.com/user-attachments/assets/d4fe5de9-e0cd-4633-bbf0-22bf6962b513" />
<img width="1920" height="1080" alt="2" src="https://github.com/user-attachments/assets/a51a7282-31cc-4b3d-83af-46640233db34" />
<img width="1920" height="1080" alt="3" src="https://github.com/user-attachments/assets/143222f0-f839-4f25-aa0d-50dc5ec5967c" />
 <img width="1920" height="1080" alt="4" src="https://github.com/user-attachments/assets/3e1d157c-0d00-431a-bf39-c6b0b79fb26e" />

# 🚀 31. Running the Project

## 1. Clone the repository

```bash
git clone https://github.com/Divyank7436/pqc-adaptive-browser.git
cd pqc-adaptive-browser
```

## 2. Create a Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install Python dependencies

Install the required Python packages according to the project's environment and cryptographic dependencies.

The project requires the Python bindings for the Open Quantum Safe cryptographic library as well as the required TLS, cryptography, browser, and machine-learning dependencies.

## 4. Build/configure liboqs

The project uses **liboqs** for post-quantum cryptographic functionality.

The required liboqs environment must be available before running the PQC components.

## 5. Run the browser

```bash
python3 zenithbrowser.py
```

or use the appropriate browser entry point:

```bash
python3 zenithbrowser_01.py
```

## 6. Run the proxy

```bash
python3 proxy.py
```

The proxy listens locally and handles the browser's HTTPS connections.

---

# 📁 32. Experimental Data

The repository contains selected experimental outputs such as:

```text
results.csv
cloudflare_classical.txt
cloudflare_pqc.txt
final_results_adaptive_model.txt
```

These files document measurements and analysis obtained during the development and experimentation process.

The CSV dataset can be further analyzed using Python/Pandas or spreadsheet software.

---

# ⚠️ 33. Current Limitations

This project is an **experimental research/prototyping implementation** rather than a production-ready browser or TLS stack.

Some components are designed specifically for controlled experimentation with TLS and PQC rather than complete standards-compliant deployment.

The hybrid TLS implementation should therefore be treated as an experimental platform for studying PQC integration, performance, and adaptive cryptographic selection.

---

# 🔮 34. Future Work

Possible future extensions include:

* Improving standards-compliant hybrid TLS interoperability.
* Expanding adaptive-model evaluation with larger datasets.
* Supporting additional PQC algorithms.
* Improving browser/proxy performance.
* Performing larger-scale network experiments.

---

# 📚 35. Project Summary

ZenithBrowser combines several areas of computer science and cybersecurity into a single experimental platform:

```text
                    ZenithBrowser
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
      Browser          Networking      Security
        │                │                │
        │                ▼                ▼
        │              TLS 1.3          X25519
        │                │                │
        │                ▼                ▼
        │          TLS Handshake       ML-KEM-768
        │                │                │
        └────────────────┼────────────────┘
                         │
                         ▼
                 Hybrid Key Exchange
                         │
                         ▼
                 Performance Analysis
                         │
                         ▼
                 Experimental Dataset
                         │
                         ▼
                 Random Forest Model
                         │
                         ▼
              Adaptive Crypto Selection
```

The result is an end-to-end experimental system that brings together:

**Web Browsers + Networking + TLS + Cryptography + Post-Quantum Cryptography + Machine Learning + Performance Analysis**

The project provides a practical environment for understanding how post-quantum cryptography can be investigated and integrated into future secure web communication systems.
