# 💎 Project Amethyst: Behavioral Anti-Ransomware & EDR Engine

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Security](https://img.shields.io/badge/Security-Blue%20Team-shield.svg)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1486-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**Project Amethyst** is a lightweight, Proof-of-Concept (PoC) Endpoint Detection and Response (EDR) engine designed to detect and mitigate Ransomware attacks in real-time. By utilizing **Shannon Entropy** analysis, dynamic process monitoring, and proactive kill-switches, Amethyst identifies cryptographic I/O operations and terminates malicious processes before significant data loss occurs.

This project also includes an integrated **Advanced Persistent Threat (APT) Simulator (Red Team)** to test the detection capabilities using evasion techniques like jitter and polymorphism.

---

## 🛡️ Core Capabilities (Blue Team Engine)

The detection engine (`detector.py`) operates entirely in user-space, simulating enterprise-grade EDR behavior:

* **Mathematical Cryptography Detection:** Calculates real-time Shannon Entropy of file modifications to distinguish between normal text/data writes and encrypted ransomware payloads.
* **LOLBins Prioritization:** Optimizes process scanning (O(1) approach) by prioritizing high-risk Living-Off-The-Land Binaries (e.g., `python.exe`, `powershell.exe`, `cmd.exe`) to ensure a 100% catch rate against rapid execution.
* **Forensic Evidence Collection:** Extracts the original executable path and generates **SHA-256 Hashes** of the malicious process for Threat Intelligence (CTI) querying.
* **Network (C2) Tracking:** Scans the active TCP/IP stack to identify if the malicious process is communicating with an external Command and Control (C2) server.
* **Active Mitigation (Kill-Switch):** Automatically terminates the offending process (`proc.kill()`) the millisecond a high-entropy write is detected.

## 🥷 Adversary Simulation (Red Team Engine)

The built-in threat simulator (`threat_simulator.py`) mimics modern ransomware behavior to test the Blue Team engine:

* **AES-Fernet Encryption:** Generates and encrypts dummy data on the fly.
* **Polymorphic File Extensions:** Rapidly changes target file extensions (`.bin`, `.dat`, `.tmp`, `.cache`) to bypass static File Integrity Monitoring (FIM) signatures.
* **Jitter (Evasion):** Uses randomized sleep intervals between I/O operations to avoid periodic beaconing detection.

---

## 🧮 Mathematical Foundation: Shannon Entropy

Project Amethyst does not rely on static file signatures. Instead, it detects the mathematical randomness of encrypted data. The entropy $H$ of a file is calculated using the Shannon Entropy formula:

$$H(X) = - \sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

* Standard text files typically score between **3.0 - 5.0**.
* Compressed or encrypted files (AES/RSA) score between **7.0 - 8.0**.
* Amethyst triggers a forensic hunt when the I/O entropy crosses the defined threshold (Default: `5.5` for Base64 encoded ciphertexts).

---

## 🎯 MITRE ATT&CK® Mapping

| Tactic | Technique ID | Technique Name | Mitigation Approach |
| :--- | :--- | :--- | :--- |
| **Impact** | T1486 | Data Encrypted for Impact | Entropy-based I/O monitoring and process termination. |
| **Defense Evasion** | T1036 | Masquerading | Polymorphic extension tracking. |
| **Command and Control** | T1071 | Application Layer Protocol | Real-time TCP/IP process connection extraction. |

---

## ⚙️ Installation & Prerequisites

1. Clone the repository:

    ```bash

   git clone [https://github.com/SuatKoray/Amethyst.git](https://github.com/SuatKoray/Amethyst.git)
   cd Amethyst
   
   ```
   
2. Install the required dependencies:

```bash

pip install psutil watchdog cryptography
```

🚀 Usage Guide
To witness the real-time "Purple Team" collision, you need to run both engines simultaneously.

1. Start the Blue Team (Defender)
Open your first terminal and start the monitoring engine:

```bash

python BlueTeam/detector.py
The engine will initialize, establish the entropy threshold, and begin monitoring the target directory.
```

2. Start the Red Team (Adversary)
Open a second terminal and launch the ransomware simulator:

```bash

python RedTeam/threat_simulator.py
```

3. Observe the Mitigation
Watch the Blue Team terminal. Within seconds, it will detect the high-entropy encryption, extract the process ID and SHA-256 hash, and instantly terminate the Red Team terminal.

Alerts are automatically logged in JSON format to blue_team_alerts.json for SIEM integration.

Disclaimer: This project is developed strictly for educational purposes, defensive engineering research, and malware analysis PoC. Do not use the simulator outside of authorized, isolated environments.