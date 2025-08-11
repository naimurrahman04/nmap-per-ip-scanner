# Nmap Per-IP Interactive Scanner

This Python script reads IP addresses (or hostnames) from a text file, prompts the user for **Nmap flags** per IP, and generates **separate report files** for each scan.  
It is designed for penetration testing workflows where different targets may require different scan parameters.

---

## Features
- Reads targets from `ip.txt` (one per line, supports comments with `#`).
- Asks for Nmap flags individually for each IP.
- Optional flag reuse mode (`--reuse`) to save typing for similar scans.
- Generates separate `.nmap`, `.gnmap`, and `.xml` reports per target in a specified folder.
- Cross-platform (Linux, macOS, Windows with Python 3).

---

## Requirements
- **Python 3.6+**
- [Nmap](https://nmap.org/download.html) installed and available in your system `PATH`.

---

## Installation
Clone or download the repository:

```bash
git clone https://github.com/yourusername/nmap-per-ip-scanner.git
cd nmap-per-ip-scanner

nmap --version
# Example targets
192.168.1.1
10.0.0.5
scanme.nmap.org

python3 scan_per_ip.py
python3 scan_per_ip.py -i targets.txt -o myreports --reuse
