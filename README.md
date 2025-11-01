# Batch Nmap Scanner (Pause / Resume + Parallel Scans + Metadata Logging)

This script automates large-scale **Nmap** scanning with the ability to:

- Load targets from **IP list**, **hostnames**, or **CIDR ranges**
- **Pause and resume** scans safely at any time (Ctrl-C)
- Run scans **sequentially or in parallel** (`--workers`)
- Save **full scan output** + machine-readable **metadata JSON**
- Skip already-scanned hosts (or force re-scan with `--overwrite`)
- Record consistent scan state in `scan_progress.json`

Useful for **VAPT**, **asset discovery**, **shadow IT investigations**, and **internal infrastructure audits**.

---

## Features

| Feature | Description |
|--------|-------------|
| CIDR expansion | Automatically expands network ranges to host IPs |
| Pause / Resume | Safe resume using `--resume scan_progress.json` |
| Parallel scanning | Adjustable concurrency via `--workers` |
| Per-target timeout | Avoids scans hanging indefinitely |
| Output logging | `.txt` full Nmap output + `.json` result metadata |
| Run index | `index.json` records each scan session summary |
| Skip existing results | Prevents duplicate work *(default)* |

---

## Requirements

- Python **3.8+**
- `nmap` installed and in `PATH`

Check if Nmap is installed:

```bash
nmap -V
---
## Install on Debian/Ubuntu:

sudo apt-get update && sudo apt-get install nmap -y

## Scan from a file
---
python3 scan_per_ip.py -i targets.txt

## Use custom Nmap flags
---
python3 scan_per_ip.py -i targets.txt --nflag "-sV -Pn -T3 -p 22,80,443"

## Provide flags after
---
python3 scan_per_ip.py -i targets.txt -- -sV -Pn -T4 -p-

## Run multiple scans in parallel
python3 scan_per_ip.py -i targets.txt --workers 3

## Set per-target timeout (e.g., 20 minutes)

python3 scan_per_ip.py -i targets.txt --timeout-sec 1200

##Resume a paused scan
python3 scan_per_ip.py --resume reports_2025xxxx_xxxxxx/scan_progress.json

Force overwrite previously completed results
python3 scan_per_ip.py -i targets.txt --overwrite

Pipe targets from another tool
cat cidr_list.txt | python3 scan_per_ip.py --workers 2


