#!/usr/bin/env python3
import argparse
import ipaddress
import shlex
import subprocess
import sys
import time
from pathlib import Path

def read_targets(path: Path):
    """Read targets from file; supports comments, blank lines, and CIDR expansion."""
    if not path.exists():
        print(f"[!] Input file not found: {path}")
        sys.exit(1)
    targets = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            targets.extend([str(h) for h in net.hosts()])
        except ValueError:
            targets.append(line)
    seen, unique = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique

def sanitize_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", ".", "_") else "_" for c in s)

def check_nmap():
    try:
        subprocess.run(["nmap", "-V"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Nmap not found in PATH. Install it from https://nmap.org/download.html")
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Batch Nmap scanner: per-IP .txt reports, CIDR expansion, run logs."
    )
    parser.add_argument("-i", "--input", required=True, help="Input file with IPs/hosts/CIDRs")
    parser.add_argument("--outdir", default=None, help="Custom output directory (default: reports_<timestamp>)")
    parser.add_argument("--nflag", action="store_true",
                        help="Place this and then any nmap flags afterwards, e.g.: --nflag -sV -Pn")
    args, _unknown = parser.parse_known_args()
    return args

def capture_nmap_flags():
    """Capture all tokens after --nflag from sys.argv (unquoted)."""
    if "--nflag" not in sys.argv:
        return None
    idx = sys.argv.index("--nflag")
    flags = sys.argv[idx+1:]
    return flags if flags else None

def main():
    args = parse_args()
    raw_flags = capture_nmap_flags()

    # Defaults if no custom flags
    nmap_flags = raw_flags if raw_flags is not None else ["-sV", "-Pn", "-T4", "-p-"]

    # Ensure --nflag is last
    for tok in nmap_flags:
        if tok in ("-i", "--input", "--outdir", "--nflag"):
            print("[!] Place --nflag at the END of the command. Everything after it is treated as nmap flags.")
            sys.exit(2)

    ip_file = Path(args.input)
    targets = read_targets(ip_file)
    if not targets:
        print("[!] No valid targets found in input file.")
        sys.exit(1)

    ts = time.strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.outdir) if args.outdir else Path(f"reports_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    check_nmap()

    print(f"[+] Targets loaded: {len(targets)}")
    print(f"[+] Output directory: {out_dir.resolve()}")
    print(f"[+] Using flags: {' '.join(shlex.quote(f) for f in nmap_flags)}")
    print("-" * 60)

    for idx, target in enumerate(targets, 1):
        base_name = sanitize_filename(target)
        out_file = out_dir / f"{base_name}.txt"

        cmd = ["nmap", *nmap_flags, target]
        print(f"[{idx}/{len(targets)}] Scanning {target} ...")
        print("     " + " ".join(shlex.quote(c) for c in cmd))

        try:
            with open(out_file, "w") as f:
                res = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                print(f"     [OK] Report saved: {out_file}")
            else:
                print(f"     [!] Nmap exit code {res.returncode}. Check {out_file} for partial results.")
        except Exception as e:
            print(f"     [!] Error scanning {target}: {e}")

    print("-" * 60)
    print("[+] Done.")

if __name__ == "__main__":
    main()
