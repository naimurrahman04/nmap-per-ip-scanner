#!/usr/bin/env python3
import subprocess
import sys
import shlex
import time
from pathlib import Path
import ipaddress
import argparse

def read_targets(path: Path):
    """Read targets from file; supports comments and CIDR expansion."""
    targets = []
    if not path.exists():
        print(f"[!] {path} not found.")
        sys.exit(1)
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            targets.extend([str(h) for h in net.hosts()])
        except ValueError:
            targets.append(line)
    seen = set()
    return [t for t in targets if not (t in seen or seen.add(t))]

def sanitize_filename(s: str) -> str:
    """Make a safe filename from an IP/hostname."""
    return "".join(c if c.isalnum() or c in ("-", ".", "_") else "_" for c in s)

def check_nmap():
    try:
        subprocess.run(["nmap", "-V"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Nmap is not installed or not in PATH. Install it first: https://nmap.org/download.html")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Batch Nmap scanner with per-IP reports")
    parser.add_argument("-i", "--input", required=True, help="Input file containing IPs/hosts/CIDRs")
    parser.add_argument("--nflag", default="-sV -Pn -T4 -p-", help="Nmap flags to use (default: '-sV -Pn -T4 -p-')")
    parser.add_argument("--timeout", default="10m", help="Host timeout (default: 10m)")
    args = parser.parse_args()

    ip_file = Path(args.input)
    targets = read_targets(ip_file)
    if not targets:
        print("[!] No targets found in file.")
        sys.exit(1)

    ts = time.strftime("%Y%m%d_%H%M%S")
    out_dir = Path(f"reports_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    check_nmap()

    print(f"[+] Targets loaded: {len(targets)}")
    print(f"[+] Output directory: {out_dir.resolve()}")
    print(f"[+] Using flags: {args.nflag}")
    print(f"[+] Host timeout: {args.timeout}")
    print("-" * 60)

    try:
        flag_list = shlex.split(args.nflag)
    except ValueError as e:
        print(f"[!] Could not parse flags: {e}")
        sys.exit(1)

    for idx, target in enumerate(targets, 1):
        base_name = sanitize_filename(target)
        out_base = out_dir / base_name

        cmd = ["nmap", *flag_list, "--host-timeout", args.timeout, "-oA", str(out_base), target]
        print(f"[{idx}/{len(targets)}] Scanning {target} ...")
        print("     " + " ".join(shlex.quote(c) for c in cmd))

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            (out_dir / f"{base_name}.runlog.txt").write_text(
                "COMMAND:\n" + " ".join(shlex.quote(c) for c in cmd) +
                "\n\nSTDOUT:\n" + res.stdout +
                "\n\nSTDERR:\n" + res.stderr
            )
            if res.returncode == 0:
                print(f"     [OK] Reports saved as {out_base}.nmap/.gnmap/.xml")
            else:
                print(f"     [!] Nmap exited with code {res.returncode}. See {base_name}.runlog.txt for details.")
        except Exception as e:
            print(f"     [!] Error scanning {target}: {e}")

    print("-" * 60)
    print("[+] Done.")

if __name__ == "__main__":
    main()
