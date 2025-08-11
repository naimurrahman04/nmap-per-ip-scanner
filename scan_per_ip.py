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
    # de-dup preserving order
    seen, uniq = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq

def sanitize_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", ".", "_") else "_" for c in s)

def check_nmap():
    try:
        subprocess.run(["nmap", "-V"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Nmap not found in PATH. Install it from https://nmap.org/download.html")
        sys.exit(1)

def parse_args():
    p = argparse.ArgumentParser(
        description="Batch Nmap scanner: per-IP .txt reports, CIDR expansion, combined stdout+stderr."
    )
    p.add_argument("-i", "--input", required=True, help="Input file with IPs/hosts/CIDRs")
    p.add_argument("--outdir", default=None, help="Custom output directory (default: reports_<timestamp>)")
    # Option A: pass flags as a single quoted string
    p.add_argument("--nflag", default=None, help='Nmap flags as a single string, e.g. "--nflag \'-sV -Pn\'"')
    # Option B: pass flags after -- (no quotes)
    p.add_argument("nmap_args", nargs=argparse.REMAINDER,
                   help="Alternatively, place flags after '--', e.g.: ... -- -sV -Pn")
    return p.parse_args()

def resolve_flags(args):
    # 1) If user provided --nflag "..."
    if args.nflag:
        return shlex.split(args.nflag)
    # 2) Else if user used the '--' separator (REMAINDER)
    if args.nmap_args:
        # argparse includes the leading "--" in the remainder; strip it if present
        if args.nmap_args and args.nmap_args[0] == "--":
            return args.nmap_args[1:]
        return args.nmap_args
    # 3) Defaults
    return ["-sV", "-Pn", "-T4", "-p-"]

def main():
    args = parse_args()
    nmap_flags = resolve_flags(args)

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
                # Write the command header, then stream combined output
                f.write("COMMAND:\n" + " ".join(shlex.quote(c) for c in cmd) + "\n\n")
                f.flush()
                res = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)

            if res.returncode == 0:
                print(f"     [OK] Report saved: {out_file}")
            else:
                print(f"     [!] Nmap exit code {res.returncode}. See {out_file} for details.")
        except Exception as e:
            print(f"     [!] Error scanning {target}: {e}")

    print("-" * 60)
    print("[+] Done.")

if __name__ == "__main__":
    main()
