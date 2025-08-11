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
    # de-dup while preserving order
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
        description="Batch Nmap scanner: per-IP reports, CIDR expansion, run logs."
    )
    parser.add_argument("-i", "--input", required=True, help="Input file with IPs/hosts/CIDRs")
    parser.add_argument("--timeout", default="10m", help="Nmap --host-timeout value (default: 10m)")
    parser.add_argument("--outdir", default=None, help="Custom output directory (default: reports_<timestamp>)")
    # We’ll manually capture everything after --nflag so you don't need quotes
    # IMPORTANT: keep --nflag as the last option in your command.
    parser.add_argument("--nflag", action="store_true",
                        help="Place this and then any nmap flags afterwards, e.g.: --nflag -sV -Pn")
    # We need access to raw argv to capture flags after --nflag
    args, _unknown = parser.parse_known_args()
    return args

def capture_nmap_flags():
    """Capture all tokens after --nflag from sys.argv (unquoted)."""
    if "--nflag" not in sys.argv:
        return None  # means: use defaults
    idx = sys.argv.index("--nflag")
    flags = sys.argv[idx+1:]
    # If user provided nothing after --nflag, treat as None so defaults kick in
    return flags if flags else None

def main():
    args = parse_args()
    raw_flags = capture_nmap_flags()

    # Defaults if user didn't provide any flags after --nflag
    nmap_flags = raw_flags if raw_flags is not None else ["-sV", "-Pn", "-T4", "-p-"]

    # Validate we didn't accidentally swallow other options
    # (Because --nflag should be last; warn if we see our own options in flags)
    for tok in nmap_flags:
        if tok in ("-i", "--input", "--timeout", "--outdir", "--nflag"):
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
    print(f"[+] Host timeout: {args.timeout}")
    print("-" * 60)

    for idx, target in enumerate(targets, 1):
        base_name = sanitize_filename(target)
        out_base = out_dir / base_name

        cmd = ["nmap", *nmap_flags, "--host-timeout", args.timeout, "-oA", str(out_base), target]
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
                print(f"     [!] Nmap exit code {res.returncode}. See {base_name}.runlog.txt for details.")
        except Exception as e:
            print(f"     [!] Error scanning {target}: {e}")

    print("-" * 60)
    print("[+] Done.")

if __name__ == "__main__":
    main()
