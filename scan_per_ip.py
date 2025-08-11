#!/usr/bin/env python3
import os
import sys
import shlex
import shutil
import argparse
from datetime import datetime
import subprocess

DEFAULT_FLAGS = "-sC -sV -T4"  # safe-ish default; change as needed

def read_targets(path):
    if not os.path.isfile(path):
        print(f"[!] Target file not found: {path}")
        sys.exit(1)
    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    if not targets:
        print("[!] No targets found in the file.")
        sys.exit(1)
    return targets

def sanitize(name: str) -> str:
    # Make a safe filename base across OSes
    bad = '<>:"/\\|?*'
    for ch in bad:
        name = name.replace(ch, "_")
    return name.replace(" ", "_")

def ensure_nmap_available():
    if shutil.which("nmap") is None:
        print("[!] 'nmap' not found in PATH. Install Nmap and try again.")
        sys.exit(1)

def run_scan(ip: str, flags: str, outdir: str) -> int:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.join(outdir, f"{sanitize(ip)}_{ts}")
    cmd = ["nmap"] + shlex.split(flags) + ["-oA", base, ip]
    print(f"[*] Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        print(f"[!] Error executing nmap for {ip}: {e}")
        return 1

    # echo stdout/stderr for visibility
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        # Some nmap info lines come via stderr; don't treat as fatal alone
        print(proc.stderr, end="", file=sys.stderr)

    if proc.returncode == 0:
        print(f"[+] Reports saved: {base}.nmap | {base}.gnmap | {base}.xml")
    else:
        print(f"[!] Nmap exited with code {proc.returncode} for {ip}")
    return proc.returncode

def main():
    parser = argparse.ArgumentParser(
        description="Read IPs from ip.txt, prompt per-IP for Nmap flags, output separate reports."
    )
    parser.add_argument("-i", "--input", default="ip.txt", help="Path to targets file (default: ip.txt)")
    parser.add_argument("-o", "--outdir", default="reports", help="Directory to store outputs (default: reports)")
    parser.add_argument("--reuse", action="store_true",
                        help="Reuse the last entered flags if you just press Enter on subsequent IPs.")
    args = parser.parse_args()

    ensure_nmap_available()
    targets = read_targets(args.input)
    os.makedirs(args.outdir, exist_ok=True)

    print(f"[*] Loaded {len(targets)} target(s) from {args.input}")
    print("[*] For each target, enter Nmap flags (examples: '-Pn -p- -sS', '-A', '-sU -p 53').")
    print(f"[*] Press Enter for default: {DEFAULT_FLAGS}\n")

    last_flags = DEFAULT_FLAGS
    exit_code = 0

    for ip in targets:
        prompt = f"Flags for {ip} "
        if args.reuse:
            prompt += f"(default: {last_flags}): "
        else:
            prompt += f"(default: {DEFAULT_FLAGS}): "

        user_flags = input(prompt).strip()
        if not user_flags:
            flags = last_flags if args.reuse else DEFAULT_FLAGS
        else:
            flags = user_flags
            if args.reuse:
                last_flags = user_flags

        rc = run_scan(ip, flags, args.outdir)
        if rc != 0:
            exit_code = rc  # remember non-zero but continue

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
