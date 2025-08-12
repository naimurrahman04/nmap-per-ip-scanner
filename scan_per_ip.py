#!/usr/bin/env python3
import argparse
import ipaddress
import shlex
import subprocess
import sys
import time
from pathlib import Path
import json
import signal

progress_file = None
paused_targets = []

def read_targets(path: Path):
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
        print("[!] Nmap not found in PATH.")
        sys.exit(1)

def parse_args():
    p = argparse.ArgumentParser(description="Batch Nmap scanner with pause/resume support")
    p.add_argument("-i", "--input", help="Input file with IPs/hosts/CIDRs")
    p.add_argument("--resume", help="Resume from a saved progress file")
    p.add_argument("--outdir", default=None, help="Custom output directory (default: reports_<timestamp>)")
    p.add_argument("--nflag", default=None, help='Nmap flags as a string, e.g. "--nflag \'-sV -Pn\'"')
    p.add_argument("nmap_args", nargs=argparse.REMAINDER, help="Or flags after '--'")
    return p.parse_args()

def resolve_flags(args):
    if args.nflag:
        return shlex.split(args.nflag)
    if args.nmap_args:
        if args.nmap_args and args.nmap_args[0] == "--":
            return args.nmap_args[1:]
        return args.nmap_args
    return ["-sV", "-Pn", "-T4", "-p-"]

def save_progress(out_dir, remaining):
    global progress_file
    progress_file = Path(out_dir) / "scan_progress.json"
    progress_data = {
        "remaining_targets": remaining,
        "outdir": str(out_dir)
    }
    progress_file.write_text(json.dumps(progress_data, indent=2))
    print(f"[+] Progress saved to {progress_file}")

def signal_handler(sig, frame):
    global paused_targets
    choice = input("\n[!] Pause scan? (y/n): ").strip().lower()
    if choice == "y":
        save_progress(out_dir, paused_targets)
        print("[+] Scan paused. You can resume later with:")
        print(f"    python3 scan_per_ip.py --resume {progress_file}")
        sys.exit(0)
    else:
        print("[*] Continuing scan...")

signal.signal(signal.SIGINT, signal_handler)

def main():
    global paused_targets, out_dir
    args = parse_args()
    nmap_flags = resolve_flags(args)

    if args.resume:
        data = json.loads(Path(args.resume).read_text())
        targets = data["remaining_targets"]
        out_dir = Path(data["outdir"])
    else:
        ip_file = Path(args.input)
        targets = read_targets(ip_file)
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_dir = Path(args.outdir) if args.outdir else Path(f"reports_{ts}")
        out_dir.mkdir(parents=True, exist_ok=True)

    check_nmap()

    print(f"[+] Targets loaded: {len(targets)}")
    print(f"[+] Output directory: {out_dir.resolve()}")
    print(f"[+] Using flags: {' '.join(shlex.quote(f) for f in nmap_flags)}")
    print("-" * 60)

    paused_targets = targets.copy()

    for idx, target in enumerate(targets, 1):
        base_name = sanitize_filename(target)
        out_file = out_dir / f"{base_name}.txt"
        cmd = ["nmap", *nmap_flags, target]

        print(f"[{idx}/{len(targets)}] Scanning {target} ...")
        try:
            with open(out_file, "w") as f:
                f.write("COMMAND:\n" + " ".join(shlex.quote(c) for c in cmd) + "\n\n")
                f.flush()
                subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            print(f"[!] Error scanning {target}: {e}")

        paused_targets.pop(0)  # Remove completed target

    if Path(out_dir / "scan_progress.json").exists():
        Path(out_dir / "scan_progress.json").unlink()

    print("-" * 60)
    print("[+] Done.")

if __name__ == "__main__":
    main()
