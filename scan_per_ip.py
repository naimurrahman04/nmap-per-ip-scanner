#!/usr/bin/env python3
import subprocess
import sys
import shlex
import time
from pathlib import Path
import ipaddress

def read_targets(path: Path):
    """Read targets from ip.txt; supports comments and CIDR expansion."""
    targets = []
    if not path.exists():
        print(f"[!] {path} not found.")
        sys.exit(1)
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Expand CIDRs into individual IPs; leave hostnames as-is
        try:
            net = ipaddress.ip_network(line, strict=False)
            # For IPv4/IPv6 networks, iterate hosts (excludes network/broadcast for v4)
            targets.extend([str(h) for h in net.hosts()])
        except ValueError:
            # Not a CIDR; assume single IP/hostname
            targets.append(line)
    # De-duplicate while preserving order
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique

def sanitize_filename(s: str) -> str:
    """Make a safe filename from an IP/hostname."""
    return "".join(c if c.isalnum() or c in ("-", ".", "_") else "_" for c in s)

def check_nmap():
    try:
        subprocess.run(["nmap", "-V"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Nmap is not installed or not in PATH. Install it first (e.g., https://nmap.org/download.html).")
        sys.exit(1)

def main():
    print("=== Batch Nmap Scanner ===")
    ip_file = Path("ip.txt")
    targets = read_targets(ip_file)
    if not targets:
        print("[!] No targets found in ip.txt.")
        sys.exit(1)

    # Ask for flags
    default_flags = "-sV -Pn -T4 -p-"
    user_flags = input(f"Enter Nmap flags (press Enter for default '{default_flags}'): ").strip()
    flags = user_flags if user_flags else default_flags

    # Optional host-timeout to avoid hanging forever
    timeout_default = "10m"
    timeout_in = input(f"Host timeout (e.g., 5m, 10m). Enter to use default '{timeout_default}': ").strip()
    host_timeout = timeout_in if timeout_in else timeout_default

    # Prepare output directory
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_dir = Path(f"reports_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    check_nmap()

    print(f"[+] Targets loaded: {len(targets)}")
    print(f"[+] Output directory: {out_dir.resolve()}")
    print(f"[+] Using flags: {flags}")
    print(f"[+] Host timeout: {host_timeout}")
    print("-" * 60)

    # Build base flag list safely
    try:
        flag_list = shlex.split(flags)
    except ValueError as e:
        print(f"[!] Could not parse flags: {e}")
        sys.exit(1)

    for idx, target in enumerate(targets, 1):
        base_name = sanitize_filename(target)
        out_base = out_dir / base_name  # nmap -oA will produce .nmap, .gnmap, .xml

        cmd = ["nmap", *flag_list, f"--host-timeout", host_timeout, "-oA", str(out_base), target]
        print(f"[{idx}/{len(targets)}] Scanning {target} ...")
        # Show the exact command for auditability
        print("     " + " ".join(shlex.quote(c) for c in cmd))

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Save the live stdout/stderr into a companion .runlog for convenience
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
