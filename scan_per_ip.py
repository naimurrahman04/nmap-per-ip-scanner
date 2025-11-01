#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List, Dict, Any

# -------------- Globals carried by the runtime context --------------
class Runtime:
    def __init__(self):
        self.out_dir: Path | None = None
        self.progress_path: Path | None = None
        self.ctx: Dict[str, Any] = {}  # persisted fields
        self.stop_requested: bool = False

R = Runtime()

# -------------- Helpers --------------
def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")

def sanitize_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", ".", "_") else "_" for c in s)

def check_nmap_or_die() -> None:
    try:
        subprocess.run(["nmap", "-V"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)
    except Exception:
        print("[!] Nmap not found in PATH.", file=sys.stderr)
        sys.exit(1)

def normalize_target(line: str) -> str:
    return line.strip()

def read_lines(path: Path) -> Iterable[str]:
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        yield line

def stream_targets(source: Iterable[str]) -> Iterable[str]:
    """Expand CIDRs lazily; yield host IPs/hostnames; dedupe while streaming."""
    seen = set()
    for item in source:
        try:
            net = ipaddress.ip_network(item, strict=False)
            # Be careful: hosts() on IPv6 huge nets is enormous; let user supply sane CIDRs.
            for host in net.hosts():
                t = str(host)
                if t not in seen:
                    seen.add(t)
                    yield t
        except ValueError:
            t = normalize_target(item)
            # Hostnames are case-insensitive; normalize to lower for de-dup
            key = t.lower()
            if key not in seen:
                seen.add(key)
                yield t

def resolve_flags(args) -> List[str]:
    if args.nflag:
        return shlex.split(args.nflag)
    if args.nmap_args:
        if args.nmap_args and args.nmap_args[0] == "--":
            return args.nmap_args[1:]
        return args.nmap_args
    return ["-sV", "-Pn", "-T4", "-p-"]

def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False))

def load_json(path: Path) -> Any:
    return json.loads(path.read_text())

# -------------- Progress handling --------------
def progress_init(out_dir: Path, flags: List[str], targets: List[str], start_index: int = 0) -> None:
    R.out_dir = out_dir
    R.progress_path = out_dir / "scan_progress.json"
    R.ctx = {
        "outdir": str(out_dir),
        "flags": flags,
        "targets": targets,        # full ordered list
        "cursor": start_index,     # next index to scan
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    write_json(R.progress_path, R.ctx)

def progress_update(cursor: int) -> None:
    if not R.progress_path:
        return
    R.ctx["cursor"] = cursor
    R.ctx["updated_at"] = now_iso()
    write_json(R.progress_path, R.ctx)

def progress_load(resume_path: Path) -> None:
    data = load_json(resume_path)
    out_dir = Path(data["outdir"])
    R.out_dir = out_dir
    R.progress_path = resume_path
    R.ctx = data

def progress_finish() -> None:
    if R.progress_path and R.progress_path.exists():
        R.progress_path.unlink()

# -------------- SIGINT handling --------------
def handle_sigint(sig, frame):
    # Single keypress = safe stop after current target; save state
    print("\n[!] Ctrl-C received — finishing current task then pausing…", flush=True)
    R.stop_requested = True

# -------------- Core scanning --------------
def run_nmap(target: str, flags: List[str], out_dir: Path, timeout_sec: int) -> Dict[str, Any]:
    base = sanitize_filename(target)
    out_txt = out_dir / f"{base}.txt"
    meta_json = out_dir / f"{base}.json"

    cmd = ["nmap", *flags, target]
    started = time.time()
    meta = {
        "target": target,
        "command": " ".join(shlex.quote(c) for c in cmd),
        "started_at": now_iso(),
        "stdout_path": str(out_txt),
        "returncode": None,
        "duration_sec": None,
        "error": None,
    }

    try:
        with open(out_txt, "w", encoding="utf-8", errors="replace") as f:
            f.write("COMMAND:\n" + meta["command"] + "\n\n")
            f.flush()
            proc = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout_sec
            )
            meta["returncode"] = proc.returncode
    except subprocess.TimeoutExpired:
        meta["error"] = f"timeout({timeout_sec}s)"
        meta["returncode"] = 124
    except Exception as e:
        meta["error"] = repr(e)
        meta["returncode"] = -1
    finally:
        meta["duration_sec"] = round(time.time() - started, 3)
        write_json(meta_json, meta)

    return meta

def collect_targets(args) -> List[str]:
    # Support stdin if -i omitted
    if args.resume:
        return []

    raw_iter: Iterable[str]
    if args.input:
        p = Path(args.input)
        if not p.exists():
            print(f"[!] Input file not found: {p}", file=sys.stderr)
            sys.exit(1)
        raw_iter = read_lines(p)
    else:
        if sys.stdin.isatty():
            print("[!] No --input provided and no data on stdin.", file=sys.stderr)
            sys.exit(1)
        raw_iter = (line.strip() for line in sys.stdin if line.strip())

    targets = list(stream_targets(raw_iter))
    return targets

# -------------- CLI --------------
def parse_args():
    p = argparse.ArgumentParser(description="Batch Nmap scanner with pause/resume & parallelism")
    p.add_argument("-i", "--input", help="Input file with IPs/hosts/CIDRs (or pipe via stdin)")
    p.add_argument("--resume", help="Resume from a saved progress file (scan_progress.json)")
    p.add_argument("--outdir", default=None, help="Custom output directory (default: reports_<timestamp>)")
    p.add_argument("--nflag", default=None, help='Nmap flags as a single string, e.g. "--nflag \'-sV -Pn\'"')
    p.add_argument("--workers", type=int, default=1, help="Parallel scans (default: 1)")
    p.add_argument("--timeout-sec", type=int, default=3600, help="Per-target timeout (default: 3600)")
    p.add_argument("--overwrite", action="store_true", help="Re-scan targets even if output files exist")
    p.add_argument("nmap_args", nargs=argparse.REMAINDER, help="Or pass flags after '--'")
    return p.parse_args()

def main():
    signal.signal(signal.SIGINT, handle_sigint)
    args = parse_args()
    flags = resolve_flags(args)
    check_nmap_or_die()

    # Load or initialize
    if args.resume:
        resume_path = Path(args.resume)
        if not resume_path.exists():
            print(f"[!] Resume file not found: {resume_path}", file=sys.stderr)
            sys.exit(1)
        progress_load(resume_path)
        targets = list(R.ctx["targets"])
        cursor = int(R.ctx.get("cursor", 0))
        saved_flags = list(R.ctx.get("flags", []))
        # Ensure consistent flags between sessions
        if saved_flags and saved_flags != flags:
            print("[*] Warning: supplied flags differ from saved progress. Using saved flags.", file=sys.stderr)
            flags = saved_flags
        out_dir = Path(R.ctx["outdir"])
    else:
        targets = collect_targets(args)
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_dir = Path(args.outdir) if args.outdir else Path(f"reports_{ts}")
        out_dir.mkdir(parents=True, exist_ok=True)
        cursor = 0
        progress_init(out_dir, flags, targets, start_index=0)

    R.out_dir = out_dir
    R.progress_path = out_dir / "scan_progress.json"

    total = len(targets)
    print(f"[+] Targets loaded: {total}")
    print(f"[+] Output directory: {out_dir.resolve()}")
    print(f"[+] Using flags: {' '.join(shlex.quote(f) for f in flags)}")
    print(f"[+] Workers: {args.workers}  |  Timeout per target: {args.timeout_sec}s")
    print("-" * 60)

    # Build the actual worklist (skip already scanned unless --overwrite)
    work: List[str] = []
    for i, t in enumerate(targets):
        if i < cursor:
            continue
        base = sanitize_filename(t)
        out_txt = out_dir / f"{base}.txt"
        out_meta = out_dir / f"{base}.json"
        if not args.overwrite and (out_txt.exists() or out_meta.exists()):
            print(f"[-] Skipping (exists): {t}")
            cursor = i + 1
            continue
        work.append(t)

    if not work:
        print("[*] Nothing to do. All targets scanned (or skipped).")
        progress_finish()
        return

    # Master index for quick review
    index_path = out_dir / "index.json"
    index_data = load_json(index_path) if index_path.exists() else {
        "created_at": now_iso(),
        "runs": []
    }
    run_id = int(time.time())
    run_entry = {
        "run_id": run_id,
        "started_at": now_iso(),
        "flags": flags,
        "timeout_sec": args.timeout_sec,
        "workers": args.workers,
        "items": []
    }
    index_data["runs"].append(run_entry)
    write_json(index_path, index_data)

    # Execute
    next_cursor = cursor
    try:
        if args.workers <= 1:
            for t in work:
                if R.stop_requested:
                    break
                print(f"[{next_cursor+1}/{total}] Scanning {t} ...")
                meta = run_nmap(t, flags, out_dir, args.timeout_sec)
                run_entry["items"].append(meta)
                next_cursor += 1
                progress_update(next_cursor)
        else:
            # Bounded thread pool
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {}
                for offset, t in enumerate(work):
                    if R.stop_requested:
                        break
                    print(f"[{next_cursor+offset+1}/{total}] Queued {t}")
                    futures[pool.submit(run_nmap, t, flags, out_dir, args.timeout_sec)] = t
                for fut in as_completed(futures):
                    meta = fut.result()
                    run_entry["items"].append(meta)
                    next_cursor += 1
                    progress_update(next_cursor)
                    if R.stop_requested:
                        break
    finally:
        # Update index (end time + last write)
        run_entry["ended_at"] = now_iso()
        write_json(index_path, index_data)

    if R.stop_requested:
        print("\n[+] Paused. Resume with:")
        print(f"    python3 {Path(sys.argv[0]).name} --resume {R.progress_path}")
        return

    # Done
    progress_finish()
    print("-" * 60)
    print("[+] Done.")

if __name__ == "__main__":
    main()
