#!/usr/bin/env python3
"""File Integrity Monitor - detects added, deleted, modified files and permission changes."""
import argparse
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import stat
import sys
import time
from datetime import datetime, timezone

DEFAULT_BASELINE = "baseline.json"
LOG_FILE = "fim.log"
CHUNK = 1024 * 1024

log = logging.getLogger("fim")


def setup_logging():
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    for h in (logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_FILE)):
        h.setFormatter(fmt)
        log.addHandler(h)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def is_excluded(rel_path, patterns):
    name = os.path.basename(rel_path)
    return any(fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(name, p) for p in patterns)


def scan(root, excludes):
    files = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames
            if not is_excluded(os.path.relpath(os.path.join(dirpath, d), root), excludes)
        ]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if is_excluded(rel, excludes) or os.path.islink(full):
                continue
            try:
                st = os.stat(full)
                files[rel] = {
                    "sha256": sha256_file(full),
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "mode": stat.filemode(st.st_mode),
                }
            except (PermissionError, FileNotFoundError, OSError) as e:
                log.warning("Could not read %s: %s", rel, e)
    return files


def _sign(files):
    key = os.environ.get("FIM_KEY")
    if not key:
        return None
    blob = json.dumps(files, sort_keys=True).encode()
    return hmac.new(key.encode(), blob, hashlib.sha256).hexdigest()


def save_baseline(path, root, excludes, files):
    data = {
        "version": 1,
        "created": datetime.now(timezone.utc).isoformat(),
        "root": os.path.abspath(root),
        "excludes": excludes,
        "files": files,
        "hmac": _sign(files),
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_baseline(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        sys.exit(f"Baseline '{path}' not found. Run: python fim.py init <path>")
    except json.JSONDecodeError:
        log.critical("Baseline file is corrupted or has been tampered with.")
        sys.exit(2)
    stored = data.get("hmac")
    if stored:
        expected = _sign(data["files"])
        if expected is None:
            sys.exit("Baseline is HMAC-protected. Set the FIM_KEY env variable.")
        if not hmac.compare_digest(stored, expected):
            log.critical("BASELINE TAMPERED - HMAC mismatch! Do not trust results.")
            sys.exit(2)
    return data


def compare(old, new):
    old_keys, new_keys = set(old), set(new)
    changes = {
        "added": sorted(new_keys - old_keys),
        "deleted": sorted(old_keys - new_keys),
        "modified": [],
        "permissions": [],
    }
    for p in sorted(old_keys & new_keys):
        if old[p]["sha256"] != new[p]["sha256"]:
            changes["modified"].append(p)
        elif old[p]["mode"] != new[p]["mode"]:
            changes["permissions"].append(p)
    return changes


def report(changes):
    total = sum(len(v) for v in changes.values())
    if total == 0:
        log.info("OK - no changes detected.")
        return 0
    for p in changes["added"]:
        log.warning("ADDED     %s", p)
    for p in changes["deleted"]:
        log.warning("DELETED   %s", p)
    for p in changes["modified"]:
        log.warning("MODIFIED  %s", p)
    for p in changes["permissions"]:
        log.warning("PERM-CHG  %s", p)
    log.warning("%d change(s) detected.", total)
    return total


def cmd_init(args):
    log.info("Building baseline for %s ...", args.path)
    files = scan(args.path, args.exclude)
    save_baseline(args.baseline, args.path, args.exclude, files)
    log.info("Baseline saved to %s (%d files).", args.baseline, len(files))


def cmd_check(args):
    base = load_baseline(args.baseline)
    new = scan(base["root"], base["excludes"])
    changes = compare(base["files"], new)
    total = report(changes)
    if args.report:
        with open(args.report, "w") as f:
            json.dump({"time": datetime.now(timezone.utc).isoformat(), **changes}, f, indent=2)
        log.info("Report written to %s", args.report)
    sys.exit(1 if total else 0)


def cmd_watch(args):
    base = load_baseline(args.baseline)
    last = base["files"]
    log.info("Watching %s every %ss (Ctrl+C to stop)", base["root"], args.interval)
    try:
        while True:
                        new = scan(base["root"], base["excludes"])
            changes = compare(last, new)
            if any(changes.values()):
                report(changes)
            last = new
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("Stopped.")


def main():
    p = argparse.ArgumentParser(description="File Integrity Monitor")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="create baseline")
    pi.add_argument("path")
    pi.add_argument("--exclude", nargs="*", default=[".git", "__pycache__", "*.log", "*.tmp"])
    pi.add_argument("--baseline", default=DEFAULT_BASELINE)
    pi.set_defaults(func=cmd_init)

    pc = sub.add_parser("check", help="compare against baseline")
    pc.add_argument("--baseline", default=DEFAULT_BASELINE)
    pc.add_argument("--report", help="write JSON report to this file")
    pc.set_defaults(func=cmd_check)

    pw = sub.add_parser("watch", help="continuous monitoring")
    pw.add_argument("--baseline", default=DEFAULT_BASELINE)
    pw.add_argument("--interval", type=int, default=10)
    pw.set_defaults(func=cmd_watch)

    args = p.parse_args()
    setup_logging()
    args.func(args)


if __name__ == "__main__":
    main()