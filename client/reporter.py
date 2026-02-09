#!/usr/bin/env python3
"""SSH Blacklist Reporter - Watches auth.log and reports failed SSH attempts to the central server."""

import argparse
import json
import logging
import os
import re
import signal
import sys
import time

import requests

# Pattern matching "Failed password for ..." lines in auth.log.
# Covers both valid-user and invalid-user variants:
#   Failed password for root from 1.2.3.4 port 12345 ssh2
#   Failed password for invalid user admin from 1.2.3.4 port 12345 ssh2
FAILED_PASSWORD_RE = re.compile(
    r"Failed password for .+ from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+"
)

DEFAULT_LOG_FILE = "/var/log/auth.log"
DEFAULT_SERVER_URL = "http://localhost:5000"
DEFAULT_BATCH_INTERVAL = 5  # seconds

log = logging.getLogger("ssh-blacklist-reporter")


def parse_args():
    p = argparse.ArgumentParser(description="Report failed SSH attempts to the SSH Blacklist server.")
    p.add_argument("--log-file", default=os.environ.get("AUTH_LOG", DEFAULT_LOG_FILE),
                    help="Path to auth.log (default: %(default)s)")
    p.add_argument("--server", default=os.environ.get("BLACKLIST_SERVER", DEFAULT_SERVER_URL),
                    help="Blacklist server URL (default: %(default)s)")
    p.add_argument("--interval", type=int,
                    default=int(os.environ.get("REPORT_INTERVAL", DEFAULT_BATCH_INTERVAL)),
                    help="Batch send interval in seconds (default: %(default)s)")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    return p.parse_args()


def tail_follow(filepath):
    """Yield new lines from a file, starting at the end. Handles log rotation."""
    while True:
        try:
            with open(filepath, "r") as f:
                # Seek to end -- ignore existing content
                f.seek(0, os.SEEK_END)
                current_inode = os.fstat(f.fileno()).st_ino
                log.info("Watching %s (inode %d) from end", filepath, current_inode)

                while True:
                    line = f.readline()
                    if line:
                        yield line.rstrip("\n")
                    else:
                        # No new data -- check for rotation
                        try:
                            stat = os.stat(filepath)
                            if stat.st_ino != current_inode:
                                log.info("Log file rotated, reopening")
                                break
                        except FileNotFoundError:
                            log.warning("Log file disappeared, waiting for it to reappear")
                            break
                        time.sleep(0.2)
        except FileNotFoundError:
            log.warning("Waiting for %s to appear...", filepath)
            time.sleep(2)


def extract_ip(line):
    """Extract the attacker IP from a Failed password line, or None."""
    m = FAILED_PASSWORD_RE.search(line)
    return m.group(1) if m else None


def send_reports(server_url, ips):
    """Send a batch of IPs to the blacklist server. Returns True on success."""
    url = server_url.rstrip("/") + "/api/report"
    try:
        resp = requests.post(url, json={"ips": ips}, timeout=10)
        if resp.status_code == 200:
            log.info("Reported %d IPs: %s", len(ips), resp.json())
            return True
        else:
            log.error("Server returned %d: %s", resp.status_code, resp.text[:200])
            return False
    except requests.RequestException as e:
        log.error("Failed to reach server: %s", e)
        return False


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    )

    log.info("SSH Blacklist Reporter starting")
    log.info("Log file : %s", args.log_file)
    log.info("Server   : %s", args.server)
    log.info("Interval : %ds", args.interval)

    # Graceful shutdown
    running = True

    def handle_signal(signum, frame):
        nonlocal running
        log.info("Received signal %d, shutting down", signum)
        running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    pending = []
    last_send = time.monotonic()

    for line in tail_follow(args.log_file):
        if not running:
            break

        ip = extract_ip(line)
        if ip:
            log.debug("Detected failed SSH from %s", ip)
            pending.append(ip)

        now = time.monotonic()
        if pending and (now - last_send >= args.interval):
            batch = pending[:]
            pending.clear()
            if not send_reports(args.server, batch):
                # Put them back for retry
                pending.extend(batch)
            last_send = now

    # Send any remaining on shutdown
    if pending:
        log.info("Flushing %d pending reports before exit", len(pending))
        send_reports(args.server, pending)

    log.info("Reporter stopped")


if __name__ == "__main__":
    main()
