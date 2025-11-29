#!/bin/bash
# Multi-tool Linux Security Scan Script
# Detects malware, rootkits, and system security issues.

REPORT_DIR="/var/reports/security"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

log() {
  echo -e "\n=== $1 ===\n"
}

filter_bad() {
  grep -iE "INFECTED|FOUND|WARNING|SUSPICIOUS|ROOTKIT|BACKDOOR|VIRUS|Trojan|Alert|[Ff]ailed|compromised" || echo "No suspicious results found."
}

# Helper to run commands and continue on error
run_cmd() {
  "$@" || echo "Command failed: $* (ignored)"
}

# Update and install required tools
run_cmd sudo apt update -y
run_cmd sudo apt install -y clamav rkhunter chkrootkit lynis curl tar

# --- Rootkit Hunter ---
log "Running Rootkit Hunter"
run_cmd sudo rkhunter --update
run_cmd sudo rkhunter --propupd
run_cmd sudo rkhunter --checkall --skip-keypress > "$REPORT_DIR/rkhunter.log"
grep -iE "Warning|Found" "$REPORT_DIR/rkhunter.log" > "$REPORT_DIR/rkhunter_bad.log" || echo "No suspicious results" > "$REPORT_DIR/rkhunter_bad.log"

# --- chkrootkit ---
log "Running chkrootkit"
run_cmd sudo chkrootkit > "$REPORT_DIR/chkrootkit.log"
grep -iE "INFECTED|Vulnerable|FOUND|rootkit" "$REPORT_DIR/chkrootkit.log" > "$REPORT_DIR/chkrootkit_bad.log" || echo "No suspicious results" > "$REPORT_DIR/chkrootkit_bad.log"

# --- Lynis ---
log "Running Lynis"
run_cmd sudo lynis audit system --quiet --log-file "$REPORT_DIR/lynis.log"
grep -iE "warning|suggestion|fail" "$REPORT_DIR/lynis.log" > "$REPORT_DIR/lynis_bad.log" || echo "No warnings in Lynis" > "$REPORT_DIR/lynis_bad.log"

# --- ClamAV ---
log "Running ClamAV"
run_cmd sudo freshclam > /dev/null 2>&1 || true
# Avoid scanning virtual filesystems
run_cmd sudo clamscan -r / --infected --no-summary --exclude-dir="^/proc|^/sys|^/dev|^/run|^/var/log|^/tmp" > "$REPORT_DIR/clamav.log"
cat "$REPORT_DIR/clamav.log" | filter_bad > "$REPORT_DIR/clamav_bad.log"

# --- Summary ---
log "All scans complete!"
echo "Reports saved to: $REPORT_DIR"
echo "Summary of detected issues:"
echo
grep -H . "$REPORT_DIR"/*_bad.log | grep -v "No suspicious" || echo "No suspicious or infected files detected."
