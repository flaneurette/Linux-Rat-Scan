#!/bin/bash
# Multi-tool Linux Security Scan Script (with Maldet)
# Scans for malware, rootkits, and system security issues
# Saves timestamped reports in /var/reports/security

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="/var/reports/security/$TIMESTAMP"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

BAD_PATTERNS="INFECTED|FOUND|WARNING|SUSPICIOUS|ROOTKIT|BACKDOOR|VIRUS|Trojan|Alert|Failed|compromised|malware|hits|quarantined|scan"

log() {
  echo -e "\n=== $1 ===\n"
}

filter_bad() {
  grep -iE "$BAD_PATTERNS" || echo "No suspicious results found."
}

run_cmd() {
  "$@" || echo "Command failed: $* (ignored)"
}

# --- Install/update tools ---
log "Installing/updating required tools"
for cmd in clamav rkhunter chkrootkit lynis curl tar inotify-tools; do
  command -v $cmd >/dev/null 2>&1 || run_cmd sudo apt install -y $cmd
done

# --- Maldet ---
log "Installing/updating Maldet"
if ! command -v maldet >/dev/null 2>&1; then
  run_cmd sudo curl -L https://www.rfxn.com/downloads/maldetect-current.tar.gz -o /tmp/maldetect.tar.gz
  run_cmd sudo tar -xzf /tmp/maldetect.tar.gz -C /tmp
  MALDIR=$(ls -d /tmp/maldetect-*/)
  run_cmd sudo /tmp/"$MALDIR"/install.sh
fi

log "Running Maldet"

sudo maldet -u      # update signatures
sudo maldet -d      # update program

echo "Maldet scan started... this may take a while, please wait."
# Run the scan in background and show progress dots
sudo maldet -a / > "$REPORT_DIR/maldet.log" 2>&1 &
SCAN_PID=$!

while kill -0 $SCAN_PID 2>/dev/null; do
  echo -n "."
  sleep 5
done
echo -e "\nMaldet scan finished!"
grep -iE "$BAD_PATTERNS" "$REPORT_DIR/maldet.log" > "$REPORT_DIR/maldet_bad.log" || echo "No suspicious results" > "$REPORT_DIR/maldet_bad.log"


# --- Rootkit Hunter ---
log "Running rkhunter"
echo "RKHunter scan started... this may take a while, please wait."
run_cmd sudo rkhunter --update
run_cmd sudo rkhunter --propupd
run_cmd sudo rkhunter --checkall --skip-keypress > "$REPORT_DIR/rkhunter.log"
grep -iE "Warning|Found" "$REPORT_DIR/rkhunter.log" > "$REPORT_DIR/rkhunter_bad.log" || echo "No suspicious results" > "$REPORT_DIR/rkhunter_bad.log"

# --- chkrootkit ---
log "Running chkrootkit"
echo "Chkrootkit scan started... this may take a while, please wait."
run_cmd sudo chkrootkit > "$REPORT_DIR/chkrootkit.log"
grep -iE "INFECTED|Vulnerable|FOUND|rootkit" "$REPORT_DIR/chkrootkit.log" > "$REPORT_DIR/chkrootkit_bad.log" || echo "No suspicious results" > "$REPORT_DIR/chkrootkit_bad.log"

# --- Lynis ---
log "Running Lynis"
echo "Lynis scan started... this may take a while, please wait."
run_cmd sudo lynis audit system --quiet --log-file "$REPORT_DIR/lynis.log"
grep -iE "warning|suggestion|fail" "$REPORT_DIR/lynis.log" > "$REPORT_DIR/lynis_bad.log" || echo "No warnings in Lynis" > "$REPORT_DIR/lynis_bad.log"

# --- ClamAV ---
log "Running ClamAV"
echo "ClamAV scan started... this may take a while, please wait."
run_cmd sudo freshclam > /dev/null 2>&1 || true
run_cmd sudo nice -n 10 clamscan -r / --infected --no-summary --exclude-dir="^/proc|^/sys|^/dev|^/run|^/var/log|^/tmp|^/mnt|^/media" > "$REPORT_DIR/clamav.log"
cat "$REPORT_DIR/clamav.log" | filter_bad > "$REPORT_DIR/clamav_bad.log"

# --- Summary ---
log "All scans complete!"
echo "Reports saved to: $REPORT_DIR"
echo -e "\nSummary of detected issues:"
grep -H . "$REPORT_DIR"/*_bad.log | grep -v "No suspicious" || echo "No suspicious or infected files detected."
