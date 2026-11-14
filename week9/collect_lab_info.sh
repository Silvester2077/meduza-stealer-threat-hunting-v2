#!/usr/bin/env bash
# Collects EXACT versions of the Linux lab VM (Splunk + listener) for the report (section 9.4).
# Usage: sudo bash collect_lab_info.sh   -> lab_info_linux.md
OUT="lab_info_linux.md"
row(){ echo "| $1 | $2 |" >> "$OUT"; }
echo "# Linux lab VM - collected $(date '+%Y-%m-%d %H:%M %Z')" > "$OUT"; echo "" >> "$OUT"
echo "| Item | Value |" >> "$OUT"; echo "|---|---|" >> "$OUT"
. /etc/os-release 2>/dev/null
row "Distribution" "${PRETTY_NAME:-unknown}"
row "Kernel" "$(uname -r) ($(uname -m))"
row "Virtualization (systemd-detect-virt)" "$(systemd-detect-virt 2>/dev/null || echo unknown)"
row "vCPU / RAM" "$(nproc) vCPU / $(free -h | awk '/Mem:/{print $2}')"
if [ -x /opt/splunk/bin/splunk ]; then
  row "Splunk" "$(grep -E 'VERSION|BUILD' /opt/splunk/etc/splunk.version 2>/dev/null | tr '\n' ' ')"
  row "Splunk path" "/opt/splunk"
else
  row "Splunk" "not found in /opt/splunk - check Settings > Server settings or Help > About in the web UI"
fi
NCV=$( (dpkg -l 2>/dev/null | awk '/netcat/{print $2" "$3}'; rpm -qa 2>/dev/null | grep -i -E 'nmap-ncat|netcat') | head -1)
row "netcat package" "${NCV:-not found}"
ip -4 -o addr show | awk '$2!="lo"{print $2" "$4}' | while read i a; do row "IPv4 ($i)" "$a"; done
cat "$OUT"
