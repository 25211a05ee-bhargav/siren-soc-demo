#!/bin/bash
# incident_response.sh
# Usage: ./incident_response.sh <attacker_ip> <failed_attempts> <target_user> <attack_hour(0-23)>

ATTACKER_IP=$1
ATTEMPTS=$2
TARGET_USER=$3
ATTACK_HOUR=$4
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
INCIDENT_ID="INC-$(date +%s)"

if [ -z "$ATTACKER_IP" ] || [ -z "$ATTEMPTS" ] || [ -z "$TARGET_USER" ]; then
  echo "Usage: $0 <attacker_ip> <failed_attempts> <target_user> <attack_hour(0-23)>"
  exit 1
fi

# --- Likelihood scoring (attempt volume) ---
if [ "$ATTEMPTS" -le 2 ]; then LIKELIHOOD=1
elif [ "$ATTEMPTS" -le 4 ]; then LIKELIHOOD=2
elif [ "$ATTEMPTS" -le 9 ]; then LIKELIHOOD=3
elif [ "$ATTEMPTS" -le 20 ]; then LIKELIHOOD=4
else LIKELIHOOD=5
fi

# --- Time-of-day anomaly bump (Proactive Detection) ---
if [ -n "$ATTACK_HOUR" ] && { [ "$ATTACK_HOUR" -lt 8 ] || [ "$ATTACK_HOUR" -ge 20 ]; }; then
  if [ "$LIKELIHOOD" -lt 5 ]; then LIKELIHOOD=$((LIKELIHOOD + 1)); fi
  TIME_FLAG="Unusual login time (off-hours) - likelihood increased"
else
  TIME_FLAG="Normal login time window"
fi

# --- Impact scoring (account sensitivity) ---
if [ "$TARGET_USER" == "root" ] || [ "$TARGET_USER" == "admin" ]; then
  IMPACT=5
else
  IMPACT=3
fi

RISK_SCORE=$((LIKELIHOOD * IMPACT))

if [ "$RISK_SCORE" -le 6 ]; then SEVERITY="Low"
elif [ "$RISK_SCORE" -le 12 ]; then SEVERITY="Medium"
elif [ "$RISK_SCORE" -le 19 ]; then SEVERITY="High"
else SEVERITY="Critical"
fi

echo "=== SOC ALERT ==="
echo "Incident ID: $INCIDENT_ID"
echo "Source IP: $ATTACKER_IP"
echo "Failed Attempts: $ATTEMPTS"
echo "Time Flag: $TIME_FLAG"
echo "Risk Score: $RISK_SCORE ($SEVERITY)"
echo "MITRE ATT&CK: T1110 - Brute Force"
echo "=================="

# --- Containment: analyst-confirmed, not autonomous (stated intentionally) ---
read -p "Confirm containment: block $ATTACKER_IP? (y/n): " CONFIRM
if [ "$CONFIRM" == "y" ]; then
  sudo iptables -A INPUT -s "$ATTACKER_IP" -j DROP
  ACTION="IP $ATTACKER_IP blocked via iptables (analyst-confirmed)"
  echo "$ACTION"
else
  ACTION="No containment action taken (analyst declined)"
fi

# --- Report generation ---
REPORT_FILE="incident_report_${INCIDENT_ID}.txt"
cat <<EOF > "$REPORT_FILE"
INCIDENT REPORT
================
Incident ID: $INCIDENT_ID
Detection Time: $TIMESTAMP
Attack Type: SSH Brute Force
MITRE ATT&CK Technique: T1110 - Brute Force
Source IP: $ATTACKER_IP
Target Account: $TARGET_USER
Failed Attempts: $ATTEMPTS
Time Analysis: $TIME_FLAG
Risk Score: $RISK_SCORE
Severity: $SEVERITY
Response Action: $ACTION
Response Type: Semi-automated (Splunk detects, analyst confirms containment)
Framework Followed: NIST IR Lifecycle
Final Status: $( [ "$CONFIRM" == "y" ] && echo "Contained" || echo "Under Review" )

--- Known Limitations (for transparency) ---
- Detection window is fixed at 2 minutes; attacks spanning window
  boundaries may undercount.
- Containment requires analyst confirmation (not fully autonomous).
EOF

echo "Incident report saved: $REPORT_FILE"
