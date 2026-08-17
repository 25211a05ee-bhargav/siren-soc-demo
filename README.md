# SIREN — SOC Incident Response & Event Network

Beginner-friendly SOC dashboard and detection simulation for the SOC Mini Hackathon.

## Current version
This is an **offline simulation**. Events are synthetic; no real attacker or live Splunk instance is connected yet.

## Run
Open `index.html` in a browser.

## Detection rules
- SSH brute force: `failed_auth >= 5 within 5m`
- Port scan: `unique_ports >= 20 within 1m`
- Impossible login burst: `successful_logins >= 3 within 1m`

## Roadmap
1. Dashboard UI
2. Search/filter events
3. Incident details
4. SPL detection rules
5. Incident report generation
6. Connect to real Splunk after the Kali lab works
