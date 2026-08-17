// SIREN SOC Demo - Application & Detection Engine

const defaultEvents = [
  { "time": "02:15:01", "source": "sshd", "event": "Failed password", "user": "root", "ip": "10.10.20.60", "severity": "HIGH" },
  { "time": "02:15:03", "source": "sshd", "event": "Failed password", "user": "root", "ip": "10.10.20.60", "severity": "HIGH" },
  { "time": "02:15:05", "source": "sshd", "event": "Failed password", "user": "root", "ip": "10.10.20.60", "severity": "HIGH" },
  { "time": "02:15:07", "source": "sshd", "event": "Failed password", "user": "root", "ip": "10.10.20.60", "severity": "HIGH" },
  { "time": "02:15:09", "source": "sshd", "event": "Failed password", "user": "root", "ip": "10.10.20.60", "severity": "HIGH" },
  { "time": "12:01:05", "source": "sshd", "event": "Accepted password", "user": "alice", "ip": "10.10.10.15", "severity": "INFO" },
  { "time": "12:05:01", "source": "sshd", "event": "Accepted password", "user": "admin", "ip": "10.10.20.70", "severity": "INFO" },
  { "time": "12:05:10", "source": "sshd", "event": "Accepted password", "user": "user1", "ip": "10.10.20.70", "severity": "INFO" },
  { "time": "12:05:18", "source": "sshd", "event": "Accepted password", "user": "user2", "ip": "10.10.20.70", "severity": "INFO" },
  { "time": "14:22:18", "source": "firewall", "event": "Connection to port 443", "user": "-", "ip": "10.10.10.88", "dest_port": 443, "severity": "INFO" },
  { "time": "16:45:30", "source": "sshd", "event": "Failed password", "user": "bob", "ip": "10.10.10.99", "severity": "LOW" },
  { "time": "16:46:12", "source": "sshd", "event": "Accepted password", "user": "bob", "ip": "10.10.10.99", "severity": "INFO" },
  { "time": "23:31:02", "source": "sshd", "event": "Failed password", "user": "testuser", "ip": "10.10.20.45", "severity": "HIGH" },
  { "time": "23:31:04", "source": "sshd", "event": "Failed password", "user": "testuser", "ip": "10.10.20.45", "severity": "HIGH" },
  { "time": "23:31:08", "source": "sshd", "event": "Failed password", "user": "testuser", "ip": "10.10.20.45", "severity": "HIGH" },
  { "time": "23:31:11", "source": "sshd", "event": "Failed password", "user": "testuser", "ip": "10.10.20.45", "severity": "HIGH" },
  { "time": "23:31:14", "source": "sshd", "event": "Failed password", "user": "testuser", "ip": "10.10.20.45", "severity": "HIGH" },
  { "time": "23:32:01", "source": "firewall", "event": "Connection to port 21", "user": "-", "ip": "10.10.20.50", "dest_port": 21, "severity": "LOW" },
  { "time": "23:32:05", "source": "firewall", "event": "Connection to port 22", "user": "-", "ip": "10.10.20.50", "dest_port": 22, "severity": "LOW" },
  { "time": "23:32:10", "source": "firewall", "event": "Connection to port 80", "user": "-", "ip": "10.10.20.50", "dest_port": 80, "severity": "LOW" },
  { "time": "23:32:15", "source": "firewall", "event": "Connection to port 443", "user": "-", "ip": "10.10.20.50", "dest_port": 443, "severity": "LOW" },
  { "time": "23:32:20", "source": "firewall", "event": "Connection to port 8080", "user": "-", "ip": "10.10.20.50", "dest_port": 8080, "severity": "LOW" }
];

let events = JSON.parse(JSON.stringify(defaultEvents));
let incidents = [];
let containedIPs = new Set();
let selectedIncidentId = null;
let containmentTimes = {}; // maps incident ID to simulated containment timestamp (seconds)

// --- Time Helper Functions ---

function timeToSeconds(timeStr) {
  const [h, m, s] = timeStr.split(":").map(Number);
  return h * 3600 + m * 60 + s;
}

function secondsToTime(secs) {
  const h = Math.floor((secs % 86400) / 3600).toString().padStart(2, '0');
  const m = Math.floor((secs % 3600) / 60).toString().padStart(2, '0');
  const s = (secs % 60).toString().padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function getBucket(timeStr, spanSeconds) {
  const secs = timeToSeconds(timeStr);
  const bucketSecs = Math.floor(secs / spanSeconds) * spanSeconds;
  return secondsToTime(bucketSecs);
}

// --- Detection Engine Logic ---

function runDetectionEngine() {
  // Sort events chronologically by time
  events.sort((a, b) => timeToSeconds(a.time) - timeToSeconds(b.time));
  
  incidents = [];
  
  // 1. Group SSH logs by IP, User, and 2-Minute Bucket
  const sshGroups = {};
  events.forEach(e => {
    if (e.source === "sshd") {
      const bucket = getBucket(e.time, 120); // 2 minutes bucket
      const key = `${e.ip}_${e.user}_${bucket}`;
      if (!sshGroups[key]) {
        sshGroups[key] = {
          ip: e.ip,
          user: e.user,
          bucket: bucket,
          failed: [],
          accepted: []
        };
      }
      if (e.event.toLowerCase().includes("failed password")) {
        sshGroups[key].failed.push(e);
      } else if (e.event.toLowerCase().includes("accepted password")) {
        sshGroups[key].accepted.push(e);
      }
    }
  });

  // Evaluate SSH groups for Brute Force
  Object.values(sshGroups).forEach(group => {
    if (group.failed.length >= 5) {
      const sortedFailed = group.failed.slice().sort((a, b) => timeToSeconds(a.time) - timeToSeconds(b.time));
      const firstAttempt = sortedFailed[0].time;
      const lastAttempt = sortedFailed[sortedFailed.length - 1].time;
      
      const firstHour = parseInt(firstAttempt.split(":")[0], 10);
      const isOffHours = firstHour < 8 || firstHour >= 20;

      // Base Likelihood (attempt volume)
      const count = sortedFailed.length;
      let likelihood = 1;
      if (count <= 2) likelihood = 1;
      else if (count <= 4) likelihood = 2;
      else if (count <= 9) likelihood = 3;
      else if (count <= 20) likelihood = 4;
      else likelihood = 5;

      // Time-of-day proactive bump
      let timeFlag = "Normal login time window";
      if (isOffHours) {
        if (likelihood < 5) likelihood += 1;
        timeFlag = "Unusual login time (off-hours) - likelihood increased";
      }

      // Impact scoring (account sensitivity)
      const impact = (group.user === "root" || group.user === "admin") ? 5 : 3;
      let riskScore = likelihood * impact;

      // Critical escalation check: success event after failures in the same bucket
      const successAttempts = group.accepted.filter(a => timeToSeconds(a.time) >= timeToSeconds(firstAttempt));
      const escalated = successAttempts.length > 0;
      
      let severity = "High";
      if (riskScore <= 6) severity = "Low";
      else if (riskScore <= 12) severity = "Medium";
      else if (riskScore <= 19) severity = "High";
      else severity = "Critical";

      if (escalated) {
        severity = "Critical";
        riskScore = Math.max(riskScore, 20); // ensure in Critical severity range
      }

      const id = `INC-BF-${group.ip.replace(/\./g, '')}-${group.user}`;
      const status = containedIPs.has(group.ip) ? "Contained" : "Active";

      incidents.push({
        id: id,
        type: "SSH Brute Force",
        mitre: "T1110 - Brute Force",
        ip: group.ip,
        user: group.user,
        details: `${count} failed authentication attempts in 2m` + (escalated ? " (COMPROMISED: Success login detected)" : ""),
        severity: severity,
        likelihood: likelihood,
        impact: impact,
        riskScore: riskScore,
        timeFlag: timeFlag,
        status: status,
        first_attempt_time: firstAttempt,
        last_attempt_time: escalated ? successAttempts[successAttempts.length - 1].time : lastAttempt,
        detection_time: lastAttempt,
        outcome: escalated ? "Compromise (Successful Login)" : "Blocked/Stopped",
        events: [...group.failed, ...successAttempts]
      });
    }
  });

  // 2. Group Firewall connections by IP and 1-Minute Bucket
  const portGroups = {};
  events.forEach(e => {
    if (e.source === "firewall" || e.dest_port !== undefined) {
      const bucket = getBucket(e.time, 60); // 1 minute bucket
      const key = `${e.ip}_${bucket}`;
      if (!portGroups[key]) {
        portGroups[key] = {
          ip: e.ip,
          bucket: bucket,
          events: []
        };
      }
      portGroups[key].events.push(e);
    }
  });

  // Evaluate Port Scan groups
  Object.values(portGroups).forEach(group => {
    const ports = new Set();
    group.events.forEach(e => {
      if (e.dest_port !== undefined) ports.add(e.dest_port);
      else {
        const match = e.event.match(/port\s+(\d+)/i);
        if (match) ports.add(parseInt(match[1], 10));
      }
    });

    if (ports.size >= 5) {
      const sortedEvents = group.events.slice().sort((a, b) => timeToSeconds(a.time) - timeToSeconds(b.time));
      const firstAttempt = sortedEvents[0].time;
      const lastAttempt = sortedEvents[sortedEvents.length - 1].time;

      const size = ports.size;
      let likelihood = 3;
      if (size <= 6) likelihood = 3;
      else if (size <= 10) likelihood = 4;
      else likelihood = 5;

      const impact = 3;
      const riskScore = likelihood * impact;

      let severity = "Medium";
      if (riskScore <= 6) severity = "Low";
      else if (riskScore <= 12) severity = "Medium";
      else if (riskScore <= 19) severity = "High";
      else severity = "Critical";

      const id = `INC-PS-${group.ip.replace(/\./g, '')}`;
      const status = containedIPs.has(group.ip) ? "Contained" : "Active";

      incidents.push({
        id: id,
        type: "Port Scan",
        mitre: "T1046 - Network Service Discovery",
        ip: group.ip,
        user: "-",
        details: `Port scan detected: ${size} unique ports contacted in 1m (${Array.from(ports).join(', ')})`,
        severity: severity,
        likelihood: likelihood,
        impact: impact,
        riskScore: riskScore,
        timeFlag: "Normal login time window",
        status: status,
        first_attempt_time: firstAttempt,
        last_attempt_time: lastAttempt,
        detection_time: lastAttempt,
        outcome: "Reconnaissance Completed",
        events: group.events
      });
    }
  });

  // 3. Group successful logins by IP and 1-Minute Bucket
  const burstGroups = {};
  events.forEach(e => {
    if (e.source === "sshd" && e.event.toLowerCase().includes("accepted password")) {
      const bucket = getBucket(e.time, 60); // 1 minute bucket
      const key = `${e.ip}_${bucket}`;
      if (!burstGroups[key]) {
        burstGroups[key] = {
          ip: e.ip,
          bucket: bucket,
          events: []
        };
      }
      burstGroups[key].events.push(e);
    }
  });

  // Evaluate Impossible Login Burst
  Object.values(burstGroups).forEach(group => {
    if (group.events.length >= 3) {
      const sortedEvents = group.events.slice().sort((a, b) => timeToSeconds(a.time) - timeToSeconds(b.time));
      const firstAttempt = sortedEvents[0].time;
      const lastAttempt = sortedEvents[sortedEvents.length - 1].time;
      const users = Array.from(new Set(group.events.map(e => e.user)));

      const likelihood = 5;
      const impact = 5;
      const riskScore = 25;
      const severity = "Critical";

      const id = `INC-IL-${group.ip.replace(/\./g, '')}`;
      const status = containedIPs.has(group.ip) ? "Contained" : "Active";

      incidents.push({
        id: id,
        type: "Impossible Login Burst",
        mitre: "T1078 - Valid Accounts",
        ip: group.ip,
        user: users.join(', '),
        details: `Impossible login burst: ${group.events.length} successful logins in 1m targeting multiple users: [${users.join(', ')}]`,
        severity: severity,
        likelihood: likelihood,
        impact: impact,
        riskScore: riskScore,
        timeFlag: "Unusual activity pattern",
        status: status,
        first_attempt_time: firstAttempt,
        last_attempt_time: lastAttempt,
        detection_time: lastAttempt,
        outcome: "Multiple accounts accessed",
        events: group.events
      });
    }
  });
  
  // Sort incidents by risk score descending
  incidents.sort((a, b) => b.riskScore - a.riskScore);
}

// --- UI Rendering Helpers ---

function badge(s) {
  return `<span class="badge-severity badge-${s}">${s}</span>`;
}

function statusBadge(status) {
  const statusClass = status.toLowerCase() === "contained" ? "status-contained" : "status-active";
  return `<span class="badge-status ${statusClass}">${status.toUpperCase()}</span>`;
}

// --- UI Actions ---

window.selectIncident = (id) => {
  selectedIncidentId = id;
  renderInvestigation();
};

window.triggerContainment = (id) => {
  const inc = incidents.find(x => x.id === id);
  if (!inc) return;
  
  const confirmBlock = confirm(`Run containment script to block IP ${inc.ip}?`);
  if (confirmBlock) {
    containedIPs.add(inc.ip);
    
    // Simulate containment response timestamp (last_attempt_time + 45s)
    const lastSecs = timeToSeconds(inc.last_attempt_time);
    containmentTimes[inc.id] = lastSecs + 45;
    
    // Re-evaluate incidents to apply Contained state
    runDetectionEngine();
    render();
    
    // Update terminal output logs
    const log = generateContainmentLog(inc);
    document.querySelector("#response").innerHTML = `
      <div style="font-weight:bold; color:#75e19b; margin-bottom:5px;">Containment execution succeeded:</div>
      <div class="terminal-box">${log}</div>
    `;
  }
};

window.downloadIncidentReport = (id) => {
  const inc = incidents.find(x => x.id === id);
  if (!inc) return;
  
  const count = inc.events.filter(e => e.event.toLowerCase().includes("failed")).length;
  const action = `IP ${inc.ip} blocked via iptables (analyst-confirmed)`;
  const todayStr = new Date().toISOString().slice(0, 10);
  
  const reportText = `
INCIDENT REPORT
================
Incident ID: ${inc.id}
Detection Time: ${todayStr} ${inc.detection_time}
Attack Type: ${inc.type}
MITRE ATT&CK Technique: ${inc.mitre}
Source IP: ${inc.ip}
Target Account: ${inc.user}
Failed Attempts: ${count}
Time Analysis: ${inc.timeFlag}
Risk Score: ${inc.riskScore}
Severity: ${inc.severity}
Response Action: ${action}
Response Type: Semi-automated (Splunk detects, analyst confirms containment)
Framework Followed: NIST IR Lifecycle
Final Status: Contained

--- Known Limitations (for transparency) ---
- Detection window is fixed at 2 minutes; attacks spanning window
  boundaries may undercount.
- Containment requires analyst confirmation (not fully autonomous).
  `.trim();

  const blob = new Blob([reportText], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = `incident_report_${inc.id}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// --- Log Generator for Terminal Simulation ---

function generateContainmentLog(inc) {
  const cleanIp = inc.ip;
  const count = inc.events.filter(e => e.event.toLowerCase().includes("failed")).length;
  const attackHour = parseInt(inc.first_attempt_time.split(":")[0], 10);
  return `
$ ./incident_response.sh ${cleanIp} ${count} "${inc.user}" ${attackHour}
=== SOC ALERT ===
Incident ID: ${inc.id}
Source IP: ${cleanIp}
Failed Attempts: ${count}
Time Flag: ${inc.timeFlag}
Risk Score: ${inc.riskScore} (${inc.severity})
MITRE ATT&CK: ${inc.mitre}
==================
Confirm containment: block ${cleanIp}? (y/n): y
sudo iptables -A INPUT -s "${cleanIp}" -j DROP
IP ${cleanIp} blocked via iptables (analyst-confirmed)
Incident report saved: incident_report_${inc.id}.txt
  `.trim();
}

// --- Render Functions ---

function renderInvestigation() {
  const inc = incidents.find(x => x.id === selectedIncidentId);
  const container = document.querySelector("#investigationContent");
  
  if (!inc) {
    container.innerHTML = `<p style="color:#8d9ab1;">Select an active incident from the list to start a deep-dive investigation.</p>`;
    return;
  }

  // Create timeline markup
  const timelineItems = inc.events.map(e => {
    const isFailed = e.event.toLowerCase().includes("failed");
    const isSuccess = e.event.toLowerCase().includes("accepted");
    const logClass = isFailed ? "failed" : (isSuccess ? "success" : "");
    return `
      <div class="timeline-item ${logClass}">
        <span class="timeline-time">${e.time}</span>
        <span style="color:#e8eef8;">${e.source}</span>: ${e.event} (${e.user || '-'} from ${e.ip})
      </div>
    `;
  }).join("");

  const detectDuration = timeToSeconds(inc.detection_time) - timeToSeconds(inc.first_attempt_time);

  container.innerHTML = `
    <div style="margin-top:10px;">
      <h3 style="margin:0 0 10px;">${inc.type} Deep-Dive</h3>
      <table style="width:100%; font-size:12px; margin-bottom:15px; border-collapse:collapse;">
        <tr style="border-bottom: 1px solid #1c253c;"><td style="color:#8d9ab1; padding:6px 0;">Incident ID:</td><td style="padding:6px 0;"><b>${inc.id}</b></td></tr>
        <tr style="border-bottom: 1px solid #1c253c;"><td style="color:#8d9ab1; padding:6px 0;">MITRE ATT&CK:</td><td style="padding:6px 0;"><code style="background:#24304a; padding:2px 4px; border-radius:3px;">${inc.mitre}</code></td></tr>
        <tr style="border-bottom: 1px solid #1c253c;"><td style="color:#8d9ab1; padding:6px 0;">Source IP:</td><td style="padding:6px 0;"><b style="color:#ff5e5e">${inc.ip}</b></td></tr>
        <tr style="border-bottom: 1px solid #1c253c;"><td style="color:#8d9ab1; padding:6px 0;">Target User:</td><td style="padding:6px 0;"><b>${inc.user}</b></td></tr>
        <tr style="border-bottom: 1px solid #1c253c;"><td style="color:#8d9ab1; padding:6px 0;">Detection Window:</td><td style="padding:6px 0;"><b>${inc.first_attempt_time} → ${inc.detection_time}</b></td></tr>
        <tr style="border-bottom: 1px solid #1c253c;"><td style="color:#8d9ab1; padding:6px 0;">Time to Detect:</td><td style="padding:6px 0;"><b>${detectDuration} seconds</b></td></tr>
        <tr style="border-bottom: 1px solid #1c253c;"><td style="color:#8d9ab1; padding:6px 0;">Risk Scoring:</td><td style="padding:6px 0;">
          <code>Likelihood (${inc.likelihood}) × Impact (${inc.impact}) = <b>${inc.riskScore}</b></code>
          <br><small style="color:#8d9ab1; font-size:10px;">(${inc.timeFlag})</small>
        </td></tr>
        <tr style="border-bottom: 1px solid #1c253c;"><td style="color:#8d9ab1; padding:6px 0;">Outcome:</td><td style="padding:6px 0;"><b>${inc.outcome}</b></td></tr>
      </table>
      
      <h4 style="margin:15px 0 5px;">Attack Event Timeline</h4>
      <div class="investigation-timeline">
        ${timelineItems}
      </div>

      <h4 style="margin:15px 0 5px;">NIST Incident Response Steps</h4>
      <ul class="nist-steps">
        <li class="done">✓ Detection & Analysis <small style="color:#8d9ab1;">(Detected in ${detectDuration}s)</small></li>
        <li class="${inc.status === 'Contained' ? 'done' : ''}">
          ${inc.status === 'Contained' ? '✓' : '☐'} Containment, Eradication & Recovery
          ${inc.status === 'Contained' ? `<small style="color:#8d9ab1;">(IP blocked)</small>` : ''}
        </li>
        <li class="${inc.status === 'Contained' ? 'done' : ''}">
          ${inc.status === 'Contained' ? '✓' : '☐'} Post-Incident Activity
          ${inc.status === 'Contained' ? `<small style="color:#8d9ab1;">(Report generated)</small>` : ''}
        </li>
      </ul>

      ${inc.status === 'Contained' ? `
        <div style="margin-top:15px;">
          <a class="btn-download" href="#" onclick="downloadIncidentReport('${inc.id}')">Download NIST Incident Report</a>
        </div>
      ` : `
        <div style="margin-top:15px; font-size:12px; color:#ffe69d;">
          ⚠️ Contain IP to complete response phase & extract report.
        </div>
      `}
    </div>
  `;
}

function render() {
  // Update Cards count
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  
  incidents.forEach(inc => {
    if (inc.severity === "Critical") criticalCount++;
    else if (inc.severity === "High") highCount++;
    else if (inc.severity === "Medium") mediumCount++;
  });
  
  document.querySelector("#critical").textContent = criticalCount;
  document.querySelector("#high").textContent = highCount;
  document.querySelector("#medium").textContent = mediumCount;
  document.querySelector("#events").textContent = events.length;
  
  // Calculate MTTD and MTTR
  let mttdSum = 0;
  let mttdCount = 0;
  let mttrSum = 0;
  let mttrCount = 0;
  
  incidents.forEach(inc => {
    const diff = timeToSeconds(inc.detection_time) - timeToSeconds(inc.first_attempt_time);
    mttdSum += diff;
    mttdCount++;
    
    if (inc.status === "Contained" && containmentTimes[inc.id]) {
      const respDiff = containmentTimes[inc.id] - timeToSeconds(inc.detection_time);
      mttrSum += respDiff;
      mttrCount++;
    }
  });
  
  const avgMttd = mttdCount > 0 ? Math.round(mttdSum / mttdCount) : 0;
  const avgMttr = mttrCount > 0 ? Math.round(mttrSum / mttrCount) : 0;
  
  document.querySelector("#mttd").textContent = avgMttd + "s";
  document.querySelector("#mttr").textContent = avgMttr + "s";

  // Render Incidents List
  const listContainer = document.querySelector("#incidents");
  if (incidents.length === 0) {
    listContainer.innerHTML = `<p style="color:#8d9ab1; text-align:center; padding:20px;">No active threat incidents detected.</p>`;
  } else {
    listContainer.innerHTML = incidents.map(x => {
      const isContained = x.status === "Contained";
      const fillCol = x.severity === 'Critical' ? '#ff5e5e' : x.severity === 'High' ? '#ffa05e' : '#ffe69d';
      return `
        <div class="incident" style="cursor: pointer; padding: 15px; border-bottom: 1px solid #24304a;" onclick="selectIncident('${x.id}')">
          <div>
            ${statusBadge(x.status)}
            <b>${x.type}</b> ${badge(x.severity)}
          </div>
          <small style="display:block; color:#8d9ab1; margin-top: 6px;">
            Risk Score: ${x.riskScore}/25 · MITRE: ${x.mitre}
          </small>
          <div style="font-size:12px; margin-top:5px; color:#e8eef8;">${x.details}</div>
          <div class="risk-meter"><div class="risk-fill" style="width: ${(x.riskScore/25)*100}%; background: ${fillCol}"></div></div>
          <div style="margin-top:10px;">
            <button class="btn-action btn-investigate" onclick="event.stopPropagation(); selectIncident('${x.id}')">Investigate</button>
            <button class="btn-action btn-contain" ${isContained ? 'disabled' : ''} onclick="event.stopPropagation(); triggerContainment('${x.id}')">Contain IP</button>
          </div>
        </div>
      `;
    }).join("");
  }

  // Render Events Table
  document.querySelector("#eventsTable").innerHTML = events.slice().reverse().map(e => `
    <tr>
      <td>${e.time}</td>
      <td>${e.source}</td>
      <td>${e.event}</td>
      <td>${e.user}</td>
      <td>${e.ip}</td>
      <td>${e.dest_port !== undefined ? e.dest_port : "-"}</td>
      <td><span class="badge-severity badge-${e.severity}">${e.severity}</span></td>
    </tr>
  `).join("");
}

// --- Atta// --- Custom Alert Toast Notification ---

function triggerCustomAlert(title, message, type, icon) {
  const alertBox = document.getElementById("customAlert");
  const alertTitle = document.getElementById("alertTitle");
  const alertBody = document.getElementById("alertBody");
  const alertIcon = document.getElementById("alertIcon");
  
  alertTitle.textContent = title;
  alertBody.textContent = message;
  alertIcon.textContent = icon;
  
  // Reset animations
  alertBox.style.animation = 'none';
  alertBox.offsetHeight; // trigger reflow
  alertBox.style.animation = null;
  
  // Set theme styles
  if (type === "critical") {
    alertBox.style.background = "#281212";
    alertBox.style.border = "1px solid #ff5e5e";
    alertBox.style.borderLeft = "6px solid #ff5e5e";
    alertBox.style.animation = "slideIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), pulseBorder 1.5s infinite alternate";
  } else if (type === "warning") {
    alertBox.style.background = "#2a1b10";
    alertBox.style.border = "1px solid #ffa05e";
    alertBox.style.borderLeft = "6px solid #ffa05e";
    alertBox.style.animation = "slideIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)";
  } else {
    alertBox.style.background = "#111a2e";
    alertBox.style.border = "1px solid #42c5f5";
    alertBox.style.borderLeft = "6px solid #42c5f5";
    alertBox.style.animation = "slideIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)";
  }
  
  alertBox.style.display = "block";
  
  if (window.alertTimeout) clearTimeout(window.alertTimeout);
  window.alertTimeout = setTimeout(() => {
    alertBox.style.display = "none";
  }, 6000);
}

// --- Dynamic Relative Time Generator ---

function getOffsetTime(offsetSeconds) {
  const now = new Date();
  now.setSeconds(now.getSeconds() + offsetSeconds);
  const h = now.getHours().toString().padStart(2, '0');
  const m = now.getMinutes().toString().padStart(2, '0');
  const s = now.getSeconds().toString().padStart(2, '0');
  return `${h}:${m}:${s}`;
}

// --- Attack Simulator ---

function simulateAttack(scenario) {
  const newEvents = [];
  
  if (scenario === "ssh_std") {
    // Generate 5 failed logins within 15 seconds ending just now
    const times = [getOffsetTime(-15), getOffsetTime(-12), getOffsetTime(-9), getOffsetTime(-6), getOffsetTime(-3)];
    times.forEach(t => {
      newEvents.push({ time: t, source: "sshd", event: "Failed password", user: "webuser", ip: "10.10.40.12", severity: "HIGH" });
    });
    
    events.push(...newEvents);
    runDetectionEngine();
    render();
    
    triggerCustomAlert(
      "SSH Brute Force Detected", 
      "Source IP: 10.10.40.12\nTarget Account: webuser\nFailed Attempts: 5 within 15s\nSeverity: HIGH (Score 9)", 
      "warning", 
      "🔑"
    );
  } else if (scenario === "ssh_esc") {
    // Generate 5 failed logins + 1 success within 15 seconds ending just now
    const times = [getOffsetTime(-15), getOffsetTime(-12), getOffsetTime(-9), getOffsetTime(-6), getOffsetTime(-3)];
    times.forEach(t => {
      newEvents.push({ time: t, source: "sshd", event: "Failed password", user: "testuser", ip: "10.10.30.22", severity: "HIGH" });
    });
    newEvents.push({ time: getOffsetTime(0), source: "sshd", event: "Accepted password", user: "testuser", ip: "10.10.30.22", severity: "INFO" });
    
    events.push(...newEvents);
    runDetectionEngine();
    render();
    
    triggerCustomAlert(
      "CRITICAL: Compromise Escalation", 
      "SSH Brute Force worked! Success login detected from 10.10.30.22 after failures.\nSeverity: CRITICAL", 
      "critical", 
      "💀"
    );
  } else if (scenario === "ssh_off") {
    // Force off-hours by hardcoding to 3:40 AM
    const times = ["03:40:01", "03:40:03", "03:40:06", "03:40:08", "03:40:11"];
    times.forEach(t => {
      newEvents.push({ time: t, source: "sshd", event: "Failed password", user: "root", ip: "10.10.90.11", severity: "HIGH" });
    });
    
    events.push(...newEvents);
    runDetectionEngine();
    render();
    
    triggerCustomAlert(
      "Off-Hours Root Brute Force", 
      "Source IP: 10.10.90.11\nTarget Account: root\nTime: 03:40 AM (Off-hours)\nSeverity: CRITICAL (Score 20)", 
      "critical", 
      "🌙"
    );
  } else if (scenario === "port_scan") {
    // Generate port scan hitting 6 unique ports within 30 seconds ending just now
    const ports = [22, 23, 80, 443, 3389, 8080];
    const times = [getOffsetTime(-25), getOffsetTime(-20), getOffsetTime(-15), getOffsetTime(-10), getOffsetTime(-5), getOffsetTime(0)];
    ports.forEach((p, idx) => {
      newEvents.push({ time: times[idx], source: "firewall", event: `Connection to port ${p}`, user: "-", ip: "10.10.50.88", dest_port: p, severity: "LOW" });
    });
    
    events.push(...newEvents);
    runDetectionEngine();
    render();
    
    triggerCustomAlert(
      "Port Scan Detected", 
      "Source IP: 10.10.50.88\n6 unique destination ports hit within 30s\nSeverity: MEDIUM (Score 9)", 
      "warning", 
      "🌐"
    );
  } else if (scenario === "impossible_burst") {
    // Generate 3 successful logins in 10 seconds ending just now
    const users = ["admin1", "admin2", "admin3"];
    const times = [getOffsetTime(-10), getOffsetTime(-5), getOffsetTime(0)];
    users.forEach((u, idx) => {
      newEvents.push({ time: times[idx], source: "sshd", event: "Accepted password", user: u, ip: "10.10.60.99", severity: "INFO" });
    });
    
    events.push(...newEvents);
    runDetectionEngine();
    render();
    
    triggerCustomAlert(
      "CRITICAL: Impossible Login Burst", 
      "Source IP: 10.10.60.99\n3 successful administrative logins in 10 seconds!\nSeverity: CRITICAL", 
      "critical", 
      "⚡"
    );
  }
}

// --- Initialize Page ---

document.querySelector("#simulate").onclick = () => {
  const scenario = document.querySelector("#scenarioSelect").value;
  simulateAttack(scenario);
};

// --- Documentation Panel Toggling & Tab Switching ---

window.toggleDocs = () => {
  const panel = document.querySelector("#docsPanel");
  const arrow = document.querySelector("#docsToggleArrow");
  if (panel.style.display === "none") {
    panel.style.display = "block";
    arrow.textContent = "▲";
  } else {
    panel.style.display = "none";
    arrow.textContent = "▼";
  }
};

window.switchDocTab = (tabName) => {
  // Hide all contents
  document.querySelectorAll(".doc-tab-content").forEach(el => el.style.display = "none");
  
  // Show target content
  document.querySelector(`#docTab-${tabName}`).style.display = "block";
  
  // Update buttons styling
  const tabs = ["ssh", "port", "bash"];
  tabs.forEach(t => {
    const btn = document.querySelector(`#tabBtn-${t}`);
    if (t === tabName) {
      btn.style.background = "#42c5f5";
      btn.style.color = "#0a1020";
    } else {
      btn.style.background = "#1c253c";
      btn.style.color = "#8d9ab1";
    }
  });
};

// Run Detection Engine and render default logs on start
runDetectionEngine();
render();
