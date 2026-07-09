# SecureVis — Linux Security Visualization & Adaptive Sandbox System

SecureVis is a Linux-based security monitoring and sandboxing platform designed to provide real-time visibility into system behavior, suspicious process activity, and isolated execution environments.

The project combines OS-level isolation mechanisms with behavioral monitoring and a terminal-based visualization dashboard to help analyze potentially unsafe programs without permanently affecting the host system.

---

## Overview

Traditional security tools usually focus only on detection after damage occurs. SecureVis follows a prevention-first approach by combining:

- Isolated execution
- Real-time system monitoring
- Behavioral anomaly detection
- Deception-based traps
- Forensic analysis

SecureVis creates a controlled environment where suspicious applications can execute while the system continuously observes CPU behavior, memory usage, filesystem changes, process activity, and security events.

---

# Key Features

## 1. Real-Time System Monitoring Dashboard

SecureVis includes a Textual-based terminal UI dashboard that displays:

- CPU utilization
- Memory consumption
- Disk usage
- Network statistics
- Running processes
- Process risk levels

System information is collected continuously using psutil and displayed in real time.

---

## 2. Process Behavior Analysis

Each running process is monitored using behavioral profiling.

Collected metrics:

- Process ID
- Process name
- CPU consumption
- Memory consumption
- Average CPU behavior

The system maintains historical CPU patterns for each process and detects abnormal behavior.

Detection logic includes:

- Sudden CPU spikes
- Resource abuse
- Unusual process behavior

---

## 3. Threat Scoring Engine

SecureVis assigns risk levels dynamically:

LOW:
Normal system activity

MEDIUM:
Possible abnormal behavior detected

HIGH:
Potentially dangerous activity

Risk calculation considers:

- CPU anomalies
- Resource spikes
- Memory usage patterns

---

## 4. Secure Sandbox Environment

SecureVis provides a hardened Linux sandbox for executing suspicious files safely.

Security layers:

### OverlayFS Isolation

Uses a copy-on-write filesystem model.

Original files remain untouched while all modifications happen inside a temporary overlay layer.

Features:

- Reset after execution
- Discard unwanted changes
- Prevent permanent filesystem modification

---

### Linux Namespace Isolation

Uses kernel namespaces to isolate:

- Processes
- Network access
- IPC communication
- Host identity

Implemented isolation:

- PID Namespace
- Network Namespace
- IPC Namespace
- UTS Namespace

---

### Capability Restriction

Linux capabilities are dropped to reduce process privileges.

Restricted capabilities include:

- Raw network access
- Kernel module modification
- System administration privileges
- Debugging capabilities

---

### Resource Limiting

Kernel resource controls prevent abuse.

Limits include:

- CPU usage
- Memory usage
- File descriptors
- Process creation
- File size

---

# Deception-Based Security

SecureVis uses defensive deception techniques to identify suspicious behavior.

## Honeypot Files

Fake sensitive files are created inside the sandbox:

Examples:

- passwords.txt
- id_rsa
- .env
- api_tokens.json
- database.conf

Accessing these files triggers security events.

---

## File Activity Monitoring

Using Linux inotify, SecureVis monitors:

- File creation
- Modification
- Deletion
- Access attempts
- Permission changes

Suspicious filesystem behavior is logged automatically.

---

# Runtime Behavior Detection

SecureVis monitors sandbox activity for:

- High CPU abuse
- Unexpected child process creation
- Suspicious memory regions
- Possible process injection behavior

---

# Syscall Monitoring

System calls are traced during execution.

Tracked activity:

- File operations
- Process execution
- Network activity

This provides low-level forensic visibility.

---

# Forensic Reporting

After every sandbox session SecureVis generates reports containing:

- Modified files
- Created files
- SHA-256 hashes
- Suspicious events
- Security verdict

Verdict categories:

- CLEAN
- SUSPICIOUS
- MALICIOUS

---

# Architecture
