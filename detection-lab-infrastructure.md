# Lab Architecture & Asset Inventory

## 1. Overview
This lab simulates a small enterprise environment designed for detection engineering, adversary simulation, and telemetry analysis.

It provides:
- Host-based visibility via centralized logging (Splunk)
- Network-based visibility via network monitoring and intrusion detection (SecurityOnion)
- A controlled environment to validate detections aligned to MITRE ATT&CK

---

## 2. Objectives
- Simulate realistic attacker behavior in a controlled environment
- Collect and centralize host and network telemetry
- Develop and validate detection logic
- Measure detection coverage and identify gaps
- Build a repeatable Detection-as-Code workflow

---

## 3. Network Architecture

### Internal Lab Network
- Subnet: `10.10.10.0/24`
- Purpose: Core enterprise environment for all lab systems

### Management Network
- Subnet: `192.168.116.0/24`
- Purpose: Management access for monitoring platform and updates

---

## 4. Systems Overview

| System | Hostname | Role | IP Address |
|--------|----------|------|-----------|
| Domain Controller | `CORP-DC-01` | Active Directory / DNS | 10.10.10.10 |
| Windows Endpoint | `WIN-ENDPOINT-01` | User workstation | 10.10.10.20 |
| SIEM Platform | `SPLUNK-SERVER` | Log ingestion and detection | 10.10.10.30 |
| Network Sensor | `SENSOR-NSM` | Network monitoring and detection | 10.10.10.40 / 192.168.116.130 |
| Attacker VM | `ATTACKER` | Adversary simulation | 10.10.10.50 |

---

## 5. Asset Inventory

### CORP-DC-01 (Domain Controller)
- Operating System: Windows Server
- Role: Active Directory and DNS services
- Domain: `corp.local`

**Responsibilities**
- Authentication and directory services
- DNS resolution
- Account and policy management

**Detection Relevance**
- Authentication activity
- Directory access patterns
- Lateral movement behaviors

---

### WIN-ENDPOINT-01 (Endpoint)
- Operating System: Windows
- Role: Primary user workstation and attack target

**Responsibilities**
- Generates endpoint telemetry
- Executes simulated adversary behaviors
- Forwards logs to centralized logging platform

**Detection Relevance**
- Process execution activity
- File and registry changes
- Script and command-line execution

---

### SPLUNK-SERVER (SIEM)
- Operating System: Linux
- Role: Centralized logging and detection platform

**Responsibilities**
- Ingests host-based telemetry
- Stores and indexes logs
- Supports detection development and analysis

**Detection Relevance**
- Event correlation
- Behavioral analysis
- Detection logic execution

---

### SENSOR-NSM (Network Monitoring)
- Operating System: Security-focused Linux distribution
- Role: Network detection and monitoring

**Interfaces**
- Lab Network: `10.10.10.40`
- Management Network: `192.168.116.130`

**Responsibilities**
- Monitors network traffic
- Generates network metadata and alerts
- Provides visibility into network activity

**Detection Relevance**
- Network scanning and reconnaissance
- Protocol and service activity
- East-west traffic analysis

---

### ATTACKER (Adversary Simulation)
- Operating System: Linux
- Role: Simulated attacker system

**Responsibilities**
- Generates controlled attack traffic
- Performs reconnaissance and enumeration
- Executes attack scenarios for validation

**Detection Relevance**
- Source of simulated adversary activity
- Enables repeatable detection testing
- Supports validation of network and host detections

---

## 6. Detection Coverage

| Layer | Coverage |
|------|--------|
| Host | Endpoint and system-level telemetry |
| Network | Traffic analysis and network-based detection |

---

## 7. Access Points

- SIEM Web Interface: `http://10.10.10.30:8000`
- SIEM API: `https://10.10.10.30:8089`
- Network Monitoring Interface: `https://192.168.116.130`

---

## 8. Summary

This lab provides full visibility across both host and network layers, enabling:
- Detection engineering and validation
- Adversary simulation
- Telemetry analysis
- Continuous improvement of detection coverage

The environment is designed to be modular and scalable, allowing additional systems, telemetry sources, and detection capabilities to be integrated over time.