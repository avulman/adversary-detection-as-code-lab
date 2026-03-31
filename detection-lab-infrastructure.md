# Lab Architecture & Infrastructure

This document describes the underlying environment used to support detection engineering, validation, and adversary simulation.

Unlike the README, which focuses on workflow and outcomes, this document focuses on **how the lab is built and how systems interact**.

---

## Overview

The lab simulates a small enterprise network with both host-based and network-based visibility.

It is designed to:
- Generate realistic telemetry
- Support repeatable adversary simulation
- Enable validation of detections across multiple data sources

---

## Network Design

### Internal Lab Network
- Subnet: 10.10.10.0/24
- Purpose: Core communication between all lab systems

### Management Network
- Subnet: 192.168.116.0/24
- Purpose: Administrative access to monitoring platforms

---

## Systems

| System | Hostname | Role | IP Address |
|--------|----------|------|-----------|
| Domain Controller | CORP-DC-01 | Active Directory / DNS | 10.10.10.10 |
| Endpoint | WIN-ENDPOINT-01 | User workstation | 10.10.10.20 |
| SIEM | SPLUNK-SERVER | Log ingestion and detection | 10.10.10.30 |
| Network Sensor | SENSOR-NSM | Network monitoring | 10.10.10.40 / 192.168.116.130 |
| Attacker | ATTACKER | Adversary simulation | 10.10.10.50 |

---

## System Roles & Detection Relevance

### CORP-DC-01 (Domain Controller)
- Provides authentication and directory services
- Handles DNS resolution within the lab

**Detection Relevance**
- Authentication patterns
- Account usage and anomalies
- Lateral movement indicators

---

### WIN-ENDPOINT-01 (Endpoint)
- Primary target for adversary activity
- Generates host-based telemetry

---

### SPLUNK-SERVER (SIEM)
- Centralizes host telemetry
- Executes detection logic

---

### SENSOR-NSM (Security Onion)
- Captures and analyzes network traffic
- Runs Zeek and Suricata

**Detection Relevance**
- Network scanning activity
- Protocol usage patterns
- East-west traffic visibility
- Alert generation from Suricata rules

---

### ATTACKER (Adversary Simulation)
- Generates controlled attack activity
- Used for repeatable validation scenarios

**Detection Relevance**
- Source of known-bad activity
- Enables consistent detection testing
- Supports validation across host and network layers

---

## Telemetry Flow

### Host-Based Flow
Endpoint > Sysmon > Splunk Forwarder > Splunk Index

### Network-Based Flow
Network Traffic > Security Onion > Zeek / Suricata > Alerts & Logs


---

## Detection Coverage Layers

| Layer | Coverage |
|------|--------|
| Host | Process, registry, command-line activity |
| Network | Connections, protocols, traffic patterns |

---

## Access Points

- Splunk Web: http://10.10.10.30:8000
- Splunk API: https://10.10.10.30:8089
- Security Onion UI: https://192.168.116.130

---

## Design Considerations

- Systems are intentionally minimal to keep detection logic focused
- Both host and network telemetry are required to validate coverage
- Adversary simulation is controlled and repeatable
- Environment is modular and can be expanded with additional hosts or sensors

---

## Summary

This lab provides:

- Controlled adversary simulation
- Full visibility across host and network telemetry
- A foundation for building and validating detections

It is designed to support **practical detection engineering**, not just theoretical analysis.