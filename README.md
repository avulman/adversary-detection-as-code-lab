# Adversary Detection as Code Lab

This project simulates a small enterprise environment to design, validate, and operationalize detections across both host and network telemetry.

The focus is not just detection creation, but building a **repeatable detection engineering workflow** supported by validation, testing, and CI/CD.

---

## What This Project Demonstrates

- Detection engineering across **endpoint and network telemetry**
- Validation of detections using **structured test data and PCAP replay**
- CI/CD pipelines for **detection quality assurance and deployment**
- Integration of **Splunk (host)** and **Security Onion (network)**
- Mapping detections to **MITRE ATT&CK techniques**
- Treating detections as **version-controlled, testable code**

---

## Why This Matters

Many detection efforts fail due to lack of validation and consistency.

This project focuses on solving that problem by treating detections as code:
- version-controlled
- testable
- continuously validated
- deployable through CI/CD

The goal is not just to detect threats, but to ensure detections are reliable and maintainable over time.

--- 

## Project Goals

- Simulate realistic adversary behavior in a controlled lab
- Collect and centralize telemetry from multiple sources
- Develop detections aligned to MITRE ATT&CK
- Validate detections using repeatable test cases
- Track coverage and identify detection gaps
- Enforce structure and quality through CI/CD pipelines

---

## Quick Start

### Prerequisites

This project is designed for a **self-hosted Windows GitHub Actions runner** and a working lab environment.

Required components:

- Python 3.11
- Git
- Playwright
- Chromium browser for Playwright
- Suricata installed and accessible in `PATH`
- Splunk Enterprise with REST API access
- Splunk HTTP Event Collector (HEC) configured for test ingestion
- Security Onion UI accessible from the runner

## Workflow setup

This repository includes three GitHub Actions workflows:

1. `validate`  
   runs repository validation, syntax validation, and detection tests

2. `validate-and-deploy` for Splunk  
   validates and deploys Splunk detections as alerts

3. `validate-and-deploy-securityonion`  
   validates and deploys Security Onion detections through UI automation

### Important

These workflows are designed for a **self-hosted Windows runner** and will not function correctly on a default GitHub-hosted runner without major changes.

### Install dependencies

py -m pip install -r requirements.txt
py -m playwright install chromium

---

## Telemetry Sources

### Host-Based (Splunk)
- Windows Event Logs
- Sysmon
- Process creation and access events
- Registry and command-line activity

### Network-Based (Security Onion)
- Zeek connection logs
- Suricata alerts
- Protocol and traffic metadata

---

## Detection Lifecycle

This project models a full detection engineering lifecycle:

1. Adversary simulation generates telemetry
2. Alerts are analyzed by a cybersecurity analyst
3. Detections are developed and stored as code
4. CI/CD pipelines validate detections using test data
5. Validated detections are deployed back into the environment

This creates a continuous feedback loop for improving detection quality.

---

## Detection Validation

Each detection includes structured test coverage:

### Splunk
- JSON-based event fixtures
- Injected into a test index via HEC
- Queries executed and validated

### Suricata
- PCAP-based validation
- Traffic replayed against rules
- Alert generation verified

### Sigma
- JSON event samples
- Rule logic evaluated against expected matches

---

## CI/CD Pipeline

GitHub Actions pipelines enforce quality and automate deployment:

### Validation Pipeline
- Repository structure validation
- Detection syntax validation
- Splunk detection testing
- Suricata PCAP validation
- Sigma rule validation

### Deployment Pipelines
- Splunk detections deployed as alerts via API
- Security Onion detections deployed via UI automation (implemented with Playwright due to limited API support in the free version)

---

## Security Onion Deployment Approach

Security Onion detections are deployed using **Playwright-based UI automation**.

This approach was intentionally chosen to:
- Simulate real-world constraints where APIs may be limited
- Demonstrate automation capability across non-API systems
- Enable full lifecycle management (create/update/delete)

Note: This method is dependent on UI structure and may require adjustments across versions.

---

## Limitations

- Lab environment does not reflect full enterprise scale
- Detection logic is simplified and requires tuning for production
- Security Onion deployment relies on UI automation
- ATT&CK coverage is partial and expanding
- Detection scoring and prioritization is not yet implemented

---

## Future Improvements

- Expand ATT&CK coverage across additional tactics
- Add negative test cases (false positive validation)
- Introduce detection scoring / severity modeling
- Improve Sigma > SIEM translation workflows
- Add automated reporting / dashboards

---

## Summary

This project focuses on building detections the same way mature security teams do:

- structured
- validated
- version-controlled
- continuously improved

The goal is not just visibility, but **confidence in detection quality**.