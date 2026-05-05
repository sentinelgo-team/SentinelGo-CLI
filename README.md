# SentinelGo CLI — Insider Threat Detection Engine

> **A high-performance, Go-based command-line tool for detecting insider threats through log analysis, rule-based detection, and risk scoring.**

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Solution](#solution)
- [Core Features](#core-features)
- [Threat Model](#threat-model)
- [Architecture](#architecture)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Input Format](#input-format)
- [Detection Logic](#detection-logic)
- [Risk Scoring Model](#risk-scoring-model)
- [Output Example](#output-example)
- [Exit Codes](#exit-codes)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Use Cases](#use-cases)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**SentinelGo CLI** is a command-line cybersecurity tool designed to detect insider threats through structured log analysis, rule-based behavioral detection, and quantitative risk scoring. Built in Go, it emphasizes performance, modularity, and extensibility for enterprise-grade security analysis.

---

## Problem Statement

Insider threats are inherently difficult to detect due to:

- **Legitimate access privileges** — malicious or negligent insiders already have authorized credentials
- **Lack of behavioral baselines** — deviation is hard to measure without established norms
- **Subtle anomalies** — insider activity often blends seamlessly with normal usage

Traditional security systems focus on perimeter defense, leaving internal threat vectors under-monitored.

---

## Solution

SentinelGo CLI addresses this gap by:

- Parsing structured and unstructured logs
- Detecting anomalous behavior using configurable rules
- Assigning risk scores to user actions
- Generating actionable alerts for security teams

---

## Core Features

| Feature | Description |
|---|---|
| High-performance log parsing | Go-native parser for JSON and structured log formats |
| Rule-based anomaly detection | Configurable rule engine targeting known threat patterns |
| Risk scoring system | Quantitative evaluation of user activity |
| CLI-driven workflow | Automatable interface for SOC pipelines |
| Modular architecture | Clean separation of parsing, analysis, scoring, and output |
| AI-ready design | Optional AI layer for future behavioral modeling |

---

## Threat Model

SentinelGo targets the following insider threat categories:

- **Malicious Insider** — intentional misuse of elevated privileges
- **Negligent Insider** — accidental risky behavior leading to exposure
- **Compromised Account** — external attacker operating through valid credentials

---

## Architecture

```
Log Input → Parser → Normalization → Rule Engine → Risk Scorer → Output / Alert
                                                         ↓
                                              (Optional AI Layer)
```

Each stage is independently modular, enabling targeted testing, extension, and future integration with real-time streaming or AI-based behavioral models.

---

## Installation

### Prerequisites

- [Go 1.20](https://golang.org/dl/) or later
- [Git](https://git-scm.com/)

### Steps

```bash
git clone https://github.com/sentinelgo-team/SentinelGo.git
cd SentinelGo
go mod tidy
go build -o sentinelgo
```

---

## CLI Usage

### Basic Command

```bash
./sentinelgo --input <log_file> --mode <analysis|monitor>
```

### Available Flags

| Flag | Description | Required |
|---|---|---|
| `--input` | Path to log file | Yes |
| `--mode` | Operation mode: `analysis` or `monitor` | Yes |
| `--config` | Path to configuration file | No |
| `--verbose` | Enable detailed output | No |

> **Note:** Flags are aligned with the current implementation. If you fork or extend the project, update this section accordingly. Do not use undocumented flags.

### Example Usage

```bash
./sentinelgo --input logs.json --mode analysis
./sentinelgo --input logs.json --mode analysis --config configs/config.yaml --verbose
```

---

## Input Format

SentinelGo accepts JSON-formatted log files. Each log entry must include the following fields:

```json
{
  "user": "admin",
  "action": "login",
  "timestamp": "2026-05-01T02:15:00Z",
  "status": "success"
}
```

| Field | Type | Description |
|---|---|---|
| `user` | string | Username or identity performing the action |
| `action` | string | Type of activity (e.g., `login`, `file_access`, `privilege_change`) |
| `timestamp` | string (ISO 8601) | UTC timestamp of the event |
| `status` | string | Outcome of the event (`success`, `failure`) |

---

## Detection Logic

### Rule-Based Detection

The rule engine evaluates each log entry against the following threat patterns:

- Login outside defined working hours
- Multiple failed login attempts exceeding the configured threshold
- Privilege escalation events

### Behavioral Analysis

- Baseline user activity comparison
- Deviation detection from established usage norms

Rules are configurable via `configs/config.yaml`. See the [Configuration](#configuration) section.

---

## Risk Scoring Model

Each event contributes to a cumulative user risk score calculated as:

```
Risk Score = Σ (Event Weight × Severity)
```

### Default Event Weights

| Event Type | Weight |
|---|---|
| Failed Login | 10 |
| Off-Hours Login | 20 |
| Privilege Escalation | 40 |

Weights are fully configurable. Modify values in `configs/config.yaml` to reflect your organization's risk tolerance.

---

## Output Example

```
[ALERT] User: admin
        Event: Privilege Escalation
        Risk Score: 85 (HIGH)
        Action Required: Immediate Review
```

Risk severity levels map to the thresholds defined in your configuration:

| Level | Score Range |
|---|---|
| LOW | < 30 |
| MEDIUM | 30 – 59 |
| HIGH | 60 – 79 |
| CRITICAL | ≥ 80 |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success — no threats detected |
| `1` | Invalid input — malformed flags or file not found |
| `2` | Processing error — internal failure during analysis |
| `3` | Threat detected — one or more alerts generated |

Exit codes enable integration with automation pipelines, SIEM systems, and shell scripts.

---

## Project Structure

```
SentinelGo/
├── cmd/           # CLI entry point and flag parsing
├── parser/        # Log parsing and normalization
├── analyzer/      # Rule-based detection logic
├── scoring/       # Risk scoring engine
├── configs/       # YAML configuration files
└── utils/         # Helper utilities and shared functions
```

---

## Configuration

SentinelGo uses a YAML configuration file to control detection thresholds and rules.

**Default path:** `configs/config.yaml`

```yaml
thresholds:
  low: 30
  medium: 60
  high: 80

rules:
  off_hours_login: true
  failed_login_limit: 5
```

Pass a custom configuration file using the `--config` flag:

```bash
./sentinelgo --input logs.json --mode analysis --config /path/to/custom-config.yaml
```

---

## Use Cases

- **Security Operations Center (SOC) monitoring** — integrate into analyst workflows for real-time triage
- **Insider threat detection in enterprises** — proactive monitoring of privileged user activity
- **Cybersecurity research** — rule testing and behavioral experimentation on log datasets
- **Log-based anomaly detection** — lightweight analysis without requiring a full SIEM deployment

---

## Limitations

- Detection accuracy depends on the quality and completeness of input logs
- Rule-based detection may generate false positives in atypical but legitimate usage patterns
- Real-time log streaming is not yet implemented in the current version
- The AI module is in design phase and not fully integrated

> These limitations are documented in the interest of intellectual honesty. Contributors are encouraged to address them via the roadmap below.

---

## Roadmap

- [ ] Real-time log streaming
- [ ] AI-based anomaly detection (ML behavioral models)
- [ ] Dashboard visualization
- [ ] SIEM integration (Splunk, Elastic, IBM QRadar)
- [ ] Extended log format support (syslog, CEF, Windows Event Log)

---

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit with clear, descriptive messages
4. Submit a pull request with a summary of changes

### Standards

- Follow [Go best practices](https://go.dev/doc/effective_go) and idiomatic Go style
- Maintain modular design — keep packages loosely coupled
- Include unit tests for new detection rules and scoring logic
- Update documentation for any new CLI flags or configuration options

---

## License

This project is licensed under the [MIT License](LICENSE).

---

*SentinelGo is developed for cybersecurity research and enterprise security use. Use responsibly and in compliance with applicable laws and organizational policies.*
