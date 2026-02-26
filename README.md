# Cybersecurity Incident Response Simulation Tool

A lightweight Flask application for simulating cybersecurity incidents and testing response readiness.

## What it does

- Simulates common attack scenarios (port scan, DoS attempt, credential stuffing).
- Generates incident telemetry including severity, confidence, and packet preview.
- Tracks detection coverage and severity distribution in a resilience dashboard.
- Suggests automated response actions to expose strategy gaps.

## Stack

- **Backend/UI:** Flask
- **Network event simulation:** Scapy packet preview generation (safe and offline)
- **Tests:** Pytest

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.main
```

Open: `http://localhost:5000`

## API snippets

Simulate an event:

```bash
curl -X POST http://localhost:5000/simulate \
  -H "Content-Type: application/json" \
  -d '{"event_type":"port_scan","source_ip":"198.51.100.10"}'
```

Reset simulation state:

```bash
curl -X POST http://localhost:5000/reset -H "Content-Type: application/json" -d '{}'
```

## Notes

This tool is meant for controlled simulation and tabletop drills. It does not launch real attacks.
