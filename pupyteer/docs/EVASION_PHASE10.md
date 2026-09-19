# Pupyteer — Phase 10: Evasion Testing

> **Detection-resilience testing capability** with controlled test configurations,
> reproducible builds, artifact hashes, test results recording, and Litterbox integration.

---

## Overview

Phase 10 adds a complete **evasion testing subsystem** to the Pupyteer red-team
framework. It gives operators the ability to validate whether their payload
artifacts are detected by various defensive controls (AV, EDR, SIEM, YARA, etc.)
before deploying them in a field engagement.

The subsystem is **explicitly gated behind a laboratory mode** (`evasion.test_mode`)
to prevent accidental production use.

### LitterBox Integration

[Litterbox](https://github.com/BlackSnufkin/LitterBox) is a self-hosted
payload-analysis sandbox for red teams. Once configured, Pupyteer will upload
artifact samples to Litterbox for static + dynamic analysis and retrieve a
detection score plus per-control breakdown.

---

## Architecture

```
PupyteerEngine
    └── EvasionTestManager         # core orchestrator
        ├── EvasionTestConfig      # test configuration
        ├── EvasionTestResult      # result record (persisted)
        ├── LitterboxClient        # HTTP integration with Litterbox sandbox
        └── EvasionTestModule      # TUI module (evasion_test / evasion_config)
```

### Data Flow

```
┌─────────────────────────────────────────────────────────┐
│  Operator sets test_mode=true (lab-only)                │
│                                                         │
│  ┌─────────────────┐     ┌──────────────────────────┐  │
│  │ TestConfig       │────▶│ EvasionTestManager       │  │
│  │ - name           │     │                          │  │
│  │ - artifact_path  │     │ 1. Validate config       │  │
│  │ - artifact_hash  │     │ 2. Verify hash           │  │
│  │ - controls[]     │     │ 3. Submit to Litterbox   │  │
│  │ - environment    │     │ 4. Parse detections      │  │
│  │ - test_mode=true │     │ 5. Persist results       │  │
│  └─────────────────┘     └─────────┬────────────────┘  │
│                                     │                   │
│                          ┌──────────▼──────────┐       │
│                          │ LitterboxClient     │       │
│                          │ - submit_sample()   │       │
│                          │ - poll_result()     │       │
│                          │ - get_report()      │       │
│                          │ - health_check()    │       │
│                          └──────────┬──────────┘       │
│                                     │                   │
│                          ┌──────────▼──────────┐       │
│                          │ Litterbox Server    │       │
│                          │ - /api/analyze      │       │
│                          │ - /api/jobs/{id}    │       │
│                          │ - /api/jobs/{id}/   │       │
│                          │        report       │       │
│                          └─────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

---

## Installation

1. **Litterbox (optional)** — Deploy Litterbox locally:
   ```bash
   git clone https://github.com/BlackSnufkin/LitterBox
   cd LitterBox
   docker compose up -d
   # Default: http://localhost:8080
   ```

2. **Pupyteer config** — Enable evasion in your `pupyteer.yaml`:
   ```yaml
   evasion:
     test_mode: true
     litterbox_url: "http://localhost:8080"
     litterbox_token: ""  # or PUPYTEER_EVASION__LITTERBOX_TOKEN env
     litterbox_timeout: 120
   ```

---

## Usage

### TUI Commands

From the Pupyteer TUI, use the evasion modules:

```
pupyteer > evasion_test action=list          # list recent tests
pupyteer > evasion_test action=stats         # show stats
pupyteer > evasion_test action=run \
              name=my-test \
              artifact_path=/tmp/payload.bin \
              environment=litterbox \
              controls=yara,windows_defender,amsi
pupyteer > evasion_config                    # show current config
```

### CLI Commands (headless)

```bash
python -m pupyteer.tui.commands.evasion_status
python -m pupyteer.tui.commands.evasion_run --name test1 --artifact /tmp/file --env local --controls yara,amsi
python -m pupyteer.tui.commands.evasion_list
python -m pupyteer.tui.commands.evasion_stats
```

### API Usage

```python
from pupyteer.server.evasion.models import EvasionTestConfig, TestEnvironment
from pupyteer.server.evasion.manager import EvasionTestManager

manager = EvasionTestManager(config, audit)
await manager.initialize()

cfg = EvasionTestConfig(
    name="test",
    artifact_path="/tmp/payload.bin",
    artifact_hash_sha256="abc123...",
    environment=TestEnvironment.LITTERBOX.value,
    controls=["yara", "windows_defender"],
    test_mode=True,
)
result = await manager.run_test(cfg)
print(result.detection_overall)       # "undetected" / "detected"
print(result.detected_count)          # 1
print(result.undetected_count)        # 1
print(result.litterbox_job_id)        # "job-abc-123"
```

---

## Test Result Format

```json
{
  "test_id": "evt-a1b2c3d4e5f6",
  "config": { "name": "test", "controls": ["yara", "defender"] },
  "timestamp": "2026-09-19T13:30:00+00:00",
  "environment": "litterbox",
  "detection_overall": "partial",
  "execution_result": "success",
  "false_positive_risk": "low",
  "control_results": [
    {
      "control": "yara",
      "detection": "undetected",
      "notes": "",
      "signatures_triggered": []
    },
    {
      "control": "windows_defender",
      "detection": "detected",
      "notes": "Trojan:Win32/Fuerboos.C!cl",
      "signatures_triggered": ["Trojan:Win32/Fuerboos.C!cl"]
    }
  ],
  "telemetry_generated": ["network-beacon", "dns-query"],
  "litterbox_job_id": "job-abc-123",
  "litterbox_report_url": "http://localhost:8080/report/job-abc-123",
  "build_reproducible": true,
  "artifact_hash_verified": true,
  "duration_seconds": 45.2
}
```

---

## Evaluation Metrics

| Metric                  | Description                                    |
|-------------------------|------------------------------------------------|
| Detection Result        | Overall verdict (undetected/detected/partial)  |
| Execution Result        | Payload ran? (success/blocked/partial)         |
| False Positive Risk     | Risk of false positives (low/medium/high)      |
| Telemetry Generated     | What telemetry events were triggered            |
| Defensive Control       | Which control detected the artifact             |
| Test Configuration      | Exact config used for reproducibility           |
| Timestamp               | ISO8601 test timestamp                          |
| Environment             | Where the test ran (local/lab/litterbox)        |

---

## Configuration

| Key                                      | Default              | Description                              |
|------------------------------------------|----------------------|------------------------------------------|
| `evasion.test_mode`                      | `false`              | Must be `true` to run any tests          |
| `evasion.history_path`                   | `./logs/evasion_history.json` | Persisted test results            |
| `evasion.litterbox_url`                  | `""`                 | Litterbox base URL                       |
| `evasion.litterbox_token`                | `""`                 | Bearer token for Litterbox API           |
| `evasion.litterbox_timeout`              | `120`                | HTTP timeout in seconds                  |

---

## Safety & Scope

- **Laboratory only**: `test_mode` must be explicitly enabled.
- **No real AV engines**: The local mode is a placeholder that records *what would* be checked. Real detection requires Litterbox or external engines.
- **Audit logged**: Every test run emits an `evasion_test_completed` audit event.
- **Hash verification**: Builds are verified via SHA256 hash comparison for reproducibility.
- **No sensitive data**: Artifact hashes are stored, not the actual payload content.

---

## Tests

```bash
# Unit tests
python -m pupyteer.tests.unit.test_evasion

# Integration tests
python -m pupyteer.tests.integration.test_evasion_integration
```

---

## Files Added

```
pupyteer/server/evasion/
├── __init__.py               # Package init, public exports
├── models.py                 # Data models (configs, results, hashing)
├── litterbox_client.py       # Litterbox HTTP client
└── manager.py                # Core orchestrator

pupyteer/server/modules/builtin/
└── evasion.py                # Built-in evasion modules (TUI-accessible)

pupyteer/tui/commands/
└── evasion.py                # CLI commands for evasion

pupyteer/tests/unit/
└── test_evasion.py           # Unit tests (14 tests)

pupyteer/tests/integration/
└── test_evasion_integration.py  # Integration tests (2 tests)

pupyteer/config/defaults/
└── pupyteer.yaml             # +evasion section
```
