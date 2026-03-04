# Parity Golden Log Validation

This runbook validates OpenProton runtime traces against frozen parity milestones.

## Inputs

- Fixture: `tests/fixtures/parity_golden_logs.json`
- Validator: `scripts/validate_parity_logs.py`
- Runtime log file from `openproton-bridge` execution.

## Supported scenarios

- `first_login`
- `existing_account_startup`
- `repair_flow`
- `interrupted_sync`

## Command

```bash
python3 scripts/validate_parity_logs.py \
  --fixture tests/fixtures/parity_golden_logs.json \
  --scenario first_login \
  --log /path/to/openproton.log \
  --report-json /tmp/parity-first-login.json
```

## Result semantics

- Exit `0`: all required milestones for the selected scenario were matched in order.
- Exit `1`: one or more required milestones are missing or out of order; stderr includes a mismatch summary.

The optional JSON report contains:

- `scenario`
- `passed`
- `matched_milestones`
- `missing_milestones`
- `out_of_order_milestones`
- `fixture`
- `log`
