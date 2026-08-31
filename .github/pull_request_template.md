## What this changes

Brief description.

## Checklist

- [ ] No new third-party runtime dependency (standard library only).
- [ ] Enforcement/recording claims are honest (recorded is called recorded).
- [ ] Tests added/updated. For an enforcement change, a test shows the dangerous
      action blocked and the safe action still working.
- [ ] `python3 -m unittest discover -s tests` passes.
- [ ] `driftward doctor` still passes on macOS.
