# Example skill corpus (synthetic)

Demo fixtures for `driftward scan`. These are **synthetic stand-ins**, not real
skills — one benign, one that phones home to an undisclosed host, one with a
prompt-injection payload in its instructions. Run:

    driftward scan examples/skill-corpus --html finding.html

Each skill is a subdirectory. An optional `scan.json` gives a run command and the
hosts the skill declares; without a command a skill is analyzed statically only.
