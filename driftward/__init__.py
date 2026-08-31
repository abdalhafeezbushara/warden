"""Driftward — least privilege and a flight recorder for AI coding agents.

Your agent runs with your full user account. Driftward fixes that:
record everything it does, enforce what it may do, and prove what happened.

OS-level enforcement (macOS Seatbelt / Linux bubblewrap), a signed tamper-evident
flight recorder for network egress (and, with --deep, files/processes via
Endpoint Security), behavioral risk scoring, and least-privilege policy
generation. Pure standard library, local-first, no telemetry.
"""

__version__ = "0.2.0a2"
