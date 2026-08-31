"""Live approval engine for `on_violation: ask` mode.

When the agent reaches a host that is neither allowed nor explicitly denied,
Warden can pause and ask a human instead of silently blocking. The decision is
made by a pluggable *decider* and cached per host, so:

  * each host is decided at most once per session (no repeated prompts),
  * "allow always" learns the host into the session allow-list,
  * the whole thing is testable without a TTY by injecting an AutoDecider.

Explicit deny-list hosts are never asked about — a deny is firm.
"""

from __future__ import annotations

import sys
import threading
from typing import Callable

# A decider maps a host to one of these decisions.
ALLOW_ONCE = "allow-once"
ALLOW_ALWAYS = "allow-always"
DENY = "deny"
DECISIONS = (ALLOW_ONCE, ALLOW_ALWAYS, DENY)


Decider = Callable[[str], str]


def auto_decider(default: str = DENY) -> Decider:
    """Non-interactive decider — always returns `default`. Used when there is no
    TTY (CI, piped input) so an unattended run fails safe."""
    if default not in DECISIONS:
        raise ValueError(f"invalid default decision: {default}")

    def decide(host: str) -> str:
        return default

    return decide


def tty_decider(stream=None, out=None) -> Decider:
    """Interactive decider — prompts on the terminal. Falls back to deny on EOF."""
    stream = stream or sys.stdin
    out = out or sys.stderr

    def decide(host: str) -> str:
        try:
            print(f"\n[warden] The agent wants to reach an unlisted host: {host}",
                  file=out)
            print("  [o] allow once   [a] allow always   [d] deny (default)", file=out)
            out.write("  choice> ")
            out.flush()
            answer = stream.readline().strip().lower()
        except (EOFError, OSError):
            return DENY
        return {"o": ALLOW_ONCE, "a": ALLOW_ALWAYS, "d": DENY}.get(answer, DENY)

    return decide


class DecisionCache:
    """Remember decisions per host and expose the learned allow-list.

    Thread-safe: proxy handlers run concurrently, and we must decide each host
    exactly once even if two connections to it race.
    """

    def __init__(self, decider: Decider):
        self._decider = decider
        self._lock = threading.Lock()
        self._decided: dict[str, str] = {}
        self.learned: set[str] = set()  # hosts approved "always" this session

    def resolve(self, host: str) -> str:
        """Return a final verdict for an unlisted host: 'allow' or 'deny'."""
        with self._lock:
            if host in self._decided:
                decision = self._decided[host]
            else:
                decision = self._decider(host)
                if decision not in DECISIONS:
                    decision = DENY
                self._decided[host] = decision
                if decision == ALLOW_ALWAYS:
                    self.learned.add(host)
            return "allow" if decision in (ALLOW_ONCE, ALLOW_ALWAYS) else "deny"
