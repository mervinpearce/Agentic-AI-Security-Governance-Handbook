"""Circuit breaker for autonomous AI agent tool execution.

This module implements a thread-safe circuit breaker tailored to agentic AI
systems. Unlike a classic network circuit breaker, it tracks failures *per
action type* (for example ``execute_trade`` versus ``read_file``) so that a
misbehaving high-impact action can be isolated without halting benign, low-risk
activity.

The breaker follows the standard three-state model:

* ``CLOSED``    - calls flow normally; failures are counted within a sliding window.
* ``OPEN``      - the failure threshold has been exceeded; calls are rejected fast.
* ``HALF_OPEN`` - after a cooldown, a limited number of trial calls are allowed to
  probe whether the downstream action has recovered.

Design goals for the financial-services context (see chapter 04, Security
Controls Playbook, and chapter 10, Production Deployment):

* Deterministic, auditable state transitions.
* Independent trip control that a running agent cannot reset itself.
* A structured callback hook so a trip can page an on-call engineer.

Example
-------
>>> from circuit_breaker import CircuitBreaker, CircuitBreakerError
>>> breaker = CircuitBreaker("execute_trade", failure_threshold=3, window_seconds=60)
>>> @breaker.protect
... def execute_trade(symbol: str, quantity: int) -> str:
...     return f"filled {quantity} {symbol}"
>>> execute_trade("AAPL", 10)
'filled 10 AAPL'

Author: Mervin Pearce, Pearce.Academy.
License: CC-BY-4.0.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, Optional, ParamSpec, TypeVar

logger = logging.getLogger("agent.circuit_breaker")

P = ParamSpec("P")
R = TypeVar("R")


class CircuitState(str, Enum):
    """Operational states of the circuit breaker."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(RuntimeError):
    """Raised when a call is rejected because the circuit is open."""

    def __init__(self, action_type: str, retry_after_seconds: float) -> None:
        self.action_type = action_type
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Circuit for action '{action_type}' is OPEN; "
            f"retry after {retry_after_seconds:.1f}s"
        )


@dataclass
class CircuitBreakerStats:
    """Point-in-time snapshot of breaker health, useful for dashboards."""

    action_type: str
    state: CircuitState
    recent_failures: int
    total_calls: int
    total_failures: int
    total_rejections: int
    last_trip_epoch: Optional[float] = None


@dataclass
class CircuitBreaker:
    """A per-action circuit breaker with a sliding failure window.

    Parameters
    ----------
    action_type:
        Logical name of the protected action (used in logs and alerts).
    failure_threshold:
        Number of failures within ``window_seconds`` that trips the breaker.
    window_seconds:
        Length of the sliding window over which failures are counted.
    cooldown_seconds:
        Time the breaker stays OPEN before allowing trial calls (HALF_OPEN).
    half_open_max_calls:
        Number of trial calls permitted in HALF_OPEN before deciding to
        close (all succeed) or re-open (any fails).
    on_trip:
        Optional callback invoked exactly once when the breaker trips OPEN.
        Receives the :class:`CircuitBreakerStats` snapshot. Use it to raise an
        alert. Exceptions from the callback are logged and suppressed.
    """

    action_type: str
    failure_threshold: int = 5
    window_seconds: float = 60.0
    cooldown_seconds: float = 300.0
    half_open_max_calls: int = 1
    on_trip: Optional[Callable[[CircuitBreakerStats], None]] = None

    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failures: Deque[float] = field(default_factory=deque, init=False)
    _opened_at: Optional[float] = field(default=None, init=False)
    _half_open_calls: int = field(default=0, init=False)
    _total_calls: int = field(default=0, init=False)
    _total_failures: int = field(default=0, init=False)
    _total_rejections: int = field(default=0, init=False)
    _last_trip_epoch: Optional[float] = field(default=None, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if self.cooldown_seconds <= 0:
            raise ValueError("cooldown_seconds must be > 0")

    # -- Public API ------------------------------------------------------

    @property
    def state(self) -> CircuitState:
        """Return the current state, accounting for cooldown expiry."""
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state

    def allow(self) -> bool:
        """Return ``True`` if a call may proceed right now."""
        with self._lock:
            self._maybe_transition_to_half_open()
            if self._state is CircuitState.OPEN:
                return False
            if self._state is CircuitState.HALF_OPEN:
                return self._half_open_calls < self.half_open_max_calls
            return True

    def record_success(self) -> None:
        """Record a successful call and, in HALF_OPEN, close the circuit."""
        with self._lock:
            self._total_calls += 1
            if self._state is CircuitState.HALF_OPEN:
                logger.info(
                    "Circuit for '%s' recovered; transitioning HALF_OPEN -> CLOSED",
                    self.action_type,
                )
                self._reset_locked()

    def record_failure(self) -> None:
        """Record a failed call and trip the breaker if the threshold is hit."""
        now = time.monotonic()
        with self._lock:
            self._total_calls += 1
            self._total_failures += 1

            if self._state is CircuitState.HALF_OPEN:
                logger.warning(
                    "Trial call for '%s' failed; re-opening circuit",
                    self.action_type,
                )
                self._trip_locked()
                return

            self._failures.append(now)
            self._evict_old_locked(now)
            if len(self._failures) >= self.failure_threshold:
                self._trip_locked()

    def call(self, func: Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> R:
        """Invoke ``func`` through the breaker.

        Raises
        ------
        CircuitBreakerError
            If the circuit is open and the call is rejected.
        """
        if not self.allow():
            with self._lock:
                self._total_rejections += 1
                retry_after = self._retry_after_locked()
            raise CircuitBreakerError(self.action_type, retry_after)

        with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                self._half_open_calls += 1

        try:
            result = func(*args, **kwargs)
        except Exception:
            self.record_failure()
            raise
        self.record_success()
        return result

    def protect(self, func: Callable[P, R]) -> Callable[P, R]:
        """Decorator form of :meth:`call`."""

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return self.call(func, *args, **kwargs)

        return wrapper

    def manual_reset(self) -> None:
        """Force the breaker back to CLOSED (human-operated recovery)."""
        with self._lock:
            logger.info("Manual reset of circuit '%s'", self.action_type)
            self._reset_locked()

    def force_open(self) -> None:
        """Force the breaker OPEN, e.g. as a targeted kill switch."""
        with self._lock:
            logger.warning("Circuit '%s' forced OPEN by operator", self.action_type)
            self._trip_locked()

    def stats(self) -> CircuitBreakerStats:
        """Return a snapshot of breaker health for monitoring."""
        with self._lock:
            self._evict_old_locked(time.monotonic())
            return CircuitBreakerStats(
                action_type=self.action_type,
                state=self._state,
                recent_failures=len(self._failures),
                total_calls=self._total_calls,
                total_failures=self._total_failures,
                total_rejections=self._total_rejections,
                last_trip_epoch=self._last_trip_epoch,
            )

    # -- Internal helpers (all assume the lock is held) ------------------

    def _evict_old_locked(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()

    def _maybe_transition_to_half_open(self) -> None:
        if self._state is CircuitState.OPEN and self._opened_at is not None:
            if time.monotonic() - self._opened_at >= self.cooldown_seconds:
                logger.info(
                    "Cooldown elapsed for '%s'; OPEN -> HALF_OPEN", self.action_type
                )
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0

    def _retry_after_locked(self) -> float:
        if self._opened_at is None:
            return 0.0
        elapsed = time.monotonic() - self._opened_at
        return max(0.0, self.cooldown_seconds - elapsed)

    def _trip_locked(self) -> None:
        already_open = self._state is CircuitState.OPEN
        self._state = CircuitState.OPEN
        self._opened_at = time.monotonic()
        self._last_trip_epoch = time.time()
        self._half_open_calls = 0
        if not already_open:
            logger.error(
                "Circuit for '%s' TRIPPED after %d failures in %.0fs window",
                self.action_type,
                len(self._failures),
                self.window_seconds,
            )
            if self.on_trip is not None:
                try:
                    self.on_trip(self.stats())
                except Exception:  # pragma: no cover - defensive
                    logger.exception("on_trip callback failed for '%s'", self.action_type)

    def _reset_locked(self) -> None:
        self._state = CircuitState.CLOSED
        self._failures.clear()
        self._opened_at = None
        self._half_open_calls = 0


class CircuitBreakerRegistry:
    """Central registry so orchestration code can share and inspect breakers."""

    def __init__(self) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def get_or_create(self, action_type: str, **kwargs: object) -> CircuitBreaker:
        """Return the breaker for ``action_type``, creating it if necessary."""
        with self._lock:
            if action_type not in self._breakers:
                self._breakers[action_type] = CircuitBreaker(action_type, **kwargs)  # type: ignore[arg-type]
            return self._breakers[action_type]

    def snapshot(self) -> list[CircuitBreakerStats]:
        """Return stats for every registered breaker."""
        with self._lock:
            return [b.stats() for b in self._breakers.values()]

    def trip_all(self) -> None:
        """System-level kill switch: force every breaker OPEN."""
        with self._lock:
            for breaker in self._breakers.values():
                breaker.force_open()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    def _alert(stats: CircuitBreakerStats) -> None:
        print(f"ALERT: circuit {stats.action_type} tripped -> {stats.state.value}")

    cb = CircuitBreaker(
        "execute_trade",
        failure_threshold=3,
        window_seconds=10,
        cooldown_seconds=2,
        on_trip=_alert,
    )

    def _flaky(should_fail: bool) -> str:
        if should_fail:
            raise RuntimeError("downstream error")
        return "ok"

    for _ in range(3):
        try:
            cb.call(_flaky, True)
        except RuntimeError:
            pass

    print("state after failures:", cb.state.value)
    try:
        cb.call(_flaky, False)
    except CircuitBreakerError as exc:
        print("rejected:", exc)

    time.sleep(2.1)
    print("state after cooldown:", cb.state.value)
    print("trial call:", cb.call(_flaky, False))
    print("state after recovery:", cb.state.value)
    print("stats:", cb.stats())
