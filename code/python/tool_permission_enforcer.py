"""Least-privilege tool permission enforcement for autonomous agents.

Excessive Agency (LLM06:2025) is the mechanism behind the most damaging agentic
incidents, including the January 2026 Step Finance loss of roughly USD 40m when
autonomous trading agents with over-broad permissions executed unauthorised SOL
token transfers. The defence is boring but effective: every tool call is checked,
at runtime, against an explicit permission grant scoped to the agent's role.

This module provides:

* :class:`Permission` - a single grant (tool name, access level, optional scope
  predicate, and an approval gate).
* :class:`PermissionPolicy` - the set of grants for one agent role.
* :class:`ToolPermissionEnforcer` - the runtime checker, usable directly or as a
  decorator, that raises :class:`PermissionDenied` on violation and returns an
  :class:`ApprovalRequired` decision when a call crosses a human-approval gate.

It integrates with the approval-gate model from chapter 03 (Governance) and the
tool permission model from chapter 04 (Security Controls Playbook).

Example
-------
>>> from tool_permission_enforcer import (
...     Permission, PermissionPolicy, ToolPermissionEnforcer, AccessLevel, Gate)
>>> policy = PermissionPolicy(
...     role="customer_service_agent",
...     permissions=[
...         Permission("query_crm", AccessLevel.READ),
...         Permission("update_account_status", AccessLevel.WRITE,
...                    scope=lambda a: a.get("status") in {"active", "suspended"},
...                    gate=Gate.LIGHT_OVERSIGHT),
...     ],
... )
>>> enforcer = ToolPermissionEnforcer(policy)
>>> enforcer.check("query_crm", {"customer_id": "C123"}, AccessLevel.READ).allowed
True

Author: Mervin Pearce, Pearce.Academy.
License: CC-BY-4.0.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Mapping, Optional, ParamSpec, TypeVar

logger = logging.getLogger("agent.permissions")

P = ParamSpec("P")
R = TypeVar("R")

# Predicate applied to a tool call's arguments to enforce a scope restriction.
ScopePredicate = Callable[[Mapping[str, Any]], bool]


class AccessLevel(IntEnum):
    """Ordered access levels. A grant satisfies any request at or below it."""

    NONE = 0
    READ = 1
    WRITE = 2
    EXECUTE = 3


class Gate(IntEnum):
    """Approval gates mapped from the governance model (chapter 03)."""

    AUTONOMOUS = 0  # Gate 0: fully autonomous
    LIGHT_OVERSIGHT = 1  # Gate 1: post-hoc review / light oversight
    HUMAN_APPROVAL = 2  # Gate 2: human approval required before execution
    DUAL_APPROVAL = 3  # Gate 3: two-person approval required


class PermissionDenied(PermissionError):
    """Raised when a tool call violates the permission policy."""

    def __init__(self, tool: str, reason: str) -> None:
        self.tool = tool
        self.reason = reason
        super().__init__(f"permission denied for tool '{tool}': {reason}")


class ApprovalPending(RuntimeError):
    """Raised by the decorator when a call needs approval it did not receive."""

    def __init__(self, tool: str, gate: Gate) -> None:
        self.tool = tool
        self.gate = gate
        super().__init__(
            f"tool '{tool}' requires approval at {gate.name} before execution"
        )


@dataclass
class Permission:
    """A single tool permission grant.

    Parameters
    ----------
    tool:
        Name of the tool this grant applies to.
    level:
        Maximum :class:`AccessLevel` granted for the tool.
    scope:
        Optional predicate evaluated against the call arguments. Return ``True``
        to allow, ``False`` to deny. Use this to express restrictions such as
        "only symbols in an allow-list" or "quantity below a cap".
    gate:
        Approval gate that applies to this tool. Calls at
        :attr:`Gate.HUMAN_APPROVAL` or higher must present prior approval.
    description:
        Optional human-readable rationale, surfaced in audit output.
    """

    tool: str
    level: AccessLevel
    scope: Optional[ScopePredicate] = None
    gate: Gate = Gate.AUTONOMOUS
    description: str = ""


@dataclass
class PermissionPolicy:
    """The permission grants for a single agent role."""

    role: str
    permissions: list[Permission] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._by_tool: dict[str, Permission] = {}
        for perm in self.permissions:
            if perm.tool in self._by_tool:
                raise ValueError(f"duplicate permission for tool '{perm.tool}'")
            self._by_tool[perm.tool] = perm

    def get(self, tool: str) -> Optional[Permission]:
        """Return the grant for ``tool`` or ``None`` if not permitted."""
        return self._by_tool.get(tool)

    def tools(self) -> list[str]:
        """Return the sorted list of permitted tool names."""
        return sorted(self._by_tool)


@dataclass
class Decision:
    """Result of a permission check."""

    allowed: bool
    tool: str
    reason: str
    requires_approval: bool = False
    gate: Gate = Gate.AUTONOMOUS

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable representation for audit logs."""
        return {
            "tool": self.tool,
            "allowed": self.allowed,
            "reason": self.reason,
            "requires_approval": self.requires_approval,
            "gate": self.gate.name,
        }


# Signature for a pluggable approval provider: given (tool, gate, args), return
# True if approval has been granted for this specific call.
ApprovalProvider = Callable[[str, Gate, Mapping[str, Any]], bool]


@dataclass
class ToolPermissionEnforcer:
    """Runtime enforcer for a single agent's :class:`PermissionPolicy`.

    Parameters
    ----------
    policy:
        The permission policy to enforce.
    approval_provider:
        Optional callable that resolves whether a gated call is approved. If
        omitted, gated calls are reported as requiring approval and, when used
        via :meth:`enforce`, raise :class:`ApprovalPending`.
    audit_hook:
        Optional callback invoked with every :class:`Decision` for logging.
    """

    policy: PermissionPolicy
    approval_provider: Optional[ApprovalProvider] = None
    audit_hook: Optional[Callable[[Decision], None]] = None

    def check(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        requested_level: AccessLevel,
    ) -> Decision:
        """Evaluate a call without executing it.

        Returns a :class:`Decision`. Never raises for a policy violation; callers
        that prefer exceptions should use :meth:`enforce` or inspect the result.
        """
        perm = self.policy.get(tool)
        if perm is None:
            return self._record(
                Decision(False, tool, "tool not in policy (default deny)")
            )

        if requested_level > perm.level:
            return self._record(
                Decision(
                    False,
                    tool,
                    f"requested {requested_level.name} exceeds granted {perm.level.name}",
                )
            )

        if perm.scope is not None:
            try:
                in_scope = bool(perm.scope(arguments))
            except Exception as exc:  # defensive: a broken predicate denies
                logger.exception("scope predicate raised for tool '%s'", tool)
                return self._record(
                    Decision(False, tool, f"scope predicate error: {exc}")
                )
            if not in_scope:
                return self._record(
                    Decision(False, tool, "arguments outside permitted scope")
                )

        if perm.gate >= Gate.HUMAN_APPROVAL:
            approved = False
            if self.approval_provider is not None:
                approved = bool(self.approval_provider(tool, perm.gate, arguments))
            if not approved:
                return self._record(
                    Decision(
                        allowed=False,
                        tool=tool,
                        reason=f"awaiting approval at {perm.gate.name}",
                        requires_approval=True,
                        gate=perm.gate,
                    )
                )

        return self._record(
            Decision(True, tool, "permitted", gate=perm.gate)
        )

    def enforce(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        requested_level: AccessLevel,
    ) -> None:
        """Check a call and raise on violation.

        Raises
        ------
        PermissionDenied
            If the call is not permitted by policy.
        ApprovalPending
            If the call is otherwise permitted but requires unmet approval.
        """
        decision = self.check(tool, arguments, requested_level)
        if decision.allowed:
            return
        if decision.requires_approval:
            raise ApprovalPending(tool, decision.gate)
        raise PermissionDenied(tool, decision.reason)

    def require(
        self, tool: str, level: AccessLevel
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorator factory that enforces permission before running a tool.

        The wrapped function must accept its tool arguments as a single mapping
        passed as the first positional argument or as keyword arguments. Keyword
        arguments are used for scope evaluation when no mapping is supplied.
        """

        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            @functools.wraps(func)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                if args and isinstance(args[0], Mapping):
                    call_args: Mapping[str, Any] = args[0]
                else:
                    call_args = dict(kwargs)
                self.enforce(tool, call_args, level)
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def _record(self, decision: Decision) -> Decision:
        if decision.allowed:
            logger.debug("ALLOW %s (%s)", decision.tool, decision.reason)
        else:
            logger.warning("DENY %s (%s)", decision.tool, decision.reason)
        if self.audit_hook is not None:
            try:
                self.audit_hook(decision)
            except Exception:  # pragma: no cover - defensive
                logger.exception("audit_hook failed for tool '%s'", decision.tool)
        return decision


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    def _approvals(tool: str, gate: Gate, args: Mapping[str, Any]) -> bool:
        # Demonstration: approve trades of 100 shares or fewer only.
        return int(args.get("quantity", 0)) <= 100

    policy = PermissionPolicy(
        role="trade_execution_agent",
        permissions=[
            Permission("query_market_data", AccessLevel.READ),
            Permission(
                "execute_trade",
                AccessLevel.WRITE,
                scope=lambda a: a.get("symbol") in {"AAPL", "MSFT", "GOOGL"},
                gate=Gate.HUMAN_APPROVAL,
                description="Only large-cap allow-list symbols.",
            ),
        ],
    )
    enforcer = ToolPermissionEnforcer(policy, approval_provider=_approvals)

    print(enforcer.check("query_market_data", {}, AccessLevel.READ).as_dict())
    print(
        enforcer.check(
            "execute_trade", {"symbol": "AAPL", "quantity": 50}, AccessLevel.WRITE
        ).as_dict()
    )
    print(
        enforcer.check(
            "execute_trade", {"symbol": "TSLA", "quantity": 50}, AccessLevel.WRITE
        ).as_dict()
    )
    print(
        enforcer.check(
            "execute_trade", {"symbol": "AAPL", "quantity": 5000}, AccessLevel.WRITE
        ).as_dict()
    )
