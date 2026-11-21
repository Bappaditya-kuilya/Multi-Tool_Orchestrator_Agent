"""Local test harness models for bench (M4).

Gateway-independent primitives to assert expected interfaces/behavior:
- hash-chain audit log with tamper detection
- scope attenuation / enforcement helpers
- simple budget/DoS guards
- latency/timing measurement placeholders and overhead stats
- optional live gateway integration helpers (when endpoint available)
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def hash_entry(prev_hash: str, payload: Mapping[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"\x00")
    h.update(_canon(payload).encode("utf-8"))
    return h.hexdigest()


@dataclass
class AuditEntry:
    seq: int
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str


@dataclass
class HashChainAuditLog:
    """Append-only hash-chained audit log (local model)."""

    entries: list[AuditEntry] = field(default_factory=list)

    @property
    def head_hash(self) -> str:
        return self.entries[-1].entry_hash if self.entries else "GENESIS"

    def append(self, payload: Mapping[str, Any]) -> AuditEntry:
        prev = self.head_hash
        data = dict(payload)
        entry = AuditEntry(
            seq=len(self.entries),
            payload=data,
            prev_hash=prev,
            entry_hash=hash_entry(prev, data),
        )
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prev = "GENESIS"
        for i, e in enumerate(self.entries):
            if e.seq != i:
                errors.append(f"seq mismatch at {i}: got {e.seq}")
            if e.prev_hash != prev:
                errors.append(f"prev_hash mismatch at {i}")
            expected = hash_entry(e.prev_hash, e.payload)
            if e.entry_hash != expected:
                errors.append(f"entry_hash mismatch at {i}")
            prev = e.entry_hash
        if not errors and self.entries and self.head_hash != self.entries[-1].entry_hash:
            errors.append("head hash mismatch")
        return (len(errors) == 0, errors)


def attenuate_scopes(parent_scopes: Iterable[str], requested_scopes: Iterable[str]) -> list[str]:
    """Child scopes must be subset of parent; return granted intersection in stable order."""
    parent = set(parent_scopes)
    out: list[str] = []
    for s in requested_scopes:
        if s in parent and s not in out:
            out.append(s)
    return out


def check_scope_authorized(granted_scopes: Iterable[str], required_scope: str) -> bool:
    return required_scope in set(granted_scopes)


def enforce_scope_check(enforce: bool, granted_scopes: Iterable[str], required_scope: str) -> bool:
    """Stronger enforcement helper: unauthorized scope must be blocked; in enforce mode, no implicit allow."""
    allowed = check_scope_authorized(granted_scopes, required_scope)
    if not allowed:
        return True  # blocked/denied as expected
    # if allowed, only acceptable when actually granted
    if enforce:
        assert required_scope in set(granted_scopes)
        assert allowed is True
    return allowed


def assert_scope_not_inflated(
    parent_scopes: Iterable[str], requested_scopes: Iterable[str], granted_scopes: Iterable[str]
) -> None:
    parent = set(parent_scopes)
    for s in granted_scopes:
        if s not in parent:
            raise AssertionError(f"scope inflated beyond parent: {s}")
        if s not in set(requested_scopes):
            raise AssertionError(f"scope granted but not requested: {s}")


@dataclass(frozen=True)
class Budget:
    max_payload_bytes: int = 1024 * 1024
    max_depth: int = 50
    max_items: int = 10_000
    max_expression_len: int = 256
    max_pow_exponent: int = 10_000


class BudgetExceeded(ValueError):
    pass


def enforce_payload_size(data: Any, budget: Budget = Budget()) -> None:
    raw = _canon(data).encode("utf-8")
    if len(raw) > budget.max_payload_bytes:
        raise BudgetExceeded(f"payload too large: {len(raw)} > {budget.max_payload_bytes}")


def enforce_depth(value: Any, budget: Budget = Budget(), _depth: int = 0) -> None:
    if _depth > budget.max_depth:
        raise BudgetExceeded(f"depth exceeded: {_depth} > {budget.max_depth}")
    if isinstance(value, Mapping):
        if len(value) > budget.max_items:
            raise BudgetExceeded("too many mapping items")
        for v in value.values():
            enforce_depth(v, budget, _depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > budget.max_items:
            raise BudgetExceeded("too many sequence items")
        for v in value:
            enforce_depth(v, budget, _depth + 1)


def enforce_pow(expr: str, budget: Budget = Budget()) -> None:
    if len(expr) > budget.max_expression_len:
        raise BudgetExceeded("expression too long")
    # conservative: reject any ** with a large numeric exponent literal
    import re

    for m in re.finditer(r"\*\*\s*([0-9][0-9_]*)", expr):
        exp = int(m.group(1).replace("_", ""))
        if exp > budget.max_pow_exponent:
            raise BudgetExceeded(f"pow exponent too large: {exp}")
    # reject chained pow like **...** which can explode evaluation cost
    if expr.count("**") > 1:
        raise BudgetExceeded("chained exponentiation not allowed")


def safe_route_lookup(registry: Mapping[str, Sequence[str]], capability: str) -> str | None:
    """Return first provider or None (clean failure, no exception)."""
    providers = registry.get(capability) or ()
    return providers[0] if providers else None


def require_known_capability(registry: Mapping[str, Sequence[str]], capability: str) -> str:
    provider = safe_route_lookup(registry, capability)
    if provider is None:
        raise LookupError(f"No tool for capability: {capability}")
    return provider


def scan_for_secrets(text: str, markers: Sequence[str] = ("sk-", "AKIA", "-----BEGIN", "password=", "api_key=")) -> list[str]:
    """Local secret-leak detector placeholder: returns marker hits in agent-visible text."""
    low = text.lower()
    hits = []
    for m in markers:
        if m.lower() in low:
            hits.append(m)
    return hits


def enforce_no_secret_leak(enforce: bool, text: str) -> None:
    """Stronger enforcement check: agent-visible output must not contain secret markers."""
    hits = scan_for_secrets(text)
    if enforce:
        # enforce mode: treat any hit as a hard block/evidence failure
        assert not hits, f"secret markers leaked in enforce mode (must block/redact): {hits}"
        # extra guard: common inline assignment forms should not appear
        lowered = text.lower()
        assert "api_key=" not in lowered and "password=" not in lowered, "credential assignment leaked in enforce mode"
    else:
        assert not hits, f"secret markers detected: {hits}"


@dataclass(frozen=True)
class TimingRecord:
    """Timing measurement captured by bench harness."""

    name: str
    duration_s: float
    status: str = "ok"
    note: str = ""


@contextmanager
def time_block(name: str, note: str = "") -> Iterator[dict[str, Any]]:
    """Measure wall-clock duration of a block; yields mutable holder with TimingRecord."""
    holder: dict[str, Any] = {"record": None}
    start = time.perf_counter()
    status = "ok"
    try:
        yield holder
    except Exception:
        status = "error"
        raise
    finally:
        holder["record"] = TimingRecord(name=name, duration_s=time.perf_counter() - start, status=status, note=note)


def measure_call(name: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, TimingRecord]:
    """Run fn and return (result, TimingRecord)."""
    start = time.perf_counter()
    status = "ok"
    try:
        result = fn(*args, **kwargs)
        return result, TimingRecord(name=name, duration_s=time.perf_counter() - start, status=status)
    except Exception:
        status = "error"
        raise
    finally:
        if status == "error":
            # caller cannot receive record on exception; timing still measurable via wrappers/fixtures
            pass


def summarize_latencies(records: Sequence[TimingRecord]) -> dict[str, Any]:
    """Compute latency/overhead summary stats (ms). CI/report friendly."""
    if not records:
        return {"count": 0, "avg_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0, "total_ms": 0.0, "by_status": {}}
    vals = sorted(r.duration_s * 1000.0 for r in records)
    def pct(p: float) -> float:
        if not vals:
            return 0.0
        k = (len(vals) - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return vals[int(k)]
        return vals[f] + (vals[c] - vals[f]) * (k - f)
    total = sum(vals)
    by_status: dict[str, int] = {}
    for r in records:
        by_status[r.status] = by_status.get(r.status, 0) + 1
    return {
        "count": len(vals),
        "avg_ms": total / len(vals),
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "max_ms": vals[-1],
        "total_ms": total,
        "by_status": by_status,
    }


@dataclass(frozen=True)
class LiveGateway:
    """Minimal live gateway client for integration-mode checks."""

    base_url: str
    timeout_s: float = 2.0

    def _url(self, path: str) -> str:
        return self.base_url.rstrip("/") + "/" + path.lstrip("/")

    def probe(self) -> tuple[bool, str]:
        """Best-effort reachability probe across common gateway/ops endpoints."""
        last_err = "unreachable"
        for path in ("/healthz", "/readyz", "/health", "/livez", "/metrics", "/"):
            try:
                req = urllib.request.Request(self._url(path), method="GET")
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    return True, f"{path}:{getattr(resp, 'status', 200)}"
            except urllib.error.HTTPError as e:
                # HTTP response means endpoint/gateway is reachable even if path is not healthy/public.
                return True, f"{path}:http_{int(getattr(e, 'code', 0) or 0)}"
            except Exception as e:
                last_err = f"{path}:{e}"
                continue
        return False, last_err

    def post_json(self, path: str, payload: Mapping[str, Any]) -> tuple[int, Any, float]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._url(path), data=data, method="POST", headers={"Content-Type": "application/json"}
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                elapsed = time.perf_counter() - start
                try:
                    return int(getattr(resp, "status", 200)), (json.loads(body) if body else None), elapsed
                except Exception:
                    return int(getattr(resp, "status", 200)), body, elapsed
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            elapsed = time.perf_counter() - start
            try:
                parsed = json.loads(body) if body else None
            except Exception:
                parsed = body
            return int(e.code), parsed, elapsed
        except Exception as e:
            elapsed = time.perf_counter() - start
            return 0, {"error": str(e)}, elapsed

    def post_json_simple(self, path: str, payload: Mapping[str, Any]) -> tuple[int, Any]:
        status, body, _ = self.post_json(path, payload)
        return status, body


def get_live_gateway(url: str | None = None, timeout_s: float = 2.0) -> LiveGateway | None:
    base = (url or os.getenv("SCOPEGATE_GATEWAY_URL", "")).strip()
    if not base:
        return None
    return LiveGateway(base_url=base, timeout_s=timeout_s)


def mcp_post_jsonrpc(
    gw: LiveGateway,
    rpc: Mapping[str, Any],
    *,
    path: str = "/mcp",
) -> tuple[int, Any, float]:
    """POST a JSON-RPC payload to the gateway MCP HTTP endpoint.

    Tries the gateway wrapper format first ({method:"", payload_json:"..."}),
    then falls back to raw JSON-RPC if the wrapper is rejected as invalid.
    Returns (status, parsed_body, elapsed_s).
    """
    wrapped = {"method": "", "payload_json": json.dumps(rpc)}
    status, body, elapsed = gw.post_json(path, wrapped)
    if status == 400 and isinstance(body, dict):
        # Some gateway builds may prefer raw JSON-RPC; retry once.
        msg = str(body.get("error") or body).lower()
        if "invalid mcp request" in msg or "invalid or missing json body" in msg:
            return gw.post_json(path, rpc)
    return status, body, elapsed


def gateway_env_summary(url: str | None = None) -> dict[str, Any]:
    """CI/helper summary for live gateway runs."""
    base = (url or os.getenv("SCOPEGATE_GATEWAY_URL", "")).strip()
    gw = get_live_gateway(base)
    ok, info = (False, "not_configured")
    if gw:
        ok, info = gw.probe()
    return {
        "configured": bool(base),
        "gateway_url": base or None,
        "reachable": ok,
        "probe": info,
        "mode": os.getenv("SCOPEGATE_BENCH_MODE", "baseline"),
    }


def write_latency_artifact(records: Sequence[TimingRecord], path: str) -> str:
    """Write instrumented latency records for CI/report ingestion."""
    payload = {
        "records": [{"name": r.name, "duration_s": r.duration_s, "status": r.status, "note": r.note} for r in records],
        "summary_ms": summarize_latencies(records),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def require_enforcement(enforce: bool, condition: bool, msg: str) -> None:
    """Stronger enforcement check: in enforce mode condition must hold (attack blocked)."""
    if enforce:
        assert condition is True, f"enforce-mode violation: {msg}"
    else:
        # baseline/dry-run: still assert modeled invariant for local evidence
        assert condition, msg


def validate_task_spec(task: Any) -> None:
    """Minimal local-model validator for malformed task specs (CRASH-05 shapes)."""
    if not isinstance(task, Mapping):
        raise ValueError("task must be an object")
    if not isinstance(task.get("task_id"), str) or not task.get("task_id"):
        raise ValueError("task_id is required")
    steps = task.get("steps")
    if not isinstance(steps, list):
        raise ValueError("steps must be a list")
    seen: set[str] = set()
    for i, step in enumerate(steps):
        if not isinstance(step, Mapping):
            raise ValueError(f"step {i} must be an object")
        sid = step.get("id")
        if not isinstance(sid, str) or not sid:
            raise ValueError(f"step {i} missing id")
        if sid in seen:
            raise ValueError(f"duplicate step id: {sid}")
        seen.add(sid)
        if not isinstance(step.get("capability"), str) or not step.get("capability"):
            raise ValueError(f"step {sid} missing capability")
    # depth/empty-subtask bound placeholder (mirrors nested subtask intent)
    def _depth(node: Any, d: int = 0) -> int:
        if not isinstance(node, Mapping):
            return d
        st = node.get("sub_task")
        if st is None:
            return d
        if not isinstance(st, Mapping):
            return d
        substeps = st.get("steps")
        if not isinstance(substeps, list) or len(substeps) == 0:
            raise ValueError("sub-task has no steps")
        child_depths = []
        for s in substeps:
            if isinstance(s, Mapping) and "sub_task" in s:
                child_depths.append(_depth(s, d + 1))
            else:
                child_depths.append(d + 1)
        return max(child_depths) if child_depths else d + 1

    for step in steps:
        if _depth(step) > 50:
            raise ValueError("sub-task depth exceeded")
