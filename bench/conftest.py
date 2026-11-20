"""Bench harness shared config.

Modes (PRD M4): baseline, dry-run, enforce.
- baseline: run attacks, record outcomes without requiring blocks.
- dryrun: exercise "would block" logging paths.
- enforce: attacks must be blocked/contained per policy (CI gate target).

Live gateway integration: set --gateway-url / SCOPEGATE_GATEWAY_URL to enable
live cases; without it they are xfailed with a clear reason.
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable

import pytest

from harness import TimingRecord

VALID_MODES = ("baseline", "dryrun", "enforce")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--bench-mode",
        action="store",
        default=os.getenv("SCOPEGATE_BENCH_MODE", "baseline"),
        choices=VALID_MODES,
        help="Harness mode: baseline|dryrun|enforce (default: baseline or $SCOPEGATE_BENCH_MODE).",
    )
    parser.addoption(
        "--gateway-url",
        action="store",
        default=os.getenv("SCOPEGATE_GATEWAY_URL", ""),
        help="Live ScopeGate MCP/gateway base URL for integration cases (or $SCOPEGATE_GATEWAY_URL).",
    )


@pytest.fixture(scope="session")
def bench_mode(pytestconfig: pytest.Config) -> str:
    return str(pytestconfig.getoption("--bench-mode"))


@pytest.fixture(scope="session")
def enforce(bench_mode: str) -> bool:
    return bench_mode == "enforce"


@pytest.fixture(scope="session")
def gateway_url(pytestconfig: pytest.Config) -> str:
    return str(pytestconfig.getoption("--gateway-url") or "").strip()


@pytest.fixture(scope="session")
def latency_records(pytestconfig: pytest.Config) -> list[TimingRecord]:
    """Session-collected latency/overhead measurements for report placeholders/hooks."""
    recs: list[TimingRecord] = []
    pytestconfig._bench_latency_records = recs  # type: ignore[attr-defined]
    return recs


@pytest.fixture
def record_latency(latency_records: list[TimingRecord]) -> Callable[[str, Callable[..., Any], Any], Any]:
    def _run(name: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        status = "ok"
        try:
            return fn(*args, **kwargs)
        except Exception:
            status = "error"
            raise
        finally:
            latency_records.append(TimingRecord(name=name, duration_s=time.perf_counter() - start, status=status))

    return _run


def require_live_gateway(gateway_url: str) -> str:
    if not gateway_url:
        pytest.xfail(
            "gateway-dependent live integration case xfailed: live gateway not configured "
            "(set --gateway-url or SCOPEGATE_GATEWAY_URL to run against a local gateway)"
        )
    return gateway_url


def pytest_terminal_summary(terminalreporter: Any, exitstatus: int, config: pytest.Config) -> None:
    records = getattr(config, "_bench_latency_records", None) or []
    if records:
        try:
            from harness import summarize_latencies

            s = summarize_latencies(records)
            terminalreporter.write_line(
                f"bench latency: count={s.get('count',0)} avg_ms={s.get('avg_ms',0):.3f} "
                f"p50_ms={s.get('p50_ms',0):.3f} p95_ms={s.get('p95_ms',0):.3f} max_ms={s.get('max_ms',0):.3f}"
            )
        except Exception:
            pass


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    # best-effort: export instrumented latency records for CI/report ingestion
    try:
        recs = getattr(session.config, "_bench_latency_records", None) or []
    except Exception:
        recs = []
    out = os.getenv("BENCH_LATENCY_OUT", "").strip()
    if out and recs:
        try:
            from harness import write_latency_artifact

            write_latency_artifact(recs, out)
        except Exception:
            pass
