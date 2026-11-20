#!/usr/bin/env python3
"""Summary/report generator for bench (M4).

Runs bench pytest suite (or reads existing JUnit XML) and emits CI-style
summary/table output in markdown and/or JSON. Includes latency/overhead
measurements/placeholders, run/mode/gateway metadata, explicit xfail reasons,
and optional CI thresholds.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ATTACK_MARKERS = [
    "injection_exfil",
    "scope_escalation",
    "confused_deputy",
    "tool_poisoning",
    "rug_pull",
    "secret_leak",
    "dos_inputs",
    "audit_tamper",
]


@dataclass
class CaseResult:
    name: str
    classname: str
    time_s: float
    outcome: str  # pass|fail|error|skip|xfail|xpass
    message: str = ""
    attack_class: str = "unclassified"


@dataclass
class SuiteSummary:
    tests: int = 0
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    xfailed: int = 0
    xpassed: int = 0
    passed: int = 0
    time_s: float = 0.0
    cases: list[CaseResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.failures == 0 and self.errors == 0 and self.xpassed == 0


def _load_marker_map() -> dict[str, str]:
    """Map test node base name -> primary attack marker from suite module."""
    mapping: dict[str, str] = {}
    try:
        bench_dir = Path(__file__).resolve().parent
        if str(bench_dir) not in sys.path:
            sys.path.insert(0, str(bench_dir))
        import test_attack_suite  # type: ignore

        for name in dir(test_attack_suite):
            obj = getattr(test_attack_suite, name)
            marks = getattr(obj, "pytestmark", []) or []
            # also direct marks
            direct = getattr(obj, "own_markers", None)
            if direct:
                marks = list(marks) + list(direct)
            # pytest stores marks in .pytestmark list or object iteration differs; try get_closest_marker not on raw fn
            # normalize: marks may be MarkDecorator or list
            found = None
            for m in (marks if isinstance(marks, list) else [marks]):
                mname = getattr(m, "name", None) or (m if isinstance(m, str) else None)
                # MarkDecorator has .mark.name sometimes
                if mname is None and hasattr(m, "mark"):
                    mname = getattr(m.mark, "name", None)
                if mname in ATTACK_MARKERS:
                    found = mname
                    break
            if found:
                mapping[name] = found
    except Exception:
        pass
    return mapping


def _class_for_case(name: str, marker_map: dict[str, str]) -> str:
    base = name.split("[", 1)[0]
    if base in marker_map:
        return marker_map[base]
    # heuristic fallback
    for m in ATTACK_MARKERS:
        if m in base:
            return m
    return "unclassified"


def parse_junit(path: Path) -> SuiteSummary:
    tree = ET.parse(path)
    root = tree.getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    marker_map = _load_marker_map()
    s = SuiteSummary()
    for ts in suites:
        s.tests += int(ts.attrib.get("tests", 0))
        s.failures += int(ts.attrib.get("failures", 0))
        s.errors += int(ts.attrib.get("errors", 0))
        s.skipped += int(ts.attrib.get("skipped", 0))
        s.time_s += float(ts.attrib.get("time", 0.0) or 0.0)
        for case in ts.findall("testcase"):
            name = case.attrib.get("name", "")
            classname = case.attrib.get("classname", "")
            time_s = float(case.attrib.get("time", 0.0) or 0.0)
            failure = case.find("failure")
            error = case.find("error")
            skipped = case.find("skipped")
            if failure is not None:
                outcome, msg = "fail", (failure.attrib.get("message") or "")
            elif error is not None:
                outcome, msg = "error", (error.attrib.get("message") or "")
            elif skipped is not None:
                msg = skipped.attrib.get("message") or ""
                stype = (skipped.attrib.get("type") or "").lower()
                low = (msg + " " + stype).lower()
                if "xfail" in low:
                    outcome = "xfail"
                    s.xfailed += 1
                elif "xpass" in low or "unexpected pass" in low:
                    outcome = "xpass"
                    s.xpassed += 1
                else:
                    outcome = "skip"
            else:
                outcome, msg = "pass", ""
            s.cases.append(
                CaseResult(
                    name=name,
                    classname=classname,
                    time_s=time_s,
                    outcome=outcome,
                    message=msg,
                    attack_class=_class_for_case(name, marker_map),
                )
            )
    # derive passed conservatively
    s.passed = max(0, s.tests - s.failures - s.errors - s.skipped)
    # but if xfailed counted inside skipped in some reporters, keep consistent
    if s.passed < sum(1 for c in s.cases if c.outcome == "pass"):
        s.passed = sum(1 for c in s.cases if c.outcome == "pass")
    return s


def run_pytest(pytest_args: list[str], junit_path: Path) -> tuple[int, SuiteSummary]:
    cmd = [sys.executable, "-m", "pytest", *pytest_args, f"--junitxml={junit_path}"]
    proc = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1])
    summary = parse_junit(junit_path) if junit_path.exists() else SuiteSummary()
    return proc.returncode, summary


def _class_counts(summary: SuiteSummary) -> dict[str, dict[str, int]]:
    by: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for c in summary.cases:
        by[c.attack_class][c.outcome] += 1
        by[c.attack_class]["total"] += 1
    return by


def _xfail_cases(summary: SuiteSummary) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in summary.cases:
        if c.outcome in ("xfail", "xpass"):
            out.append(
                {
                    "name": c.name,
                    "class": c.attack_class,
                    "outcome": c.outcome,
                    "reason": c.message or "",
                }
            )
    return out


def _run_context(args: argparse.Namespace | None = None) -> dict[str, Any]:
    mode = (getattr(args, "bench_mode", None) if args else None) or os.getenv("SCOPEGATE_BENCH_MODE", "baseline")
    gateway_url = (getattr(args, "gateway_url", None) if args else None)
    if gateway_url is None:
        gateway_url = os.getenv("SCOPEGATE_GATEWAY_URL", "")
    gateway_url = str(gateway_url or "").strip()
    ctx: dict[str, Any] = {
        "bench_mode": mode,
        "gateway_url": gateway_url or None,
        "gateway_configured": bool(gateway_url),
        "gateway_reachable": None,
        "gateway_probe": "not_checked",
    }
    if gateway_url:
        try:
            bench_dir = Path(__file__).resolve().parent
            if str(bench_dir) not in sys.path:
                sys.path.insert(0, str(bench_dir))
            from harness import gateway_env_summary  # type: ignore

            g = gateway_env_summary(gateway_url)
            ctx["gateway_reachable"] = g.get("reachable")
            ctx["gateway_probe"] = g.get("probe")
        except Exception as e:
            ctx["gateway_probe"] = f"probe_error:{e}"
    else:
        ctx["gateway_probe"] = "not_configured"
    # expected baseline evidence semantics (documented)
    ctx["expected_baseline"] = "non-live baseline: 38 passed, 7 xfailed; live-configured runs may pass reachable/enforced live integration cases"
    return ctx


def render_readme_table(summary: SuiteSummary, rc: int, run_ctx: dict[str, Any] | None = None) -> str:
    """Compact markdown table format suitable for pasting into README/docs."""
    run_ctx = run_ctx or {}
    status = "PASS" if rc == 0 and summary.ok else "FAIL"
    mode = run_ctx.get("bench_mode", "unknown")
    gw_url = run_ctx.get("gateway_url") or "(none)"
    gw_cfg = "yes" if run_ctx.get("gateway_configured") else "no"
    gw_reach = run_ctx.get("gateway_reachable")
    gw_probe = run_ctx.get("gateway_probe", "")
    lines = []
    lines.append(
        f"<!-- bench:status={status} mode={mode} gateway_configured={gw_cfg} tests={summary.tests} "
        f"passed={summary.passed} xfailed={summary.xfailed} failures={summary.failures} errors={summary.errors} rc={rc} -->"
    )
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Status | {status} |")
    lines.append(f"| Bench mode | {mode} |")
    lines.append(f"| Gateway URL | {gw_url} |")
    lines.append(f"| Gateway configured | {gw_cfg} |")
    lines.append(f"| Gateway reachable/probe | {gw_reach} ({gw_probe}) |")
    lines.append(f"| Tests | {summary.tests} |")
    lines.append(f"| Passed | {summary.passed} |")
    lines.append(f"| XFailed (gateway-dependent) | {summary.xfailed} |")
    lines.append(f"| Failed | {summary.failures} |")
    lines.append(f"| Errors | {summary.errors} |")
    lines.append(f"| Skipped | {summary.skipped} |")
    lines.append(f"| Time (s) | {summary.time_s:.3f} |")
    lines.append("")
    lines.append("| Class | Total | Pass | XFail | Fail/Error | Skip |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    by = _class_counts(summary)
    for cls in ATTACK_MARKERS + ["unclassified"]:
        d = by.get(cls)
        if not d:
            continue
        bad = d["fail"] + d["error"]
        lines.append(
            f"| {cls} | {d['total']} | {d['pass']} | {d['xfail']} | {bad} | {d['skip']} |"
        )
    xfails = _xfail_cases(summary)
    if xfails:
        lines.append("")
        lines.append("**XFail reasons (gateway-dependent/live-unconfigured):**")
        for x in xfails:
            reason = (x.get("reason") or "").replace("\n", " ").strip()
            lines.append(f"- `{x['name']}` [{x['class']}]: {reason}")
    lines.append("")
    return "\n".join(lines)


def _latency_stats(summary: SuiteSummary) -> dict[str, Any]:
    times = sorted(c.time_s * 1000.0 for c in summary.cases)
    if not times:
        return {"count": 0, "avg_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0, "total_ms": 0.0}
    def pct(p: float) -> float:
        k = (len(times) - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return times[int(k)]
        return times[f] + (times[c] - times[f]) * (k - f)
    total = sum(times)
    return {
        "count": len(times),
        "avg_ms": total / len(times),
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "max_ms": times[-1],
        "total_ms": total,
        "source": "junit_case_durations",
    }


def render_markdown(
    summary: SuiteSummary,
    rc: int,
    thresholds: dict[str, Any] | None = None,
    instrumented: dict[str, Any] | None = None,
    run_ctx: dict[str, Any] | None = None,
) -> str:
    thresholds = thresholds or {}
    instrumented = instrumented or {}
    run_ctx = run_ctx or {}
    lat = _latency_stats(summary)
    lines = []
    status = "PASS" if rc == 0 and summary.ok else "FAIL"
    lines.append(f"# ScopeGate Bench Report ({status})")
    lines.append("")
    lines.append(
        f"**Totals:** tests={summary.tests} passed={summary.passed} failures={summary.failures} "
        f"errors={summary.errors} skipped={summary.skipped} xfailed={summary.xfailed} "
        f"xpassed={summary.xpassed} time={summary.time_s:.3f}s rc={rc}"
    )
    lines.append("")
    lines.append("## Run context (mode/gateway)")
    lines.append("")
    lines.append(f"- bench_mode: `{run_ctx.get('bench_mode', 'unknown')}` (baseline|dryrun|enforce; live cases require configured gateway)")
    lines.append(f"- gateway_url: `{run_ctx.get('gateway_url') or '(not configured)'}`")
    lines.append(f"- gateway_configured: `{run_ctx.get('gateway_configured', False)}`")
    lines.append(f"- gateway_reachable: `{run_ctx.get('gateway_reachable')}`")
    lines.append(f"- gateway_probe: `{run_ctx.get('gateway_probe', '')}`")
    lines.append(f"- expected_baseline: {run_ctx.get('expected_baseline', '')}")
    lines.append("")
    if thresholds:
        lines.append(f"**Thresholds:** {json.dumps(thresholds, sort_keys=True)}")
        lines.append("")
    lines.append("## README table format")
    lines.append("")
    lines.append(render_readme_table(summary, rc, run_ctx=run_ctx).rstrip())
    lines.append("")
    by = _class_counts(summary)
    lines.append("## By attack class")
    lines.append("")
    lines.append("| Class | Total | Pass | Fail | Error | XFail | XPass | Skip |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for cls in ATTACK_MARKERS + ["unclassified"]:
        d = by.get(cls)
        if not d:
            continue
        lines.append(
            f"| {cls} | {d['total']} | {d['pass']} | {d['fail']} | {d['error']} | {d['xfail']} | {d['xpass']} | {d['skip']} |"
        )
    lines.append("")
    xfails = _xfail_cases(summary)
    lines.append("## XFailed cases (gateway-dependent / live-unconfigured)")
    lines.append("")
    if xfails:
        lines.append("| Case | Class | Outcome | Reason (why xfailed) |")
        lines.append("|---|---|---|---|")
        for x in xfails:
            reason = (x.get("reason") or "").replace("\n", " ").replace("|", "/").strip()
            lines.append(f"| `{x['name']}` | {x['class']} | {x['outcome']} | {reason} |")
    else:
        lines.append("_No xfailed/xpassed cases in this run._")
    lines.append("")
    lines.append("## Cases")
    lines.append("")
    lines.append("| Case | Class | Outcome | Time (s) | Note |")
    lines.append("|---|---|---|---:|---|")
    for c in summary.cases:
        note = (c.message or "").replace("\n", " ")[:120]
        lines.append(f"| `{c.name}` | {c.attack_class} | {c.outcome} | {c.time_s:.4f} | {note} |")
    lines.append("")
    lines.append("## Latency / overhead")
    lines.append("")
    lines.append(
        f"- case_duration_stats_ms: count={lat['count']} avg={lat['avg_ms']:.3f} p50={lat['p50_ms']:.3f} "
        f"p95={lat['p95_ms']:.3f} max={lat['max_ms']:.3f} total={lat['total_ms']:.3f} (source: JUnit case durations)"
    )
    if instrumented and instrumented.get("summary_ms"):
        s = instrumented["summary_ms"]
        lines.append(
            f"- instrumented_records_ms: count={s.get('count',0)} avg={s.get('avg_ms',0):.3f} "
            f"p50={s.get('p50_ms',0):.3f} p95={s.get('p95_ms',0):.3f} max={s.get('max_ms',0):.3f} "
            f"total={s.get('total_ms',0):.3f} statuses={json.dumps(s.get('by_status',{}), sort_keys=True)}"
        )
    else:
        lines.append("- instrumented_records: not provided (set BENCH_LATENCY_OUT during pytest and/or pass --latency-json to report).")
    lines.append("")
    return "\n".join(lines)


def _check_thresholds(summary: SuiteSummary, args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    thresholds: dict[str, Any] = {}
    reasons: list[str] = []
    if args.max_failures is not None:
        thresholds["max_failures"] = args.max_failures
        if summary.failures > args.max_failures:
            reasons.append(f"failures {summary.failures} > {args.max_failures}")
    if args.max_errors is not None:
        thresholds["max_errors"] = args.max_errors
        if summary.errors > args.max_errors:
            reasons.append(f"errors {summary.errors} > {args.max_errors}")
    if args.max_xpassed is not None:
        thresholds["max_xpassed"] = args.max_xpassed
        if summary.xpassed > args.max_xpassed:
            reasons.append(f"xpassed {summary.xpassed} > {args.max_xpassed}")
    if args.min_passed is not None:
        thresholds["min_passed"] = args.min_passed
        if summary.passed < args.min_passed:
            reasons.append(f"passed {summary.passed} < {args.min_passed}")
    if args.max_time_s is not None:
        thresholds["max_time_s"] = args.max_time_s
        if summary.time_s > args.max_time_s:
            reasons.append(f"time_s {summary.time_s:.3f} > {args.max_time_s}")
    if args.max_p95_case_ms is not None:
        lat = _latency_stats(summary)
        thresholds["max_p95_case_ms"] = args.max_p95_case_ms
        if lat["p95_ms"] > args.max_p95_case_ms:
            reasons.append(f"p95_case_ms {lat['p95_ms']:.3f} > {args.max_p95_case_ms}")
    thresholds["violations"] = reasons
    return (1 if reasons else 0), thresholds


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate bench CI-style summary/report (markdown/json)")
    ap.add_argument("--junitxml", help="Read existing JUnit XML instead of running pytest")
    ap.add_argument("--json", dest="json_out", help="Write JSON report to path")
    ap.add_argument("--md", dest="md_out", help="Write markdown report to path")
    ap.add_argument(
        "--format",
        choices=("ci", "readme-table"),
        default="ci",
        help="Stdout format: full CI markdown (default) or compact README table block",
    )
    ap.add_argument("--latency-json", help="Read instrumented latency artifact JSON (from BENCH_LATENCY_OUT)")
    ap.add_argument("--bench-mode", help="Bench mode metadata for report (default: $SCOPEGATE_BENCH_MODE or baseline)")
    ap.add_argument("--gateway-url", help="Gateway URL/config context for report (default: $SCOPEGATE_GATEWAY_URL)")
    ap.add_argument("--max-failures", type=int, default=None, help="CI threshold: fail if failures exceed value")
    ap.add_argument("--max-errors", type=int, default=None, help="CI threshold: fail if errors exceed value")
    ap.add_argument("--max-xpassed", type=int, default=0, help="CI threshold: fail if xpassed exceed value (default 0)")
    ap.add_argument("--min-passed", type=int, default=None, help="CI threshold: fail if passed below value")
    ap.add_argument("--max-time-s", type=float, default=None, help="CI threshold: fail if suite time exceeds seconds")
    ap.add_argument("--max-p95-case-ms", type=float, default=None, help="CI threshold: fail if case p95 latency exceeds ms")
    ap.add_argument("--max-instrumented-p95-ms", type=float, default=None, help="CI threshold: fail if instrumented p95 exceeds ms")
    ap.add_argument("pytest_args", nargs=argparse.REMAINDER, help="Extra pytest args (default: bench -q); prefix with --")
    args = ap.parse_args(argv)
    if args.pytest_args and args.pytest_args[0] == "--":
        args.pytest_args = args.pytest_args[1:]

    if args.junitxml:
        summary = parse_junit(Path(args.junitxml))
        rc = 0 if summary.ok else 1
    else:
        pytest_args = args.pytest_args or ["bench", "-q"]
        with tempfile.TemporaryDirectory() as td:
            junit_path = Path(td) / "bench-junit.xml"
            rc, summary = run_pytest(pytest_args, junit_path)

    run_ctx = _run_context(args)
    instrumented: dict[str, Any] = {}
    if getattr(args, "latency_json", None):
        try:
            instrumented = json.loads(Path(args.latency_json).read_text())
        except Exception as e:
            instrumented = {"error": str(e), "path": args.latency_json}
    # optional instrumented p95 threshold
    if args.max_instrumented_p95_ms is not None:
        s = (instrumented.get("summary_ms") or {}) if isinstance(instrumented, dict) else {}
        p95 = float(s.get("p95_ms", 0.0) or 0.0)
        thresholds = {}  # will be recomputed below
    th_rc, thresholds = _check_thresholds(summary, args)
    if args.max_instrumented_p95_ms is not None:
        s = (instrumented.get("summary_ms") or {}) if isinstance(instrumented, dict) else {}
        p95 = float(s.get("p95_ms", 0.0) or 0.0)
        thresholds["max_instrumented_p95_ms"] = args.max_instrumented_p95_ms
        if p95 > args.max_instrumented_p95_ms:
            thresholds.setdefault("violations", []).append(f"instrumented_p95_ms {p95:.3f} > {args.max_instrumented_p95_ms}")
            th_rc = 1
    rc = rc or th_rc
    lat = _latency_stats(summary)
    timing = {
        "case_duration_ms": lat,
        "instrumented": instrumented,
        "note": "Latency/overhead from JUnit case durations; instrumented records from harness TimingRecord export when provided.",
    }
    ci_md = render_markdown(summary, rc, thresholds=thresholds, instrumented=instrumented if isinstance(instrumented, dict) else {}, run_ctx=run_ctx)
    readme_md = render_readme_table(summary, rc, run_ctx=run_ctx)
    out = readme_md if args.format == "readme-table" else ci_md
    xfail_cases = _xfail_cases(summary)
    report: dict[str, Any] = {
        "suite": "bench",
        "run_context": run_ctx,
        "summary": {k: v for k, v in asdict(summary).items() if k != "cases"},
        "cases": [asdict(c) for c in summary.cases],
        "xfail_cases": xfail_cases,
        "returncode": rc,
        "thresholds": thresholds,
        "latency_ms_placeholders": timing,
        "latency_ms": timing["case_duration_ms"],
        "instrumented_latency": instrumented if isinstance(instrumented, dict) else {"error": "invalid instrumented payload"},
        "readme_table_markdown": readme_md,
    }

    sys.stdout.write(out)
    if args.md_out:
        Path(args.md_out).write_text(ci_md)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
