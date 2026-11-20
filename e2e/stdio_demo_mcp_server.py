#!/usr/bin/env python3
"""
Minimal stdio MCP JSON-RPC demo server for ScopeGate e2e evidence.

Speaks line-delimited JSON-RPC 2.0 over stdin/stdout.
Implements initialize, ping, tools/list, and tools/call for demo.echo.
"""
from __future__ import annotations

import json
import sys
from typing import Any


def write(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def result(req_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": payload}


def error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle(msg: dict[str, Any]) -> dict[str, Any] | None:
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    if method == "initialize":
        return result(
            req_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "scopegate-e2e-stdio-demo", "version": "0.1.0"},
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return result(req_id, {})
    if method == "tools/list":
        return result(
            req_id,
            {
                "tools": [
                    {
                        "name": "demo.echo",
                        "description": "Echo arguments back for live gateway/stdio evidence.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"message": {"type": "string"}},
                            "additionalProperties": True,
                        },
                    }
                ]
            },
        )
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if name == "demo.echo":
            text = json.dumps({"echo": arguments}, sort_keys=True, separators=(",", ":"))
            return result(
                req_id,
                {
                    "content": [{"type": "text", "text": text}],
                    "isError": False,
                    "structuredContent": {"ok": True, "tool": "demo.echo", "echo": arguments},
                },
            )
        return result(
            req_id,
            {
                "content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True,
            },
        )

    if req_id is None:
        return None
    return error(req_id, -32601, f"Method not found: {method}")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            write(error(None, -32700, "Parse error"))
            continue
        if not isinstance(msg, dict):
            write(error(None, -32600, "Invalid Request"))
            continue
        try:
            resp = handle(msg)
        except Exception as exc:  # pragma: no cover - defensive
            resp = error(msg.get("id"), -32603, f"Internal error: {exc}")
        if resp is not None:
            write(resp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
