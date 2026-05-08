#!/usr/bin/env python3
"""Count registered MCP tools in tools/*.py.

Usage:
  python3 scripts/tool_count.py
  python3 scripts/tool_count.py --breakdown
  python3 scripts/tool_count.py --json
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path


def is_mcp_tool_decorator(node: ast.expr) -> bool:
    """Return True for decorators like @mcp.tool()."""
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != "tool":
        return False
    if not isinstance(node.func.value, ast.Name):
        return False
    return node.func.value.id == "mcp"


def count_tools_in_file(path: Path) -> int:
    """Count async functions decorated with @mcp.tool()."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            if any(is_mcp_tool_decorator(d) for d in node.decorator_list):
                count += 1
    return count


def count_all_tools(repo_root: Path) -> dict:
    """Return total + per-module tool counts."""
    tools_dir = repo_root / "tools"
    per_module: dict[str, int] = {}
    total = 0

    for file_path in sorted(tools_dir.glob("*.py")):
        if file_path.name == "__init__.py":
            continue
        c = count_tools_in_file(file_path)
        if c > 0:
            per_module[file_path.name] = c
            total += c

    return {"total": total, "per_module": per_module}


def main() -> int:
    parser = argparse.ArgumentParser(description="Count MCP tools")
    parser.add_argument("--breakdown", action="store_true", help="Show per-module counts")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    result = count_all_tools(repo_root)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"TOTAL_MCP_TOOLS={result['total']}")
    if args.breakdown:
        for module, count in result["per_module"].items():
            print(f"{module}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
