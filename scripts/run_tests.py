#!/usr/bin/env python3
"""
scripts/run_tests.py
=====================
Master test runner — executes all test suites and produces a unified report.
Works without pytest installed. Run from the project root.

Usage:
    python scripts/run_tests.py           # all suites
    python scripts/run_tests.py --fast    # skip integration (unit only)
    python scripts/run_tests.py --suite pii_shield

Exit codes:
    0  — all tests passed
    1  — one or more tests failed
    2  — configuration / import error
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable

# Ensure project root is on sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ── Suite registry ────────────────────────────────────────────────────────────

@dataclass
class Suite:
    name:        str
    module_path: str          # relative to project root
    entry_fn:    str = "main" # function to call inside the module
    is_integration: bool = False
    description: str = ""


SUITES: list[Suite] = [
    Suite(
        name        = "pii_shield",
        module_path = "tests/test_pii_shield.py",
        description = "PIIShield unit tests — detection, masking, blocking, tokenisation",
    ),
    Suite(
        name        = "prompt_guard",
        module_path = "tests/test_prompt_guard.py",
        description = "PromptGuard / ResponseGuard unit tests — pre/post LLM inspection",
    ),
    Suite(
        name        = "rag_server",
        module_path = "tests/test_rag_server.py",
        is_integration = True,
        description = "RAG MCP Server integration tests — full tool-call pipeline",
    ),
    Suite(
        name        = "feature_store",
        module_path = "tests/test_feature_store.py",
        is_integration = True,
        description = "Feature Store MCP Server integration tests — token, context, ML features",
    ),
    Suite(
        name        = "e2e_pipeline",
        module_path = "tests/test_guardrail_pipeline.py",
        is_integration = True,
        description = "End-to-end guardrail pipeline across all 5 stages",
    ),
]


# ── Result tracking ───────────────────────────────────────────────────────────

@dataclass
class SuiteResult:
    name:       str
    passed:     bool
    duration_s: float
    error:      str = ""


# ── Runner ────────────────────────────────────────────────────────────────────

def load_and_run(suite: Suite) -> SuiteResult:
    """Load a test module by file path and call its entry function."""
    abs_path = os.path.join(ROOT, suite.module_path)

    if not os.path.exists(abs_path):
        return SuiteResult(suite.name, False, 0.0, f"File not found: {abs_path}")

    spec   = importlib.util.spec_from_file_location(suite.name, abs_path)
    module = importlib.util.module_from_spec(spec)

    t0 = time.perf_counter()
    try:
        spec.loader.exec_module(module)
        fn: Callable = getattr(module, suite.entry_fn)
        result = fn()
        duration = time.perf_counter() - t0
        passed   = result if isinstance(result, bool) else True
        return SuiteResult(suite.name, passed, duration)

    except SystemExit as e:
        duration = time.perf_counter() - t0
        passed   = (e.code == 0)
        return SuiteResult(suite.name, passed, duration,
                           "" if passed else f"SystemExit({e.code})")

    except Exception:
        duration = time.perf_counter() - t0
        tb = traceback.format_exc()
        return SuiteResult(suite.name, False, duration, tb[-400:])


def print_header(text: str, width: int = 62) -> None:
    print("\n" + "═" * width)
    print(f"  {text}")
    print("═" * width)


def print_section(text: str) -> None:
    print(f"\n  {text}")
    print("  " + "─" * 58)


def run(suites: list[Suite], verbose: bool = False) -> int:
    """Run all suites, print report, return exit code."""
    print_header("ENTERPRISE MCP AI PLATFORM — TEST RUNNER")
    print(f"  Suites: {len(suites)}   Root: {ROOT}")

    results: list[SuiteResult] = []

    for suite in suites:
        tag  = "[integration]" if suite.is_integration else "[unit]       "
        print(f"\n  ▶ {tag} {suite.name}")
        if verbose:
            print(f"           {suite.description}")

        r = load_and_run(suite)
        results.append(r)

        status = "✓ PASS" if r.passed else "✗ FAIL"
        print(f"    {status}  ({r.duration_s:.2f}s)", end="")
        if not r.passed and r.error:
            short_err = r.error.strip().splitlines()[-1][:70]
            print(f"  — {short_err}", end="")
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print_section("RESULTS")

    total   = len(results)
    passed  = sum(1 for r in results if r.passed)
    failed  = total - passed
    elapsed = sum(r.duration_s for r in results)

    # Table
    col = [40, 8, 8]
    fmt = f"  {{:<{col[0]}}}{{:>{col[1]}}}{{:>{col[2]}}}"
    print(fmt.format("Suite", "Status", "Time"))
    print("  " + "─" * sum(col))
    for r in results:
        status = "\u2713 PASS" if r.passed else "\u2717 FAIL"
        print(fmt.format(r.name, status, f"{r.duration_s:.2f}s"))
    print("  " + "─" * sum(col))
    print(fmt.format(f"Total: {passed}/{total} passed", "", f"{elapsed:.2f}s"))

    if failed:
        print(f"\n  FAILED SUITES:")
        for r in results:
            if not r.passed:
                print(f"    \u2192 {r.name}")
                if r.error:
                    for line in r.error.strip().splitlines()[-5:]:
                        print(f"      {line}")

    print()
    return 0 if failed == 0 else 1


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run the Enterprise MCP AI Platform test suites.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            f"  {s.name:<20} {s.description}" for s in SUITES
        ),
    )
    p.add_argument("--fast",  action="store_true", help="Unit tests only (skip integration)")
    p.add_argument("--suite", metavar="NAME",      help="Run a single named suite")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args()


def main() -> None:
    import logging
    logging.basicConfig(level=logging.WARNING)

    args = parse_args()

    if args.suite:
        suites = [s for s in SUITES if s.name == args.suite]
        if not suites:
            print(f"Unknown suite '{args.suite}'. Available: {[s.name for s in SUITES]}")
            sys.exit(2)
    elif args.fast:
        suites = [s for s in SUITES if not s.is_integration]
    else:
        suites = SUITES

    sys.exit(run(suites, verbose=args.verbose))


if __name__ == "__main__":
    main()
