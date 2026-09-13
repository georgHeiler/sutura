#!/usr/bin/env python3
"""Run the corpus parent; it forks one fresh measured child per case."""

import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("expected", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    if not arguments.command:
        parser.error("provide a measurement command")

    try:
        completed = subprocess.run(
            arguments.command, text=True, capture_output=True, check=False
        )
    except OSError:
        print(
            json.dumps(
                {"status": "aggregate", "records": 0, "failures": 1},
                separators=(",", ":"),
            )
        )
        return 1
    records = []
    invalid = False
    for line in completed.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict) or record.get("topology") not in (
            "one_source",
            "two_source",
        ):
            continue
        if any(
            key not in record
            for key in (
                "status",
                "peak",
                "reserved",
                "rss",
                "ratio",
                "answered",
                "refused",
                "failed",
            )
        ):
            invalid = True
            continue
        if record.get("status") not in ("ok", "refused", "failed"):
            invalid = True
            continue
        records.append(record)
        print(json.dumps(record, separators=(",", ":")))
    complete = len(records) == arguments.expected and not invalid
    print(
        json.dumps(
            {
                "status": "aggregate",
                "records": len(records),
                "expected": arguments.expected,
                "failures": int(not complete),
            },
            separators=(",", ":"),
        )
    )
    return 0 if completed.returncode == 0 and complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
