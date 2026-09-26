"""Developer/debug runner for Terraform structural reconnaissance.

    python -m flowlens.repository <path> [--explain ID ...] [--json] [--diagnostics]

Prints the reconnaissance summary of the repository at <path>. Read-only and
offline. This is a debugging aid, not part of the production ``flowlens scan``.
"""
from __future__ import annotations

import argparse
import sys

from flowlens.repository.build import build_repository_model, summarize
from flowlens.repository.explain import explain


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m flowlens.repository", description=__doc__.splitlines()[0])
    parser.add_argument("path")
    parser.add_argument("--explain", action="append", default=[], metavar="ID",
                        help="explain an entity id (cfg:..., ctx:root:..., tf:...); repeatable")
    parser.add_argument("--json", action="store_true", help="print the full RepositoryModel as canonical JSON")
    parser.add_argument("--diagnostics", action="store_true", help="list every diagnostic")
    args = parser.parse_args(argv)

    model = build_repository_model(args.path)
    if args.json:
        print(model.to_json())
        return 0
    print(summarize(model).render())
    if args.diagnostics:
        for d in model.diagnostics:
            print(f"  [{d.severity.value}] {d.code} {d.subject}: {d.message}")
    for subject in args.explain:
        print()
        print(explain(model, subject))
    violations = model.validate()
    for v in violations:
        print(f"MODEL INVARIANT VIOLATION: {v}", file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
