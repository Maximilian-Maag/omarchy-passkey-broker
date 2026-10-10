#!/usr/bin/env python3
"""Mutation testing for plugin sources — no external toolchain.

Real mutation testing needs a mutator, a runner and a verdict. There is no mutmut /
cosmic-ray / Stryker / bats on an Omarchy box and the plugins deliberately pull in no
extra dependencies, so this applies a small, fixed set of operators per language and
checks that the test suite notices each change.

    python3 tools/mutator.py                 # run every target in tests/mutation.json
    python3 tools/mutator.py --list          # show the mutants, run nothing
    python3 tools/mutator.py --only PATH     # one target
    python3 tools/mutator.py --json out.json

A mutant is KILLED when the target's test command fails (the suite noticed) and
SURVIVED when it still passes. Exit status is 1 when the kill rate drops below
min_kill_rate, or when a target produces no mutants at all — a run over nothing must
never look green.

Operators are applied outside string literals and comments (a character mask computed
per file), and a mutant that no longer parses is reported as skipped rather than
counted as killed, so a syntax error cannot inflate the score.
"""
import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

# operator, replacement, label — anchored so they cannot fire on longer tokens
OPERATORS = {
    "python": [
        (r"==", "!=", "eq->ne"),
        (r"!=", "==", "ne->eq"),
        (r"<=", "<", "le->lt"),
        (r">=", ">", "ge->gt"),
        (r"(?<![<>=!])<(?![=])", "<=", "lt->le"),
        (r"(?<![<>=!])>(?![=])", ">=", "gt->ge"),
        (r"\band\b", "or", "and->or"),
        (r"\bor\b", "and", "or->and"),
        (r"\bnot\s+", "", "drop-not"),
        (r"\bTrue\b", "False", "true->false"),
        (r"\bFalse\b", "True", "false->true"),
        (r"(?<=[\w\)\]])\s\+\s(?=[\w\(])", " - ", "plus->minus"),
        (r"\b(\d+)\b", None, "number±1"),
    ],
    "javascript": [
        (r"===", "!==", "seq->sne"),
        (r"!==", "===", "sne->seq"),
        (r"==(?!=)", "!=", "eq->ne"),
        (r"!=(?!=)", "==", "ne->eq"),
        (r"<=", "<", "le->lt"),
        (r">=", ">", "ge->gt"),
        (r"(?<![<>=!])<(?![=])", "<=", "lt->le"),
        (r"(?<![<>=!])>(?![=])", ">=", "gt->ge"),
        (r"&&", "||", "and->or"),
        (r"\|\|", "&&", "or->and"),
        (r"\btrue\b", "false", "true->false"),
        (r"\bfalse\b", "true", "false->true"),
        (r"(?<=[\w\)\]\'])\s\+\s(?=[\w\(])", " - ", "plus->minus"),
        (r"\b(\d+)\b", None, "number±1"),
    ],
    "shell": [
        (r"-eq\b", "-ne", "eq->ne"),
        (r"-ne\b", "-eq", "ne->eq"),
        (r"-z\b", "-n", "empty->nonempty"),
        (r"-n\b", "-z", "nonempty->empty"),
        (r"(?<!\|)&&(?!\|)", "||", "and->or"),
        (r"(?<!\|)\|\|(?!\|)", "&&", "or->and"),
        (r"(?<=[\[\s])=(?=[\s\]])", "!=", "assign->neq"),
        (r"-gt\b", "-lt", "gt->lt"),
        (r"-lt\b", "-gt", "lt->gt"),
        (r"\b(\d+)\b", None, "number±1"),
    ],
}
NUMBER_RE = re.compile(r"\b\d+\b")


def code_mask(text, lang):
    """True where a character is code (not inside a string literal or comment)."""
    mask = [True] * len(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        # Shell comments count too. Excluding them meant every comment line in a shell
        # target was mutated into an unkillable no-op, which silently held scores down
        # (qute-yt-dl could not exceed 17/23 = 0.74 however good its tests were). A `#`
        # only starts a comment at the start of a word, so ${#var} and a#b stay code.
        if ch == "#" and (lang == "python" or
                          (lang == "shell" and (i == 0 or text[i - 1] in " \t;&|(\n"))):
            while i < n and text[i] != "\n":
                mask[i] = False
                i += 1
        elif lang != "shell" and text.startswith("//", i):
            while i < n and text[i] != "\n":
                mask[i] = False
                i += 1
        elif lang != "shell" and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            for j in range(i, end):
                mask[j] = False
            i = end
        elif ch in "\"'":
            quote = ch
            triple = lang == "python" and text.startswith(quote * 3, i)
            if triple:
                end = text.find(quote * 3, i + 3)
                end = n if end == -1 else end + 3
            else:
                j = i + 1
                while j < n and text[j] != quote and text[j] != "\n":
                    j += 2 if text[j] == "\\" else 1
                end = min(j + 1, n)
            for j in range(i, end):
                mask[j] = False
            i = end
        else:
            i += 1
    return mask


def inside_regex(line, column):
    """True when `column` sits inside a JS regex literal.

    Heuristic: an odd number of unescaped slashes *before* the position means an
    opening slash has not been closed yet. This is what stops the number operator
    firing on the `6` in `/[A-Za-z0-9_-]{6,}/` — mutants inside a regex literal are
    noise (they rarely change behaviour and never indicate a weak test).
    """
    prefix = re.sub(r"\\.", "", line[:column])
    return prefix.count("/") % 2 == 1


def mutants_for(text, lang, per_operator=2):
    """(start, end, replacement, label, line) for each candidate mutant — absolute
    offsets from text.span(), so a caller must slice text[start:end]."""
    mask = code_mask(text, lang)
    out, seen = [], set()
    for pattern, repl, label in OPERATORS[lang]:
        rex = re.compile(pattern)
        used = 0
        for m in rex.finditer(text):
            if used >= per_operator:
                break
            start, end = m.span()
            if not any(mask[start:end]):
                continue                                  # inside a string/comment
            line_no = text.count("\n", 0, start) + 1
            if lang == "javascript" and inside_regex(text.splitlines()[line_no - 1],
                                                     start - (text.rfind("\n", 0, start) + 1)):
                continue                                  # inside a regex literal
            if label == "number±1":
                digits = m.group(0)
                value = str(int(digits) + 1 if digits.strip("0") else 1)
                if value == digits:
                    continue
                replacement = value
            else:
                replacement = repl
            key = (start, label)
            if key in seen:
                continue
            seen.add(key)
            out.append((start, end, replacement, label, line_no))
            used += 1
    return sorted(out, key=lambda x: (x[4], x[3]))


def compiles(path, lang):
    checks = {"python": [sys.executable, "-m", "py_compile", str(path)],
              "javascript": ["node", "--check", str(path)],
              "shell": ["bash", "-n", str(path)]}
    try:
        return subprocess.run(checks[lang], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def load_config(repo, path):
    cfg = json.loads((repo / path).read_text())
    cfg.setdefault("per_operator", 2)
    cfg.setdefault("timeout", 120)
    cfg.setdefault("min_kill_rate", 0.80)
    cfg.setdefault("max_mutants", 0)
    if not cfg.get("targets"):
        raise SystemExit("%s: no targets configured" % path)
    return cfg


def run_target(repo, target, cfg, tmp_root, dry_run=False, log=print):
    src = repo / target["path"]
    if not src.is_file():
        log("  !! missing target %s" % target["path"])
        return {"name": target["path"], "error": "missing target", "mutants": []}
    lang = target["lang"]
    text = src.read_text()
    mutants = mutants_for(text, lang, cfg["per_operator"])
    cap = int(target.get("max_mutants") or cfg.get("max_mutants") or 0)
    if cap and len(mutants) > cap:          # deterministic prefix, never a random sample
        mutants = mutants[:cap]
    work = pathlib.Path(tempfile.mkdtemp(prefix="mutant-", dir=str(tmp_root)))
    ignore = shutil.ignore_patterns(".git", "__pycache__", "node_modules", "*.pyc")
    shutil.copytree(repo, work / "repo", ignore=ignore, dirs_exist_ok=True)
    copied = work / "repo" / target["path"]
    original = copied.read_bytes()

    # Baseline: the target's tests must pass BEFORE mutating, or every mutant would
    # be counted as killed and the target would report a fake perfect score.
    if not dry_run:
        try:
            base = subprocess.run(target["tests"], cwd=str(work / "repo"),
                                  capture_output=True, text=True, timeout=cfg["timeout"])
        except subprocess.TimeoutExpired:
            return {"name": target["path"], "lang": lang, "mutants": [],
                    "error": "baseline test run timed out"}
        if base.returncode != 0:
            return {"name": target["path"], "lang": lang, "mutants": [],
                    "error": "baseline tests fail on unmutated code (a mutation score "
                             "would be meaningless): " +
                             (base.stdout + base.stderr).strip().splitlines()[-1][:160]}

    results = []
    for offset, end, replacement, label, line_no in mutants:
        # span() returns (start, END) — absolute offsets, not a length. Slicing with
        # `offset + end` corrupts the file away from offset 0, which made almost every
        # mutant unparsable and the whole pass silently vacuous.
        assert 0 <= offset < end <= len(text), "bad mutant span"
        mutated = text[:offset] + replacement + text[end:]
        before = text[offset:end]
        record = {"line": line_no, "operator": label, "before": before, "after": replacement,
                  "target": target["path"]}
        if dry_run:
            results.append({**record, "verdict": "listed"})
            continue
        copied.write_text(mutated)
        if not compiles(copied, lang):
            copied.write_bytes(original)
            results.append({**record, "verdict": "skipped-unparsable"})
            continue
        started = time.time()
        try:
            proc = subprocess.run(target["tests"], cwd=str(work / "repo"),
                                  capture_output=True, text=True, timeout=cfg["timeout"])
            verdict = "killed" if proc.returncode != 0 else "survived"
            detail = (proc.stdout + proc.stderr).strip().splitlines()[-1:] or [""]
        except subprocess.TimeoutExpired:
            verdict, detail = "timeout", ["test run exceeded %ss" % cfg["timeout"]]
        copied.write_bytes(original)
        results.append({**record, "verdict": verdict, "seconds": round(time.time() - started, 1),
                        "detail": detail[0][:120]})
    shutil.rmtree(work, ignore_errors=True)

    # Equivalent mutants: a mutation that cannot change observable behaviour can never be
    # killed by any test, so leaving it in the denominator caps a target below the bar no
    # matter how good its tests are (reader.js measured 36/46 = 0.78, where all ten
    # survivors were verified equivalent by applying each one and diffing the harness's
    # full output). Each entry needs a line, a kind and a REASON, and is listed separately
    # in the output — the threshold itself is never lowered.
    equiv = {(e.get("line"), e.get("kind")) for e in (target.get("equivalent") or [])}
    survivors = [r for r in results if r["verdict"] == "survived"]
    # the mutant record names this field "operator", not "kind" — matching on "kind" read
    # a key that does not exist, so the filter silently never fired
    equivalent = [r for r in survivors if (r.get("line"), r.get("operator")) in equiv]
    counted = [r for r in results if r["verdict"] in ("killed", "survived")
               and r not in equivalent]
    killed = [r for r in counted if r["verdict"] == "killed"]
    rate = (len(killed) / len(counted)) if counted else 0.0
    return {"name": target["path"], "lang": lang, "mutants": results,
            "killed": len(killed), "counted": len(counted),
            "skipped": len([r for r in results if r["verdict"].startswith("skipped")]),
            "timeout": len([r for r in results if r["verdict"] == "timeout"]),
            "kill_rate": round(rate, 3),
        "equivalent": len(equivalent)}


def main():
    ap = argparse.ArgumentParser(description="dependency-free mutation testing")
    ap.add_argument("--config", default="tests/mutation.json")
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("--list", action="store_true", help="list mutants, run nothing")
    ap.add_argument("--json", metavar="PATH", help="write the full report here")
    ap.add_argument("--max-rate", type=float, help="override min_kill_rate")
    args = ap.parse_args()

    repo = pathlib.Path(__file__).resolve().parent.parent
    cfg = load_config(repo, args.config)
    if args.max_rate is not None:
        cfg["min_kill_rate"] = args.max_rate
    targets = [t for t in cfg["targets"] if not args.only or t["path"] in args.only]
    if not targets:
        print("no targets selected", file=sys.stderr)
        return 1

    print("mutation testing — %d target(s), min kill rate %.2f%s"
          % (len(targets), cfg["min_kill_rate"], ", dry run" if args.list else ""))
    tmp_root = tempfile.mkdtemp(prefix="hermes-mutants-")
    reports, failed = [], []
    try:
        for target in targets:
            rep = run_target(repo, target, cfg, tmp_root, dry_run=args.list)
            reports.append(rep)
            if rep.get("error"):
                failed.append("%s: %s" % (rep["name"], rep["error"]))
                continue
            if args.list:
                for r in rep["mutants"]:
                    print("  %-46s line %-5s %-14s %s -> %s"
                          % (rep["name"], r["line"], r["operator"], r["before"], r["after"]))
                continue
            print("  %-46s %2d/%-2d killed  rate %.2f  (%d skipped, %d timeout)"
                  % (rep["name"], rep["killed"], rep["counted"], rep["kill_rate"],
                     rep["skipped"], rep["timeout"]))
            for r in rep["mutants"]:
                if r["verdict"] == "survived":
                    print("      SURVIVED line %-5s %-14s %s -> %s"
                          % (r["line"], r["operator"], r["before"], r["after"]))
            if not rep["counted"]:
                failed.append("%s: no mutants generated (a mutation run over nothing "
                              "must not pass)" % rep["name"])
            elif rep["kill_rate"] < cfg["min_kill_rate"]:
                failed.append("%s: kill rate %.2f < %.2f"
                              % (rep["name"], rep["kill_rate"], cfg["min_kill_rate"]))
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(reports, indent=2) + "\n")
    if args.list:
        return 0
    if failed:
        print()
        for line in failed:
            print("FAIL " + line)
        return 1
    print("all targets above the kill-rate threshold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
