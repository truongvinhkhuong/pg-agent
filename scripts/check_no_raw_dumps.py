# -*- coding: utf-8 -*-
"""Custom pre-commit guard: block raw business-text dumps.

detect-secrets/trufflehog catch API keys & high-entropy strings — NOT "this looks
like a real invoice". This heuristic complements them. It is intentionally
conservative (some false positives are acceptable for an anti-leak gate); override
a known-good file via the `exclude` pattern in .pre-commit-config.yaml.

Flags a staged file when it contains:
  * a Vietnamese tax id (MST): 10 digits, optionally `-` + 3 digits (branch);
  * many very long lines (pasted records / exported tables);
  * a large block of diacritic-heavy Vietnamese prose (invoice/contract bodies).

Usage (pre-commit passes staged filenames as argv):
    python scripts/check_no_raw_dumps.py file1 file2 ...
"""

import re
import sys

MST_RE = re.compile(r"\b\d{10}(-\d{3})?\b")
VN_DIACRITICS = "àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ"
VN_WORD_RE = re.compile(f"[{VN_DIACRITICS}{VN_DIACRITICS.upper()}]")

LONG_LINE = 300            # chars
MAX_LONG_LINES = 5         # how many long lines before we flag
DIACRITIC_RATIO = 0.06     # share of diacritic chars suggesting real VN prose
MIN_BODY_CHARS = 1500      # only apply prose check to large-ish files


def check_file(path):
    problems = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except Exception:
        return problems

    mst = MST_RE.findall(text)
    # The bare regex also matches phone-ish numbers; require >=2 hits to flag.
    mst_hits = len(MST_RE.findall(text))
    if mst_hits >= 2:
        problems.append(f"{path}: {mst_hits} possible tax-id (MST) patterns")

    long_lines = sum(1 for ln in text.splitlines() if len(ln) > LONG_LINE)
    if long_lines > MAX_LONG_LINES:
        problems.append(f"{path}: {long_lines} very long lines (exported records?)")

    if len(text) >= MIN_BODY_CHARS:
        diac = len(VN_WORD_RE.findall(text))
        if diac / max(len(text), 1) > DIACRITIC_RATIO:
            problems.append(f"{path}: large Vietnamese prose block (invoice/contract body?)")

    return problems


def main(argv):
    all_problems = []
    for path in argv:
        all_problems.extend(check_file(path))
    if all_problems:
        sys.stderr.write("\n[anti-leak] potential raw business data detected:\n")
        for p in all_problems:
            sys.stderr.write("  - " + p + "\n")
        sys.stderr.write(
            "\nIf this is synthetic/safe, add it to `exclude` in "
            ".pre-commit-config.yaml. Do NOT bypass with --no-verify for real data.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
