"""Shared helpers for the AWOZ-1227 demo test scripts."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def load_env():
    env_path = ROOT / ".env"
    if not env_path.exists():
        raise SystemExit(f"Missing {env_path}. Copy .env.example to .env first.")
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # A blank value is an ABSENCE, not a value -- see docs/11
        # B-10b, where a placeholder `AWS_PROFILE=` in .env reached
        # botocore as a request for a profile named "".
        if not v.strip():
            continue
        os.environ.setdefault(k, v)

def rewritten_credential_path():
    return ROOT / "_secrets" / "rewritten-credential.json"

def raw_credential_path():
    return ROOT / "_secrets" / "raw-credential.json"

def load_rewritten_credential():
    p = rewritten_credential_path()
    if not p.exists():
        raise SystemExit(f"Missing {p}. Run scripts/03 and scripts/04 first.")
    return json.loads(p.read_text())

class Report:
    """Accumulates PASS/FAIL rows in the shape the CONOPS evidence rule
    expects (Section 6.1): test ID, expected result, actual result, date,
    evidence reference."""
    def __init__(self):
        self.rows = []

    def record(self, test_id, description, expected, actual, passed, evidence_ref=""):
        import datetime
        self.rows.append({
            "test_id": test_id,
            "description": description,
            "expected": expected,
            "actual": actual,
            "passed": passed,
            "date": datetime.datetime.utcnow().isoformat() + "Z",
            "evidence_ref": evidence_ref,
        })
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {test_id}: {description}\n    expected: {expected}\n    actual:   {actual}\n")

    def write(self, path):
        path.write_text(json.dumps(self.rows, indent=2))
        # write_text creates 0664 from the umask, and this report's callers
        # land it in _secrets/, where the hygiene gate requires 0600. Running
        # the §6.3 session therefore left the repository FAILING its own gate
        # -- the same defect as b32c's shutil.copy2 backup, in a second
        # place. The chmod belongs in the writer, not in a gate exemption:
        # an exemption added so a local run would pass is a candidate for
        # having disabled the thing it was meant to observe (B-47).
        try:
            path.chmod(0o600)
        except OSError:
            pass
        print(f"\nWrote evidence log: {path}  [0600]")

    def summary(self):
        total = len(self.rows)
        passed = sum(1 for r in self.rows if r["passed"])
        print(f"\n{passed}/{total} checks passed.")
        return passed == total
