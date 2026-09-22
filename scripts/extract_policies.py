"""Extract IAM policy documents from BishopFox/iam-vulnerable Terraform files
into plain policy JSON (one file per principal) plus labels.csv with the
known answer for each. Read-only: nothing is deployed to AWS.

Usage:
    python scripts/extract_policies.py /path/to/iam-vulnerable  policies/
"""
import csv
import json
import re
import sys
from pathlib import Path

import hcl2

# files that hold no scoreable policy of their own
SKIP = {"variables.tf", "service-linked-role-common.tf",
        "privesc-permissive-role-trust.tf", "sre.tf"}

# filename prefix -> (label, note). label 1 = has privilege-escalation risk.
LABELS = {
    "privesc": (1, "known privesc path"),
    "fn": (1, "exploitable but easy to miss (false-negative trap)"),
    "fp": (0, "looks risky but is NOT exploitable (false-positive trap)"),
    "sre": (1, "wildcard admin role"),
}


def unquote(o):
    if isinstance(o, dict):
        return {unquote(k): unquote(v) for k, v in o.items()}
    if isinstance(o, list):
        return [unquote(v) for v in o]
    if isinstance(o, str) and len(o) >= 2 and o[0] == o[-1] == '"':
        return o[1:-1]
    return o


def parse_jsonencode(expr: str):
    body = expr.strip()
    if body.startswith("${") and body.endswith("}"):
        body = body[2:-1].strip()
    m = re.match(r"jsonencode\((.*)\)\s*$", body, re.S)
    if not m:
        return None
    inner = m.group(1)
    parsed = hcl2.loads("x = " + inner)
    return unquote(parsed["x"])


def policy_doc_block_to_json(block: dict):
    """aws_iam_policy_document data block -> policy JSON dict."""
    statements = []
    stmts = block.get("statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for st in stmts:
        out = {"Effect": unquote(st.get("effect", "Allow"))}
        if st.get("actions"):
            out["Action"] = unquote(st["actions"])
        if st.get("not_actions"):
            out["NotAction"] = unquote(st["not_actions"])
        out["Resource"] = unquote(st.get("resources", ["*"]))
        if st.get("condition"):
            out["Condition"] = {"(condition present)": True}
        statements.append(out)
    return {"Version": "2012-10-17", "Statement": statements}


def label_for(name: str):
    for pref, (lab, note) in LABELS.items():
        if name.startswith(pref):
            return lab, note
    return None, ""


def main():
    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("policies")
    out.mkdir(parents=True, exist_ok=True)

    tf_files = list((src / "modules" / "free-resources").rglob("*.tf"))
    rows = []
    for tf in sorted(tf_files):
        if tf.name in SKIP:
            continue
        data = unquote(hcl2.load(tf.open()))

        # 1) inline jsonencode policies on aws_iam_policy resources
        for res in data.get("resource", []):
            for rtype, bodies in res.items():
                if rtype != "aws_iam_policy":
                    continue
                for rname, body in bodies.items():
                    pol = parse_jsonencode(body.get("policy", ""))
                    if pol is None:
                        continue
                    write_policy(rname, pol, out, rows)

        # 2) aws_iam_policy_document data blocks (condition / not_action cases)
        for dat in data.get("data", []):
            for dtype, bodies in dat.items():
                if dtype != "aws_iam_policy_document":
                    continue
                for dname, body in bodies.items():
                    pol = policy_doc_block_to_json(body)
                    write_policy(dname, pol, out, rows)

    with (out.parent / "labels.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file", "label", "note"])
        w.writerows(rows)

    labeled = [r for r in rows if r[1] != ""]
    print(f"wrote {len(rows)} policies, {len(labeled)} labeled -> {out}")
    print(f"  privesc/risky : {sum(1 for r in labeled if r[1] == 1)}")
    print(f"  clean         : {sum(1 for r in labeled if r[1] == 0)}")


def write_policy(name, pol, out: Path, rows):
    lab, note = label_for(name)
    fname = f"{name}.json"
    (out / fname).write_text(json.dumps(pol, indent=2))
    rows.append([fname, lab if lab is not None else "", note])


if __name__ == "__main__":
    main()
