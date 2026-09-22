"""Score the agent against the hand-labeled set and print the three numbers.

    python benchmark.py --engine rules      # no API key, instant smoke test
    python benchmark.py --engine agent       # the real LLM agent (needs key)
    python benchmark.py --engine agent --limit 20

Outputs: accuracy, false positives, false negatives, a per-error list, and
an audit log under runs/.
"""
import argparse
import csv
import json
import time
from datetime import datetime
from pathlib import Path

from iam_agent import rules

LABELS = Path("labels.csv")
POLICY_DIR = Path("policies")


def load_labeled(limit=None):
    rows = []
    with LABELS.open() as f:
        for r in csv.DictReader(f):
            if r["label"] == "":
                continue
            rows.append((r["file"], int(r["label"]), r["note"]))
    rows.sort(key=lambda x: x[0])
    return rows[:limit] if limit else rows


def predict_rules(filename, log):
    doc = json.loads((POLICY_DIR / filename).read_text())
    v = rules.assess(doc)
    log.append({"file": filename, "engine": "rules", "verdict": v})
    return 1 if v["verdict"] == "escalation" else 0, v


def predict_agent(filename, log):
    from iam_agent import agent
    v = agent.review(filename, log=log)
    return 1 if v["verdict"] == "escalation" else 0, v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["rules", "agent"], default="rules")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    labeled = load_labeled(args.limit)
    predict = predict_rules if args.engine == "rules" else predict_agent

    log, errors = [], []
    tp = tn = fp = fn = 0
    t0 = time.time()
    for filename, truth, note in labeled:
        pred, verdict = predict(filename, log)
        if pred == truth == 1:
            tp += 1
        elif pred == truth == 0:
            tn += 1
        elif pred == 1 and truth == 0:
            fp += 1
            errors.append((filename, "FALSE POSITIVE", note, verdict.get("why", "")))
        else:
            fn += 1
            errors.append((filename, "FALSE NEGATIVE", note, verdict.get("why", "")))

    n = len(labeled)
    acc = (tp + tn) / n if n else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    dur = time.time() - t0

    print(f"\nengine={args.engine}  policies={n}  time={dur:.1f}s")
    print("=" * 46)
    print(f"  accuracy            {acc:5.0%}   ({tp+tn}/{n} correct)")
    print(f"  false positives     {fp:>3}     (clean flagged as risky)")
    print(f"  false negatives     {fn:>3}     (risky missed)")
    print(f"  recall on risky     {recall:5.0%}")
    if errors:
        print("\n  where it was wrong:")
        for fnm, kind, note, why in errors:
            print(f"    {kind:15} {fnm}")
            print(f"        trap : {note}")
            print(f"        said : {why}")

    Path("runs").mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path("runs") / f"{args.engine}-{stamp}.jsonl"
    with out.open("w") as f:
        for entry in log:
            f.write(json.dumps(entry) + "\n")
    print(f"\n  audit log -> {out}")


if __name__ == "__main__":
    main()
