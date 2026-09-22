"""IAM review agent.

The agent is given one task and one read-only tool (parse_policy). It
decides when to call the tool, reasons over what it reads, and returns a
verdict. Two guardrails matter for the interview story:
  * a hard step limit, so the loop can never run away;
  * a full audit log of every tool call and the final decision.

Nothing here touches a real AWS account. It reads policy JSON from disk.
"""
import json
import os
from pathlib import Path
from typing import Any

import anthropic

MODEL = os.environ.get("IAM_AGENT_MODEL", "claude-sonnet-5")
POLICY_DIR = Path(os.environ.get("IAM_POLICY_DIR", "policies"))
MAX_STEPS = 8

SYSTEM = (
    "You are an AWS IAM auditor. Given the name of a policy, use the "
    "parse_policy tool to read it, then decide whether the policy allows "
    "privilege escalation: a path by which the principal could grant itself "
    "more permissions than intended. Think about the interaction between "
    "statements. Remember: an explicit Deny overrides an Allow; a Condition "
    "or a tight Resource can make a dangerous action non-exploitable; "
    "NotAction with Allow is broad, not narrow. When you are done, reply "
    "with ONLY a JSON object: "
    '{"verdict": "escalation" | "no escalation", "action": "<the deciding '
    'action or null>", "why": "<one sentence>"}.'
)

TOOLS = [{
    "name": "parse_policy",
    "description": "Read one IAM policy JSON file by name and return its "
                   "Version and a cleaned list of statements.",
    "input_schema": {
        "type": "object",
        "properties": {"filename": {"type": "string",
                       "description": "policy file name, e.g. privesc1-...json"}},
        "required": ["filename"],
    },
}]


def parse_policy(filename: str) -> dict:
    """The one tool the agent can call. Read-only by construction."""
    path = POLICY_DIR / Path(filename).name  # basename only: no path escape
    if not path.exists():
        return {"error": f"{path.name} not found"}
    doc = json.loads(path.read_text())
    statements = []
    for st in doc.get("Statement", []):
        statements.append({
            "Effect": st.get("Effect", "Allow"),
            "Action": st.get("Action"),
            "NotAction": st.get("NotAction"),
            "Resource": st.get("Resource"),
            "Condition": bool(st.get("Condition")),
        })
    return {"Version": doc.get("Version"), "Statement": statements}


def _extract_verdict(text: str) -> dict:
    text = text.strip()
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return {"verdict": "unsure", "action": None, "why": "no parseable verdict"}


def review(filename: str, client: anthropic.Anthropic | None = None,
           log: list | None = None) -> dict:
    """Run the agent loop for one policy. Returns the verdict dict."""
    client = client or anthropic.Anthropic()
    log = log if log is not None else []
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": f"Review the policy '{filename}'."}]

    for step in range(MAX_STEPS):
        resp = client.messages.create(
            model=MODEL, max_tokens=1024, system=SYSTEM,
            tools=TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason == "tool_use":
            results = []
            for block in resp.content:
                if block.type == "tool_use":
                    out = parse_policy(**block.input)
                    log.append({"file": filename, "step": step,
                                "tool": block.name, "input": block.input})
                    results.append({"type": "tool_result",
                                    "tool_use_id": block.id,
                                    "content": json.dumps(out)})
            messages.append({"role": "user", "content": results})
            continue

        text = "".join(b.text for b in resp.content if b.type == "text")
        verdict = _extract_verdict(text)
        log.append({"file": filename, "step": step, "verdict": verdict})
        return verdict

    verdict = {"verdict": "unsure", "action": None,
               "why": f"hit step limit of {MAX_STEPS}"}
    log.append({"file": filename, "verdict": verdict, "note": "step_limit"})
    return verdict


if __name__ == "__main__":
    import sys
    print(json.dumps(review(sys.argv[1]), indent=2))
