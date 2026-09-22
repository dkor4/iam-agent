"""Deterministic reference checker for IAM privilege-escalation risk.

This is NOT the AI agent. It is a small rule set used for two things:
  1. a zero-cost smoke test of the whole pipeline (no API key needed);
  2. a sanity check that the hand labels are reasonable.

The AI agent lives in agent.py. Keeping a dumb baseline next to it is
also a good interview point: it shows where rules break and why an
LLM agent that can reason across statements is worth the cost.
"""
from typing import Any

# Actions that on their own (Resource "*") let a principal escalate.
DANGEROUS = {
    "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy", "iam:attachgrouppolicy", "iam:attachrolepolicy",
    "iam:putuserpolicy", "iam:putgrouppolicy", "iam:putrolepolicy",
    "iam:addusertogroup", "iam:createaccesskey", "iam:createloginprofile",
    "iam:updateloginprofile", "iam:updateassumerolepolicy",
    "iam:passrole", "sts:assumerole",
    "ec2instanceconnect:sendsshpublickey", "ssm:sendcommand", "ssm:startsession",
}
ADMIN = {"*", "iam:*", "sts:*"}


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    return [v] if isinstance(v, str) else list(v)


def _matches(action: str, patterns: set[str]) -> bool:
    a = action.lower()
    for p in patterns:
        p = p.lower()
        if a == p:
            return True
        # "*" is only admin as an exact action, never as a match-all prefix
        if p == "*":
            continue
        if p.endswith("*") and a.startswith(p[:-1]):
            return True
    return False


def assess(policy: dict) -> dict:
    """Return {'verdict': 'escalation'|'no escalation', 'action': str|None, 'why': str}."""
    allow_actions: list[str] = []
    has_deny_all = False
    has_condition = False
    has_not_action = False
    tight_resource = False

    for st in policy.get("Statement", []):
        effect = st.get("Effect", "Allow")
        actions = _as_list(st.get("Action"))
        resources = _as_list(st.get("Resource"))
        if st.get("Condition"):
            has_condition = True
        if effect == "Deny" and any(a in ADMIN for a in actions):
            has_deny_all = True
        if effect != "Allow":
            continue
        if st.get("NotAction"):
            has_not_action = True
        # a resource scoped away from account-level iam blunts iam privesc
        if resources and all(r != "*" and ":iam::" in r and "/policy/" in r
                             for r in resources):
            # non-exploitable when it targets AWS-managed policy arns
            if all("iam::aws:" in r for r in resources):
                tight_resource = True
        allow_actions.extend(actions)

    if has_deny_all:
        return {"verdict": "no escalation", "action": None,
                "why": "an explicit Deny on iam:* / * cancels the Allow"}

    for a in allow_actions:
        if a.lower() in ADMIN:  # only literal *, iam:*, sts:* count as blanket admin
            return {"verdict": "escalation", "action": a,
                    "why": "wildcard admin permission"}

    for a in allow_actions:
        if _matches(a, DANGEROUS):
            if tight_resource:
                return {"verdict": "no escalation", "action": a,
                        "why": f"{a} is scoped to AWS-managed policies, not exploitable"}
            note = " (guarded by a Condition, verify it)" if has_condition else ""
            return {"verdict": "escalation", "action": a,
                    "why": f"{a} allows privilege escalation{note}"}

    if has_not_action:
        return {"verdict": "escalation", "action": "NotAction Allow",
                "why": "NotAction with Allow grants everything except a few actions"}

    return {"verdict": "no escalation", "action": None, "why": "no escalation path found"}
