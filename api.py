"""Minimal web endpoint so the agent has a URL you can open in the interview.

POST /review  {"filename": "privesc1-CreateNewPolicyVersion.json"}
POST /review  {"policy": { ...raw IAM policy JSON... }}
GET  /            simple health + usage
GET  /policies    list the available sample policy names
"""
import json
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

from iam_agent import agent, rules

app = FastAPI(title="IAM Review Agent")
POLICY_DIR = Path(os.environ.get("IAM_POLICY_DIR", "policies"))
# no key on the host -> fall back to the rules engine so the URL still works
USE_AGENT = bool(os.environ.get("ANTHROPIC_API_KEY"))


class Req(BaseModel):
    filename: str | None = None
    policy: dict | None = None


@app.get("/")
def root():
    return {"service": "IAM Review Agent",
            "engine": "agent" if USE_AGENT else "rules",
            "usage": "POST /review {filename} or {policy}"}


@app.get("/policies")
def policies():
    return sorted(p.name for p in POLICY_DIR.glob("*.json"))


@app.post("/review")
def review(req: Req):
    log: list = []
    if req.policy is not None:
        if USE_AGENT:
            with tempfile.TemporaryDirectory() as d:
                name = "adhoc.json"
                (Path(d) / name).write_text(json.dumps(req.policy))
                agent.POLICY_DIR = Path(d)
                verdict = agent.review(name, log=log)
        else:
            verdict = rules.assess(req.policy)
    elif req.filename:
        name = Path(req.filename).name
        if USE_AGENT:
            verdict = agent.review(name, log=log)
        else:
            verdict = rules.assess(json.loads((POLICY_DIR / name).read_text()))
    else:
        return {"error": "provide filename or policy"}
    return {"engine": "agent" if USE_AGENT else "rules",
            "verdict": verdict, "tool_calls": len([e for e in log if "tool" in e])}
