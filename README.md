# IAM Review Agent

An AI agent that reads AWS IAM policies and flags privilege-escalation paths.
Built as a working prototype for the DCG conversation: cloud security, access
rights, an agent that acts under guardrails and keeps an audit trail.

Everything here is read-only. No AWS account is touched. The agent reads
policy JSON from disk. Sample policies come from the public
[BishopFox/iam-vulnerable](https://github.com/BishopFox/iam-vulnerable) lab.

## What it does

- One read-only tool, `parse_policy`, that the agent calls to read a policy.
- An agent loop with a hard step limit, so it can never run away.
- A full audit log of every tool call and the final verdict (`runs/*.jsonl`).
- A benchmark against a hand-labeled set that prints three numbers:
  accuracy, false positives, false negatives.
- A `rules` baseline (plain pattern matching, no LLM) to show where simple
  rules break and why a reasoning agent is worth the cost.

## Run it

    python -m venv venv && source venv/bin/activate
    pip install -r requirements.txt

    # 1. build the dataset from the Terraform lab (once)
    git clone https://github.com/BishopFox/iam-vulnerable /tmp/iam-vulnerable
    python scripts/extract_policies.py /tmp/iam-vulnerable policies/

    # 2. baseline, no API key, instant
    python benchmark.py --engine rules

    # 3. the real agent (needs a key in .env)
    cp .env.example .env      # paste your ANTHROPIC_API_KEY
    export $(grep -v '^#' .env | xargs)
    python benchmark.py --engine agent

    # 4. the web endpoint
    uvicorn api:app --reload
    # POST /review {"filename": "privesc1-CreateNewPolicyVersion.json"}

## The three numbers (rules baseline)

    accuracy         78%   (32/41)
    false positives   3    clean policies flagged as risky
    false negatives   6    risky policies missed

The six misses are the interesting part: they are policies where the risk
comes from **two actions combined** (for example `ec2:RunInstances` plus
`iam:PassRole`) or from a service path like SageMaker or SSM, not a single
obvious keyword. Plain rules miss those. The reasoning agent is meant to
recover them, at the cost of one model call per policy. Run the `agent`
engine to see the trade.

## Files

    scripts/extract_policies.py   Terraform -> policy JSON + labels.csv
    iam_agent/agent.py            the agent: tool + loop + step limit + log
    iam_agent/rules.py            deterministic baseline (no LLM)
    benchmark.py                  scores either engine, prints the 3 numbers
    api.py                        FastAPI endpoint
    Dockerfile                    container for deploy

## Note on the labels

Labels follow the Bishop Fox lab. The `fp*` cases are deliberate
false-positive traps (a Deny that cancels an Allow, a Condition that makes an
action non-exploitable, a Resource scoped to AWS-managed policies). The
`fn*` cases are false-negative traps (risk only visible across statements).
`fp2-allow-all` and `fp2-deny-all` are only clean when attached **together**;
scored alone the allow half looks risky, which is itself a fair example of
what single-policy tools get wrong.
