# Rune

The governance policy language. A policy compiles to the objects that already
decide what an agent may do and what it may ship.

Part of the [Kinode](../kinode-stack) stack.

## Install

```sh
pip install -e .
```

## A policy

```rune
module lending.governance

policy underwriting_maintenance {
  intent "A maintenance agent may tune the decision, but not touch money or customers."
  actor "agent:underwriting"

  grant bureau.pull limit 500 calls
  grant model.infer, model.judge
  grant workflow.checkpoint, workflow.compensated

  deny ledger.append, ledger.reverse
  deny notify.email

  scope lending.underwriting.*, lending.affordability_ratio

  limit blast_radius 12
  limit classification pseudonymous
  limit tokens 200000
  limit money 25

  require_approval when new_capabilities, contracts_change, signature_change
  promote when verified and not diverged

  audit all
}
```

## Why it is a separate language

The people who decide what an autonomous agent may change are usually not the
people writing the code it changes, and a policy that lives inside the codebase
it governs can be edited by whatever is editing that codebase. Keeping it
separate makes a policy change a distinct artifact with its own review path and
its own audit trail.

## What a policy becomes

Two objects, both already load-bearing elsewhere:

```python
policy.install(broker)              # capability grants — what it may do
policy.to_authorization("INT-1")    # authorisation — what it may ship
policy.budget()                     # token and spend ceilings
```

It is therefore enforced by construction. There is no way to run under a policy
while ignoring it:

```
ok  a policy that denies money stops the workflow at the ledger:
    bureau.pull permitted, ledger.append refused at the boundary
```

And at promotion time:

```
decision: BLOCK
  [block] CANON-E0905: lending.origination.originate was modified but is
          outside the authorised scope
```

## Rules

**Denials beat grants**, always. A policy that both grants and denies the same
operation is a compile error rather than a precedence puzzle — a rule that can
never take effect is almost always a mistake in the policy.

**Omission is refusal.** Nothing is permitted that was not granted.

**A stated promotion condition is a hard requirement**, applied whatever the
gate concluded on its own. Escalating a change that fails a condition the
policy says must hold would put a human in front of a decision the policy
already made.

Reported: wildcard grants, a policy that grants nothing, a policy with no
promotion conditions, and a policy with no blast-radius limit.

## Vocabulary

**Approval triggers** — `new_capabilities`, `contracts_change`,
`signature_change`, `behaviour_change`, `classification_increase`,
`intent_change`, `always`.

**Promotion conditions** — `verified`, `not_diverged`, `tests_pass`,
`in_scope`, `within_blast_radius`.

**Limits** — `blast_radius`, `calls`, `money`, `tokens`, `classification`.

## Usage

```python
from rune import parse_rune, evaluate
from canon.shadow import structural_diff

mod, policies, bag = parse_rune(text, "governance.rune")
policy = policies[0]

policy.install(broker, actor="agent:underwriting")

diff = structural_diff(old_cr, new_cr, old_hashes, new_hashes)
decision = evaluate(policy, diff, verification=report, differential_report=diff_report)
print(decision.render())
```

Policies also lower to a hashed Canon constant, so a policy change appears in
the same graph queries and audit records as a change to code.

## Tests

```sh
python tests/smoke_rune.py
```

## Licence

Apache-2.0. Copyright Kinode.
