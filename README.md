# Rune

policy language. compiles down to the two objects that already decide what an
agent can do and what it can ship.

part of [kinode](https://github.com/KinodeLLC/kinode-stack).

## install

```sh
pip install -e .
```

## example

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

## separation

it is a separate language on purpose. the people deciding what an agent is
allowed to change are usually not the people writing the code it changes, and a
policy sitting inside the codebase it governs can be edited by whatever is
editing that codebase. keeping it out means a policy change is its own thing
with its own review on it

## output

two objects, both of them already doing work elsewhere

```python
policy.install(broker)              # grants, what it can do
policy.to_authorization("INT-1")    # authorisation, what it can ship
policy.budget()                     # token and spend ceilings
```

so there is no way to run under a policy and ignore it at the same time

```
ok  a policy that denies money stops the workflow at the ledger:
    bureau.pull permitted, ledger.append refused at the boundary
```

and at promotion time

```
decision: BLOCK
  [block] CANON-E0905: lending.origination.originate was modified but is
          outside the authorised scope
```

## rules

denials beat grants. if you grant and deny the same thing you get a compile
error rather than a precedence puzzle, since a rule that can never fire is
nearly always a mistake somebody made in the policy

anything you did not grant is refused

a promotion condition you wrote is hard, it applies whatever the gate worked out
on its own. otherwise you end up putting a human in front of a question the
policy already answered

you get flagged for wildcard grants, a policy that grants nothing, no promotion
conditions, and no blast radius limit

## vocabulary

| kind | values |
| --- | --- |
| approval triggers | `new_capabilities`, `contracts_change`, `signature_change`, `behaviour_change`, `classification_increase`, `intent_change`, `always` |
| promotion conditions | `verified`, `not_diverged`, `tests_pass`, `in_scope`, `within_blast_radius` |
| limits | `blast_radius`, `calls`, `money`, `tokens`, `classification` |

## usage

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

policies also lower to a hashed canon constant, so changing a policy turns up in
the same graph queries and the same audit records as changing code does

## tests

```sh
python tests/smoke_rune.py
```

## licence

Apache-2.0, Kinode.
