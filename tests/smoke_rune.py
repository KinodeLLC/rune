"""Rune: policies that become capability grants and promotion authorisations."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "canon" / "src"))
sys.path.insert(0, str(ROOT / "rune" / "src"))

from canon import Hasher  # noqa: E402
from canon import values as V  # noqa: E402
from canon.checker import check  # noqa: E402
from canon.interp import Budget, Fault, Interpreter  # noqa: E402
from canon.ledger import AuditLog, CapabilityBroker, Ledger  # noqa: E402
from canon.parser import parse  # noqa: E402
from canon.shadow import structural_diff  # noqa: E402
from rune import evaluate, parse_rune  # noqa: E402

POLICY = r'''
module governance

policy agent_maintenance {
  intent "What a maintenance agent may change without a human in the loop."
  actor "agent:maintenance"

  grant model.infer, model.judge
  grant store.read
  grant store.write limit 200 calls
  deny mail.send
  deny payments.*

  scope billing.*, orders.*

  limit blast_radius 12
  limit classification internal
  limit tokens 50000

  require_approval when new_capabilities, contracts_change

  promote when verified and not diverged

  audit all
}
'''

CONFLICT = POLICY.replace("  deny mail.send\n", "  deny store.read\n")

BROAD = POLICY.replace("  grant store.read\n", "  grant store.*\n")

NO_PROMOTE = POLICY.replace(
    "  promote when verified and not diverged\n\n", "\n")

BAD_LIMIT = POLICY.replace("  limit blast_radius 12\n",
                           "  limit blast_radiuss 12\n")

PROGRAM = r'''
module billing

effect store {
  write(key: Text, value: Text) -> Unit
  read(key: Text) -> Option<Text>
}

effect mail {
  send(to: Text, subject: Text, body: Text) -> Unit
}

fn total(a: Int, b: Int) -> Int
  intent "Add two amounts."
  requires a >= 0
  requires b >= 0
  ensures result >= a
{
  a + b
}

fn save(key: Text, value: Text) -> Unit
  intent "Persist a value."
  uses store.write
{
  store.write(key, value)
}
'''

# An edit that reaches a denied capability.
REACHES_DENIED = PROGRAM.replace(
    "fn save(key: Text, value: Text) -> Unit\n"
    "  intent \"Persist a value.\"\n  uses store.write\n{\n"
    "  store.write(key, value)\n}",
    "fn save(key: Text, value: Text) -> Unit\n"
    "  intent \"Persist a value.\"\n  uses store.write, mail.send\n{\n"
    "  do store.write(key, value)\n"
    "  mail.send(\"ops@example.com\", \"saved\", key)\n}")

# A behaviour-preserving edit inside scope.
SAFE_EDIT = PROGRAM.replace("  a + b\n", "  let x = a\n  x + b\n")


def build_policy(src=POLICY):
    mod, policies, bag = parse_rune(src, "governance.rune")
    return mod, policies, bag


def build_program(src, label="billing"):
    mod, bag = parse(src, f"{label}.canon")
    if bag.has_errors:
        return None, bag, None
    cr = check([mod], bag)
    return cr, cr.bag, Hasher().add_modules([mod])


def main():
    failures = []

    def case(name, fn):
        try:
            print(f"  ok    {name}: {fn()}")
        except AssertionError as ae:
            failures.append(name)
            print(f"  FAIL  {name}: {ae}")

    mod, policies, bag = build_policy()
    errs = [d for d in bag if d.severity.value == "error"]
    if errs:
        for d in errs:
            print(d.render(POLICY))
        return 1
    policy = policies[0]

    print("parsing")

    def t_parsed():
        assert policy.name == "agent_maintenance"
        assert policy.actor == "agent:maintenance"
        assert "store.write" in policy.granted_operations()
        assert "mail.send" in policy.denied
        assert "payments.*" in policy.denied
        assert policy.limits["blast_radius"] == 12
        assert policy.max_classification == "internal"
        return (f"{len(policy.granted_operations())} grants, "
                f"{len(policy.denied)} denials, limits {policy.limits}")
    case("a policy parses into grants, denials and limits", t_parsed)

    def t_permits():
        assert policy.permits("store.write")
        assert policy.permits("model.infer")
        assert not policy.permits("mail.send"), "a denied operation was permitted"
        assert not policy.permits("payments.charge"), "a denied wildcard leaked"
        assert not policy.permits("ledger.append"), "an ungranted op was permitted"
        return "grants allow, denials and omissions refuse"
    case("denials beat grants and omission is refusal", t_permits)

    def t_lowered():
        cr = check([mod], bag)
        assert not cr.bag.has_errors, cr.bag.render(POLICY)
        ci = cr.env.consts["governance.policy_agent_maintenance"]
        it = Interpreter(cr, Ledger(), Budget())
        spec = it.eval(ci.decl.value, it.globals)
        assert spec.get("policy_name") == "agent_maintenance"
        assert "mail.send" in spec.get("denied")
        return f"lowered to a hashed PolicySpec constant"
    case("a policy lowers to a diffable Canon constant", t_lowered)

    print("\nenforcement at runtime")

    def t_broker():
        audit = AuditLog(actor="agent:maintenance")
        broker = CapabilityBroker(audit=audit)
        policy.install(broker)
        led = Ledger(broker=broker, audit=audit, actor="agent:maintenance")
        led.handle("store.write", lambda k, v: V.UNIT)
        led.handle("mail.send", lambda a, b, c: V.UNIT)

        cr, b, _ = build_program(PROGRAM)
        it = Interpreter(cr, led, Budget())
        it.call("save", ["k", "v"])
        return f"granted operation performed, {len(led.journal)} journal entry"
    case("a granted operation is permitted by the broker", t_broker)

    def t_broker_denies():
        audit = AuditLog(actor="agent:maintenance")
        broker = CapabilityBroker(audit=audit)
        policy.install(broker)
        led = Ledger(broker=broker, audit=audit, actor="agent:maintenance")
        led.handle("store.write", lambda k, v: V.UNIT)
        led.handle("mail.send", lambda a, b, c: V.UNIT)

        cr, b, _ = build_program(REACHES_DENIED)
        it = Interpreter(cr, led, Budget())
        try:
            it.call("save", ["k", "v"])
        except Fault as f:
            assert f.code == "CANON-E0403", f.code
            assert f.facts.get("operation") == "mail.send", f.facts
            return f"{f.code}: {f.facts['operation']} refused at the boundary"
        raise AssertionError("a denied operation was performed")
    case("a denied operation is refused at runtime", t_broker_denies)

    def t_call_ceiling():
        audit = AuditLog(actor="agent:maintenance")
        broker = CapabilityBroker(audit=audit)
        policy.install(broker)
        g = next(x for x in broker.grants if "store.write" in x.operations)
        assert g.max_calls == 200, g.max_calls
        return f"store.write grant carries the declared ceiling of {g.max_calls}"
    case("a per-grant call ceiling reaches the broker", t_call_ceiling)

    def t_budget():
        b = policy.budget()
        assert b.tokens == 50000, b.tokens
        return f"token budget {b.tokens}"
    case("policy limits become a runtime budget", t_budget)

    print("\nenforcement at promotion")

    def t_authorization():
        auth = policy.to_authorization("INT-200")
        assert auth.actor == "agent:maintenance"
        assert auth.max_blast_radius == 12
        assert auth.allowed_definitions == ["billing.*", "orders.*"]
        assert not auth.allow_new_capabilities, \
            "new_capabilities should require approval"
        assert not auth.allow_contract_changes
        assert auth.require_verification
        return (f"scope={auth.allowed_definitions}, "
                f"blast radius<={auth.max_blast_radius}, "
                f"verification required")
    case("a policy becomes a promotion authorisation", t_authorization)

    def t_promote_safe():
        old, _, oh = build_program(PROGRAM)
        new, _, nh = build_program(SAFE_EDIT)
        diff = structural_diff(old, new, oh, nh)
        dec = evaluate(policy, diff,
                       verification={"ok": True, "functions": []},
                       differential_report={"identical": True,
                                            "disagreements": []})
        assert dec.decision == "promote", dec.render()
        return "in-scope, verified, non-diverging edit promoted"
    case("a safe in-scope edit is promoted under the policy", t_promote_safe)

    def t_block_new_capability():
        old, _, oh = build_program(PROGRAM)
        new, _, nh = build_program(REACHES_DENIED)
        diff = structural_diff(old, new, oh, nh)
        assert "mail.send" in diff.capabilities_added, diff.capabilities_added
        dec = evaluate(policy, diff,
                       verification={"ok": True, "functions": []},
                       differential_report={"identical": True,
                                            "disagreements": []})
        assert dec.decision == "block", dec.render()
        f = next(x for x in dec.findings if "capabilit" in x.message)
        return f"{f.message}: {f.detail.get('capabilities')}"
    case("an edit reaching a capability the policy never granted is blocked",
         t_block_new_capability)

    def t_block_unverified():
        old, _, oh = build_program(PROGRAM)
        new, _, nh = build_program(SAFE_EDIT)
        diff = structural_diff(old, new, oh, nh)
        dec = evaluate(policy, diff, verification=None,
                       differential_report={"identical": True,
                                            "disagreements": []})
        assert dec.decision == "block", dec.render()
        return "promote-when-verified refused an unverified change"
    case("a promotion condition the policy states is enforced",
         t_block_unverified)

    def t_block_diverged():
        old, _, oh = build_program(PROGRAM)
        new, _, nh = build_program(SAFE_EDIT)
        diff = structural_diff(old, new, oh, nh)
        dec = evaluate(policy, diff,
                       verification={"ok": True, "functions": []},
                       differential_report={
                           "identical": False,
                           "disagreements": [{"function": "billing.total"}]})
        assert dec.decision == "block", dec.render()
        f = next(x for x in dec.findings if "not_diverged" in str(x.detail))
        return f.message
    case("promote-when-not-diverged refuses a diverging change",
         t_block_diverged)

    print("\npolicy validation")

    def t_conflict():
        _, _, b = build_policy(CONFLICT)
        assert b.has_errors, "a grant/deny conflict compiled"
        d = next(x for x in b if x.code == "CANON-E0903")
        assert d.facts["operation"] == "store.read", d.facts
        return d.message
    case("a policy that both grants and denies an operation is rejected",
         t_conflict)

    def t_broad():
        _, _, b = build_policy(BROAD)
        w = next((x for x in b if "store.*" in x.message), None)
        assert w is not None, [x.message for x in b]
        return w.message
    case("a wildcard grant is reported", t_broad)

    def t_no_promote():
        _, _, b = build_policy(NO_PROMOTE)
        w = next((x for x in b if "no promotion conditions" in x.message), None)
        assert w is not None, [x.message for x in b]
        return w.message
    case("a policy with no promotion condition is reported", t_no_promote)

    def t_bad_limit():
        _, _, b = build_policy(BAD_LIMIT)
        assert b.has_errors, "an unknown limit compiled"
        d = next(x for x in b if "unknown limit" in x.message)
        fix = d.repairs[0].text if d.repairs else ""
        return f"{d.message} (suggested {fix!r})"
    case("an unknown limit is rejected with a suggestion", t_bad_limit)

    print("\nRESULT:", "pass" if not failures else f"FAIL ({failures})")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
