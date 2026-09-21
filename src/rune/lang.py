"""
Rune: the governance policy language.

Rune is deliberately a separate language from the ones engineers write in. The
people who decide what an autonomous agent may change are usually not the
people writing the code it changes, and a policy that lives inside the codebase
it governs can be edited by whatever is editing that codebase. Keeping it
separate means a policy change is a distinct artifact with its own review path
and its own audit trail.

A policy compiles to two things that are already load-bearing elsewhere:

  * capability grants for the broker, which decide what an agent may do at
    runtime, and
  * an authorisation for the promotion gate, which decides what an agent may
    ship.

So a policy is not advice. It is the object both enforcement points consult,
and there is no way to run under a policy while ignoring it.

Denials beat grants, always, and a policy that both grants and denies the same
operation is a compile error rather than a precedence puzzle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Optional

from canon import ast as A
from canon import types as TY
from canon.diagnostics import Bag, Repair, Span
from canon.lexer import Lexer, T
from canon.parser import Parser


LANGUAGE_VERSION = "0.1"

SUPPORT_TYPES = """
record PolicyLimit {
  limit_name: Text
  value: Int
}

record PolicySpec {
  policy_name: Text
  actor: Text
  granted: List<Text>
  denied: List<Text>
  scope: List<Text>
  limits: List<PolicyLimit>
  approval_triggers: List<Text>
  promote_conditions: List<Text>
}
"""

# Conditions that force a human decision rather than an automatic promotion.
APPROVAL_TRIGGERS = {
    "new_capabilities": "the change reaches a capability it did not before",
    "contracts_change": "a contract was weakened, strengthened or removed",
    "signature_change": "a function's type changed",
    "behaviour_change": "observable behaviour differs on generated inputs",
    "classification_increase": "the change reaches more sensitive data",
    "intent_change": "a definition's stated purpose changed",
    "always": "every change under this policy needs approval",
}

# Conditions that must hold before a change may be promoted at all.
PROMOTE_CONDITIONS = {
    "verified": "verification passed",
    "not_diverged": "shadow replay found no divergence",
    "tests_pass": "declared tests pass",
    "in_scope": "every edited definition is inside the policy's scope",
    "within_blast_radius": "the blast radius is within the declared limit",
}

LIMIT_NAMES = {
    "blast_radius": "how many definitions a change may reach",
    "calls": "how many times a granted operation may be performed",
    "money": "how much a run may spend",
    "tokens": "how many model tokens a run may use",
    "classification": "the most sensitive data the actor may reach",
}


@dataclass
class GrantDecl:
    operations: list = field(default_factory=list)
    max_calls: Optional[int] = None
    span: Span = field(default_factory=Span.unknown)


@dataclass
class PolicyDecl:
    name: str = ""
    actor: str = "*"
    intent: str = ""
    doc: str = ""
    grants: list = field(default_factory=list)
    denied: list = field(default_factory=list)
    scope: list = field(default_factory=list)
    limits: dict = field(default_factory=dict)
    max_classification: str = "internal"
    approval_triggers: list = field(default_factory=list)
    promote_conditions: list = field(default_factory=list)
    sunset_millis: int = 0
    audit_all: bool = True
    span: Span = field(default_factory=Span.unknown)

    # ------------------------------------------------------------------

    def granted_operations(self) -> list:
        out = []
        for g in self.grants:
            out.extend(g.operations)
        return sorted(set(out))

    def permits(self, key: str) -> bool:
        """Whether an operation survives the deny list and reaches a grant."""
        for pattern in self.denied:
            if _matches(pattern, key):
                return False
        return any(_matches(p, key)
                   for g in self.grants for p in g.operations)

    def to_authorization(self, intent_id: str = ""):
        """The object the promotion gate consults."""
        from canon.shadow import Authorization
        return Authorization(
            actor=self.actor,
            intent_id=intent_id or self.name,
            allowed_definitions=list(self.scope),
            allowed_capabilities=self.granted_operations(),
            max_blast_radius=self.limits.get("blast_radius", 10),
            allow_new_capabilities="new_capabilities"
            not in self.approval_triggers,
            allow_contract_changes="contracts_change"
            not in self.approval_triggers,
            allow_signature_changes="signature_change"
            not in self.approval_triggers,
            allow_behaviour_change="behaviour_change"
            not in self.approval_triggers,
            require_verification="verified" in self.promote_conditions,
            max_classification=self.max_classification,
        )

    def install(self, broker, actor: Optional[str] = None) -> list:
        """
        Register this policy's grants with a capability broker.

        Denied operations are simply never granted, so a denial cannot be
        overridden by adding another grant later: the broker has nothing to
        match against.
        """
        who = actor or self.actor
        installed = []
        for g in self.grants:
            ops = [o for o in g.operations
                   if not any(_matches(d, o) for d in self.denied)]
            if not ops:
                continue
            installed.append(broker.grant(
                who, ops,
                reason=f"policy {self.name}",
                max_calls=g.max_calls or self.limits.get("calls"),
                expires_logical=self.sunset_millis or None,
                max_classification=self.max_classification))
        return installed

    def budget(self):
        """A runtime budget expressing this policy's spend and token limits."""
        from canon.interp import Budget
        b = Budget()
        if "tokens" in self.limits:
            b.tokens = self.limits["tokens"]
        if "money" in self.limits:
            b.money = Decimal(self.limits["money"])
        return b

    def to_json(self) -> dict:
        return {"policy": self.name, "actor": self.actor,
                "intent": self.intent,
                "granted": self.granted_operations(),
                "denied": sorted(self.denied),
                "scope": sorted(self.scope),
                "limits": dict(self.limits),
                "max_classification": self.max_classification,
                "approval_triggers": sorted(self.approval_triggers),
                "promote_conditions": sorted(self.promote_conditions),
                "sunset_millis": self.sunset_millis,
                "audit_all": self.audit_all}


def _matches(pattern: str, key: str) -> bool:
    if pattern == key or pattern == "*":
        return True
    if pattern.endswith(".*"):
        return key.split(".", 1)[0] == pattern[:-2]
    return False


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

class RuneParser(Parser):
    def __init__(self, tokens, source="", filename="<memory>", bag=None):
        super().__init__(tokens, source, filename, bag, language="rune")
        self.policies: list = []

    def parse_decl(self):
        doc = self.skip_docs()
        if self.at_ctx("policy") and self.at(1).kind == T.NAME:
            self.policies.append(self.parse_policy(doc))
            return None
        for fn, kw in ((self.parse_record, "record"), (self.parse_enum, "enum"),
                       (self.parse_alias, "alias"), (self.parse_const, "const")):
            if self.cur.is_kw(kw):
                return fn(doc)
        return None

    def parse_policy(self, doc: str = "") -> PolicyDecl:
        start = self.next()           # policy
        p = PolicyDecl(doc=doc)
        p.name = self.expect_name("a policy name")
        self.expect_punct("{", "to open the policy body")

        while not self.cur.is_punct("}") and self.cur.kind != T.EOF:
            self.skip_docs()
            if self.cur.is_kw("intent"):
                self.next()
                p.intent = self.parse_text_literal("an intent description")
            elif self.at_ctx("actor"):
                self.next()
                p.actor = self.parse_text_literal("an actor pattern")
            elif self.at_ctx("grant", "allow"):
                self.next()
                p.grants.append(self.parse_grant())
            elif self.at_ctx("deny"):
                self.next()
                p.denied.extend(self.parse_operations())
            elif self.at_ctx("scope"):
                self.next()
                p.scope.extend(self.parse_scope())
            elif self.at_ctx("limit"):
                self.next()
                self.parse_limit(p)
            elif self.at_ctx("require_approval"):
                self.next()
                self.eat_ctx("when")
                p.approval_triggers.extend(
                    self.parse_words(APPROVAL_TRIGGERS, "approval trigger"))
            elif self.at_ctx("promote"):
                self.next()
                self.eat_ctx("when")
                p.promote_conditions.extend(
                    self.parse_conditions())
            elif self.at_ctx("sunset"):
                self.next()
                p.sunset_millis = self._int("a sunset timestamp in "
                                            "milliseconds")
            elif self.at_ctx("audit"):
                self.next()
                if self.eat_ctx("all"):
                    p.audit_all = True
                elif self.eat_ctx("none"):
                    p.audit_all = False
                else:
                    self.err("CANON-E0101", "expected `all` or `none`")
            else:
                self.err("CANON-E0102", "unknown policy setting",
                         facts={"found": self.cur.value or self.cur.kind,
                                "known": ["actor", "grant", "deny", "scope",
                                          "limit", "require_approval",
                                          "promote", "sunset", "audit",
                                          "intent"]})
                self.next()
        self.expect_punct("}", "to close the policy body")

        self.validate(p, start)
        p.span = self.span_from(start)
        return p

    # ------------------------------------------------------------------

    def parse_grant(self) -> GrantDecl:
        start = self.cur
        g = GrantDecl(operations=self.parse_operations())
        if self.at_ctx("limit"):
            self.next()
            g.max_calls = self._int("a call ceiling")
            self.eat_ctx("calls")
        g.span = self.span_from(start)
        return g

    def parse_operations(self) -> list:
        ops = []
        while True:
            if self.cur.is_op("*"):
                self.next()
                ops.append("*")
            elif self.cur.kind == T.NAME:
                name = self.next().value
                if self.eat_punct("."):
                    if self.cur.is_op("*"):
                        self.next()
                        ops.append(f"{name}.*")
                    else:
                        ops.append(f"{name}.{self.expect_name('an operation')}")
                else:
                    ops.append(f"{name}.*")
            else:
                self.err("CANON-E0101", "expected an effect operation")
                break
            if not self.eat_punct(","):
                break
        return ops

    def parse_scope(self) -> list:
        out = []
        while True:
            parts = []
            if self.cur.kind not in (T.NAME, T.UPPER):
                self.err("CANON-E0101", "expected a definition pattern")
                break
            parts.append(self.next().value)
            while self.eat_punct("."):
                if self.cur.is_op("*"):
                    self.next()
                    parts.append("*")
                    break
                if self.cur.kind not in (T.NAME, T.UPPER):
                    break
                parts.append(self.next().value)
            out.append(".".join(parts))
            if not self.eat_punct(","):
                break
        return out

    def parse_limit(self, p: PolicyDecl):
        if self.cur.kind != T.NAME:
            self.err("CANON-E0101", "expected a limit name",
                     facts={"known": sorted(LIMIT_NAMES)})
            return
        name = self.next().value
        if name == "classification":
            cls = self.expect_name("a data classification")
            if cls not in TY.CLASS_RANK:
                self.err("CANON-E0201",
                         f"unknown data classification {cls!r}",
                         facts={"known": TY.CLASSIFICATIONS})
            else:
                p.max_classification = cls
            return
        if name not in LIMIT_NAMES:
            self.err("CANON-E0201", f"unknown limit {name!r}",
                     facts={"limit": name, "known": sorted(LIMIT_NAMES)},
                     repairs=self._near_repairs(name, LIMIT_NAMES,
                                                self.cur.span))
            self.next()
            return
        p.limits[name] = self._int(f"a value for the {name} limit")
        self.eat_ctx("calls", "definitions")

    def parse_words(self, known: dict, what: str) -> list:
        out = []
        while True:
            if self.cur.kind != T.NAME:
                self.err("CANON-E0101", f"expected {what}",
                         facts={"known": sorted(known)})
                break
            word = self.next().value
            if word not in known:
                self.err("CANON-E0201", f"unknown {what} {word!r}",
                         facts={what.replace(" ", "_"): word,
                                "known": sorted(known)},
                         repairs=self._near_repairs(word, known, self.cur.span))
            else:
                out.append(word)
            if not self.eat_punct(",") and not self.eat_ctx("or"):
                break
        return out

    def parse_conditions(self) -> list:
        """Promote conditions, written `verified and not diverged`."""
        out = []
        while True:
            negated = bool(self.eat_kw("not"))
            if self.cur.kind != T.NAME:
                self.err("CANON-E0101", "expected a promotion condition",
                         facts={"known": sorted(PROMOTE_CONDITIONS)})
                break
            word = self.next().value
            if negated and word == "diverged":
                word = "not_diverged"
            elif negated:
                word = f"not_{word}"
            if word not in PROMOTE_CONDITIONS:
                self.err("CANON-E0201",
                         f"unknown promotion condition {word!r}",
                         facts={"condition": word,
                                "known": sorted(PROMOTE_CONDITIONS)},
                         repairs=self._near_repairs(word, PROMOTE_CONDITIONS,
                                                    self.cur.span))
            else:
                out.append(word)
            if not (self.eat_kw("and") or self.eat_punct(",")):
                break
        return out

    def _int(self, what) -> int:
        if self.cur.kind == T.INT:
            return int(self.next().payload)
        self.err("CANON-E0101", f"expected {what}")
        return 0

    def _near_repairs(self, name, candidates, span) -> list:
        from canon.checker import _closest
        return [Repair("replace-span", f"did you mean {n!r}", n, span, 0.55)
                for n in _closest(name, candidates)]

    # ------------------------------------------------------------------

    def validate(self, p: PolicyDecl, start):
        granted = p.granted_operations()

        conflicts = sorted({op for op in granted
                            for d in p.denied if _matches(d, op)})
        for op in conflicts:
            self.err(
                "CANON-E0903",
                f"policy {p.name!r} both grants and denies {op!r}",
                start,
                facts={"policy": p.name, "operation": op,
                       "granted": granted, "denied": sorted(p.denied)},
                repairs=[Repair("manual",
                                f"remove {op!r} from either the grants or the "
                                f"denials")],
                notes=["Denials win, so this policy is not ambiguous at "
                       "runtime -- but a rule that can never take effect is "
                       "almost always a mistake in the policy rather than an "
                       "intentional no-op."])

        for op in granted:
            if op == "*":
                self.warn_broad(p, op, start,
                                "this grants every operation that exists")
            elif op.endswith(".*"):
                self.warn_broad(p, op, start,
                                f"this grants every operation of the "
                                f"{op[:-2]!r} effect")

        if not granted:
            self.bag.warn(
                "CANON-W0006",
                f"policy {p.name!r} grants nothing", start.span,
                facts={"policy": p.name},
                notes=["An actor under this policy can perform no effects at "
                       "all, which is a valid but unusual configuration."])

        if not p.promote_conditions:
            self.bag.warn(
                "CANON-W0004",
                f"policy {p.name!r} states no promotion conditions",
                start.span,
                facts={"policy": p.name,
                       "available": sorted(PROMOTE_CONDITIONS)},
                repairs=[Repair("manual",
                                "require verification before promotion",
                                "promote when verified and not diverged",
                                start.span, 0.6)],
                notes=["Without a promotion condition a change under this "
                       "policy can ship without being verified."])

        if "blast_radius" not in p.limits:
            self.bag.warn(
                "CANON-W0006",
                f"policy {p.name!r} sets no blast radius limit", start.span,
                facts={"policy": p.name},
                repairs=[Repair("manual", "bound how far a change may reach",
                                "limit blast_radius 15", start.span, 0.5)])

    def warn_broad(self, p, op, start, detail):
        self.bag.warn(
            "CANON-W0006",
            f"policy {p.name!r} grants {op!r}: {detail}", start.span,
            facts={"policy": p.name, "operation": op},
            repairs=[Repair("manual",
                            "name the specific operations the actor needs")],
            notes=["A wildcard grant makes the actor's capability footprint "
                   "an over-approximation, which widens every blast radius "
                   "computed against it."])


# --------------------------------------------------------------------------
# Lowering
# --------------------------------------------------------------------------

def _lit(v, k="text"):
    return A.Lit(value=v, lit_kind=k)


def _rec(tn, fields):
    return A.RecordLit(type_name=tn, fields=list(fields))


def _texts(items) -> A.ListLit:
    return A.ListLit(items=[_lit(str(i)) for i in items])


class Lowering:
    """
    Emits a Canon constant describing each policy.

    The constant is not what enforces anything -- the broker and the gate do
    that from the policy object. It exists so a policy is a hashed, diffable
    definition like everything else, and so a change to it shows up in the
    same graph queries and audit records as a change to code.
    """

    def __init__(self, bag: Bag):
        self.bag = bag

    def lower_module(self, mod: A.Module, policies: list) -> A.Module:
        if policies:
            mod.decls.extend(_support_decls())
        for p in policies:
            mod.decls.append(self.lower_policy(p))
        mod.language = "rune"
        return mod

    def lower_policy(self, p: PolicyDecl) -> A.ConstDecl:
        limits = A.ListLit(items=[
            _rec("PolicyLimit", [("limit_name", _lit(k)),
                                 ("value", _lit(v, "int"))])
            for k, v in sorted(p.limits.items())])
        return A.ConstDecl(
            name=f"policy_{p.name}",
            doc=p.doc,
            intent=p.intent or f"The {p.name} governance policy.",
            ty=A.TName(name="PolicySpec"),
            value=_rec("PolicySpec", [
                ("policy_name", _lit(p.name)),
                ("actor", _lit(p.actor)),
                ("granted", _texts(p.granted_operations())),
                ("denied", _texts(sorted(p.denied))),
                ("scope", _texts(sorted(p.scope))),
                ("limits", limits),
                ("approval_triggers", _texts(sorted(p.approval_triggers))),
                ("promote_conditions", _texts(sorted(p.promote_conditions))),
            ]),
            span=p.span)


def _support_decls() -> list:
    src = "module _rune_support\n" + SUPPORT_TYPES
    lx = Lexer(src, "<rune-support>")
    toks = lx.run()
    pr = Parser(toks, src, "<rune-support>", lx.bag)
    mod = pr.parse_module()
    if pr.bag.has_errors:
        raise RuntimeError("rune support types failed to parse:\n"
                           + pr.bag.render(src))
    return mod.decls


# --------------------------------------------------------------------------
# Enforcement
# --------------------------------------------------------------------------

def evaluate(policy: PolicyDecl, diff, verification=None,
             differential_report=None, shadow_reports=None, audit=None,
             intent_id: str = ""):
    """
    Decide a promotion under a policy.

    This is the join between Rune and the gate: the policy becomes an
    authorisation, and the gate does the rest. Keeping the decision logic in
    one place means a policy cannot express something the gate does not
    actually check.
    """
    from canon.shadow import evaluate_promotion
    auth = policy.to_authorization(intent_id)
    decision = evaluate_promotion(diff, auth, verification,
                                  differential_report, shadow_reports, audit)

    unmet = []
    if "not_diverged" in policy.promote_conditions:
        diverged = (differential_report is not None
                    and not differential_report.get("identical", True))
        diverged = diverged or any(
            not s.get("clean", True) for s in (shadow_reports or []))
        if diverged:
            unmet.append("not_diverged")
    if "verified" in policy.promote_conditions:
        if verification is None or not verification.get("ok", False):
            unmet.append("verified")

    # A stated promotion condition is a hard requirement, not a tiebreak. It
    # applies whatever the gate concluded on its own -- escalating a change
    # that fails a condition the policy says must hold would put a human in
    # front of a decision the policy already made.
    if unmet:
        from canon.shadow import Finding
        decision.findings.append(Finding(
            "CANON-E0903", "block",
            f"policy {policy.name!r} requires "
            + " and ".join(sorted(unmet)),
            {"policy": policy.name, "unmet": sorted(unmet),
             "gate_decision_before_policy": decision.decision}))
        decision.decision = "block"

    return decision


# --------------------------------------------------------------------------

def parse_rune(source: str, filename: str = "<memory>"):
    """Parse and lower Rune source. Returns (Canon Module, policies, Bag)."""
    lx = Lexer(source, filename)
    toks = lx.run()
    p = RuneParser(toks, source, filename, lx.bag)
    mod = p.parse_module()
    mod = Lowering(p.bag).lower_module(mod, p.policies)
    return mod, p.policies, p.bag
