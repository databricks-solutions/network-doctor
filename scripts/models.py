"""Data models for the Network Connectivity Doctor."""

import re as _re

from dataclasses import dataclass, field
from enum import Enum

# The single source of truth for the release the customer is running. It is
# rendered in the dashboard footer, so a support question can quote a version
# instead of "the one we installed last month". This module imports nothing from
# the rest of the engine, so anything may read it without a circular import.
#
# The footer used to carry a hardcoded "v0.3" that nothing updated — a version
# string nobody maintains is worse than none, because it is believed.
__version__ = "1.1.0"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class CheckResult:
    check_name: str
    target: str
    status: Status
    message: str
    recommendation: str = ""
    raw_output: str = ""
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    def is_failure(self):
        return self.status in (Status.FAIL, Status.ERROR)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Diagnosis:
    pattern_id: str
    title: str
    severity: Severity
    confidence: str
    root_cause: str
    evidence: list = field(default_factory=list)
    prescription: list = field(default_factory=list)
    follow_up_questions: list = field(default_factory=list)
    fix_order: int = 99
    # When True, this diagnosis depends on customer topology the skill cannot
    # verify from probes/ARM alone (e.g. whether a peering is the path to the
    # target/DNS, or whether the VNet uses custom vs Azure-provided DNS). It is a
    # HYPOTHESIS pending customer confirmation — the agent MUST ask the
    # follow_up_questions and get an answer BEFORE asserting it as a root cause.
    needs_confirmation: bool = False
    # Which network LAYER this diagnosis lives at, so the report/chat can label it
    # and never mix planes (serverless problems are NCC-layer; classic/cluster-start
    # are VNet-layer). One of: "classic-vnet" | "ncc-serverless" | "storage" | "".
    # The correlation engine fills this from the pattern_id when not set explicitly.
    layer: str = ""


@dataclass
class DiagnosticReport:
    target: str
    host: str
    port: int
    checks: dict = field(default_factory=dict)
    diagnoses: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    overall_status: Status = Status.PASS
    summary: str = ""


@dataclass
class Topology:
    """A discovered customer Azure network topology graph (classic VNet plane).

    Built once (phase 0, when ARM/SP is available) by topology.build_topology and
    queried by topology.trace. Holds only JSON/string-safe data so it can ride in a
    session checkpoint and a CheckResult.metadata. NOT one of the gate-introspected
    dataclasses (gen_docs only field-checks CheckResult/Diagnosis/DiagnosticReport).

    - environment: {plane: "classic"|"serverless"|"unknown", vnet_injected: bool,
                    hub_spoke: bool, ...}. For serverless the VNet/firewall graph is
                    intentionally NOT built — egress is account-level NCC, not a
                    customer VNet/firewall concern.
    - nodes: {arm_id -> {id, kind, name, props}} (kind in vnet/subnet/route_table/
                    nsg/peering/firewall/workspace).
    - edges: list of (src_id, edge_kind, dst_id).
    - roots: {workspace_id, data_plane_vnet_id, subnet_ids}.
    - discovery: {scopes_read: [sub_id], errors: [str], partial: bool} — records what
                    could NOT be read so trace() returns honest WARN/SETUP, never a
                    false PASS.
    """
    environment: dict = field(default_factory=dict)
    nodes: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    roots: dict = field(default_factory=dict)
    discovery: dict = field(default_factory=dict)


def results_to_dict(checks):
    """Convert a list of CheckResult objects to a list of dicts for reporting."""
    return [
        {
            "check_name": c.check_name,
            "target": c.target,
            "status": c.status.value,
            "message": c.message,
            "recommendation": c.recommendation,
            "duration_ms": round(c.duration_ms, 1),
            "raw_output": c.raw_output[:500] if c.raw_output else "",
        }
        for c in checks
    ]


# ---------------------------------------------------------------------------
# Report verdict derivation
# ---------------------------------------------------------------------------
# A DiagnosticReport carries two different KINDS of truth and they were being
# conflated:
#
#   * a CheckResult row is one OBSERVATION ("this VNet peering is not connected")
#   * a Diagnosis is the run's CONCLUSION ("that peering is latent — it is not on
#     the path to this target, so it is not blocking you")
#
# `overall_status` was derived from the rows alone (`if has_fail: FAIL`), which is
# severity blind. Observed in the field on a HEALTHY workspace: one red
# peering row + one MEDIUM diagnosis literally titled "latent — not blocking this
# target" produced `overall_status=fail` and an "ISSUES DETECTED" banner, while the
# chat said "everything works now". The customer said plainly that they could not
# tell whether they had a problem — the verdict field and the diagnosis content
# were allowed to disagree.
#
# So the headline is derived from what was actually CONCLUDED, while the rows keep
# their own truth (a peering row may legitimately stay FAIL on a healthy workspace):
#
#   FAIL  — some actionable diagnosis is CRITICAL or HIGH.
#   WARN  — the worst conclusion is MEDIUM/LOW; or a row did not pass / could not
#           reach a verdict and no conclusion owns it; or the engine itself said it
#           could not conclude (an INFO diagnosis with LOW confidence, which is how
#           `all_healthy`-with-inconclusive-checks and `storage_needs_sp` report
#           "I cannot tell you this is healthy").
#   PASS  — nothing above. SKIPPED rows do not by themselves demote the headline
#           (a skip is a DECLARED non-observation, e.g. "no SP provided"), but they
#           are always counted and named in the customer-facing text, so a clean
#           headline can never hide them.
#
# Deliberately NOT scenario-aware: it reads only severity, confidence, row status
# and the existing `metadata["inconclusive"]` convention that the checks already
# self-report.

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_HEADLINE_FAIL_SEVERITIES = ("critical", "high")
_STATUS_RANK = {"fail": 0, "error": 0, "warn": 1, "skip": 2, "pass": 3}


def severity_value(diagnosis):
    """Severity of a Diagnosis as a lowercase string ('high'), enum or str safe."""
    s = getattr(diagnosis, "severity", None)
    return str(getattr(s, "value", s) or "").lower()


def status_value(check):
    """Status of a CheckResult as a lowercase string ('warn'), enum or str safe."""
    s = getattr(check, "status", None)
    return str(getattr(s, "value", s) or "").lower()


def _check_values(checks):
    """Accept a dict of checks (report.checks) or a plain list."""
    if checks is None:
        return []
    if hasattr(checks, "values"):
        return list(checks.values())
    return list(checks)


def is_inconclusive(check):
    """Did this check try and fail to reach a verdict?

    Checks self-report this with metadata['inconclusive'] (azure_infra_checks'
    routing/NSG/DNS-alignment branches, classic_probers' DNS override probe). This
    is NOT the same as SKIP: a skip was never attempted.
    """
    return bool((getattr(check, "metadata", None) or {}).get("inconclusive"))


def actionable_diagnoses(diagnoses):
    """The diagnoses that assert a real finding: severity is not INFO, and the
    healthy card is excluded. Single definition — doctor's `_verification_line`,
    the chat prescription, the report builder and the verdict derivation all use
    this one, so they cannot drift apart."""
    out = []
    for d in diagnoses or []:
        if severity_value(d) in ("info", ""):
            continue
        if getattr(d, "pattern_id", "") == "all_healthy":
            continue
        out.append(d)
    return out


def rank_diagnoses(diagnoses):
    """Actionable diagnoses ordered as the customer should read them: severity
    first, then the engine's own `fix_order`. The chat text and the report must
    agree on WHICH finding is the top one — an earlier defect saw a medium finding re-headlined
    as "Root cause" while a higher-ranked one was dropped."""
    return sorted(
        actionable_diagnoses(diagnoses),
        key=lambda d: (_SEVERITY_RANK.get(severity_value(d), 98),
                       getattr(d, "fix_order", 99)),
    )


def worst_severity(diagnoses):
    """Lowercase severity string of the most severe actionable diagnosis, or ''."""
    ranked = rank_diagnoses(diagnoses)
    return severity_value(ranked[0]) if ranked else ""


def cannot_conclude(diagnoses):
    """Names of the diagnoses in which the engine says it could not reach a verdict.

    Convention already in the code: an INFO diagnosis with LOW confidence is the
    engine reporting "I could not conclude" — `all_healthy` when some check is
    inconclusive, and `storage_needs_sp` when no Reader SP was supplied. Both must
    keep the headline off PASS; neither is a failure.
    """
    return [getattr(d, "pattern_id", "") or getattr(d, "title", "")
            for d in (diagnoses or [])
            if severity_value(d) == "info" and str(getattr(d, "confidence", "")).lower() == "low"]


# ---------------------------------------------------------------------------
# ONE container for skips — the skip-accounting defect
# ---------------------------------------------------------------------------
# A DiagnosticReport carried skips in TWO places and each consumer picked one:
#
#   * `checks`  — rows a check RAN and produced. A check may itself return SKIP
#                 ("traceroute not available", "no forced tunnel on this subnet").
#   * `skipped` — (check_key, reason) pairs for checks the DAG gate never ran.
#
# Observed in the field on an ARM-blinded serverless run: 7 executed rows and
# 11 gate skips. Everything that counted skips counted `checks`, so the customer
# was told FOUR untrue things by one mismatch: the chat said "0 skipped", the
# driver print said "0 skip", the dashboard rendered a "0 Skipped" tile — and
# `_limitations_block` composed NOTHING, because all four of its sources read the
# empty container and it returns '' when it has no items. A dropped section
# leaves text to grep for; a section that was never composed leaves no trace at
# all, so that failure is QUIETER than the one it replaced.
#
# Latent in the same arithmetic: `headline_words` suppresses the
# "N NOT CHECKED" qualifier when the skip count is 0. Take the same shape with
# every executed row PASSing and it prints a green ALL HEALTHY, with a "0
# Skipped" tile, over eleven unverified layers. No prose guard can catch it —
# `_false_clean_claims` reads sentences, and there is no false sentence here,
# only a false number.
#
# The fix is at the source, not at the three call sites: gate skips are
# MATERIALISED into `checks` as real SKIP rows when the report is assembled
# (`merge_gate_skips`), so `checks` IS the customer-visible row set. `skipped`
# stays as provenance — the checkpoint, the chunked resume logic and the saved
# JSON all use it — but nothing has to count it any more.
#
# Two guards stop a future caller from silently reading the wrong container:
#   * `report_rows(report)` is the ONE reader. Handed a report whose rows were
#     never materialised (JSON saved by an older build, a report assembled by
#     some other path) it self-heals and SAYS SO, instead of under-counting.
#   * `check_verdict_counts` accepts a whole report and routes through it, so
#     `check_verdict_counts(report)` and `...(report.checks)` cannot disagree.
#
# `correlate()` is deliberately NOT given the materialised rows. Several rules
# branch on a check being ABSENT — "no Azure check ran at all, so ask for an SP"
# (`_rule_dns_fail_no_azure`), "the NCC was never inspected"
# (`_rule_serverless_egress_ncc`) — and a synthesised SKIP row makes absence
# unrepresentable, which would silently disable them. Rules read OBSERVATIONS;
# the report presents ROWS. That is the one place the two views legitimately
# differ, and it is stated here so nobody "tidies" it later.

# Human names for rows that never ran. A row a check produced names itself
# (`CheckResult.check_name`); a gate skip has no check to name it, and the raw
# dict key ("dns_pe_alignment") is not a string the customer can find in the
# report or in the Azure Portal. Check KEYS only — never a scenario, resource or
# chaos literal.
GATE_SKIP_TITLES = {
    "dns": "DNS Resolution",
    "dns_local_override": "Local DNS Override",
    "ping": "Ping (ICMP)",
    "tcp": "TCP Connect",
    "tls": "TLS Handshake",
    "traceroute": "Traceroute",
    "latency": "Latency",
    "nsg": "NSG Rules",
    "routes": "Route Table (UDR)",
    "subnet_egress": "Subnet Egress Route",
    "subnet_egress_firewall": "Subnet Egress Firewall",
    "peering": "VNet Peering",
    "pe": "Private Endpoints",
    "dns_zones": "Private DNS Zones",
    "dns_pe_alignment": "DNS \u2192 Private Endpoint Alignment",
    "ncc_attach": "NCC Attached",
    "ncc_pe": "NCC PE Rules",
    "egress_policy": "Egress Network Policy",
}

# Marker on a row that exists because a gate declined to run the check, as
# opposed to a check that ran and returned SKIP. Both are unverified layers and
# both must be counted; only this one has no measurement behind it at all.
GATE_SKIP_META = "gate_skip"

# ---------------------------------------------------------------------------
# WHY a check did not run — and which of those reasons is a GAP
# ---------------------------------------------------------------------------
# Counting skips correctly fixed the arithmetic and created a new
# defect one level up: every skip was then presented as an unverified layer.
# In the field, a healthy serverless run skipped nine checks whose ROW reasons
# said three sharply different things —
#
#   6x "Classic-plane check (workspace VNet) ... not applicable to a
#      serverless-only problem"            -> nothing is missing; wrong plane
#   1x "Target is a Databricks first-party host"  -> nothing is missing
#   1x "TCP succeeded — traceroute not needed"    -> nothing is missing
#   1x "the NCC attachment could not be READ (HTTP 403) ... is UNKNOWN"
#                                                -> a REAL gap, and it is the
#      one layer that governs the thing the customer asked about
#
# — and the limits section relabelled all nine as "unverified". The customer read
# two opposite statements about the same six rows ("not applicable" in the row,
# "unverified" in the limits) and could not tell which to act on, while the single
# genuine can't-check had no more prominence than the six that do not matter.
#
# So a skip reason carries its CLASS, and only one class is a gap. The default is
# deliberately the pessimistic one: an unclassified skip counts as unverified, so
# forgetting to classify can only ever over-report a gap, never hide one.
SKIP_NOT_APPLICABLE = "not_applicable"   # out of scope for this plane/target/product
SKIP_NOT_NEEDED = "not_needed"           # an earlier result made it unnecessary
SKIP_UNVERIFIED = "unverified"           # it APPLIES and could not be performed = a GAP
SKIP_KINDS = (SKIP_NOT_APPLICABLE, SKIP_NOT_NEEDED, SKIP_UNVERIFIED)

# Metadata key carrying the class on a materialised skip row.
SKIP_KIND_META = "skip_kind"


class SkipReason(str):
    """A gate's skip reason that also carries WHY the check did not run.

    A `str` subclass on purpose: every existing consumer (f-strings, `str()`,
    `json.dumps`, the checkpoint) keeps working unchanged and simply loses the
    class, which degrades to the pessimistic default. Nothing had to be rewritten
    to classify one gate.
    """

    kind = SKIP_UNVERIFIED

    def __new__(cls, text, kind=SKIP_UNVERIFIED):
        obj = super(SkipReason, cls).__new__(cls, str(text or "").strip())
        obj.kind = kind if kind in SKIP_KINDS else SKIP_UNVERIFIED
        return obj


def not_applicable(text):
    """This layer is out of scope for the plane/target being diagnosed — not a gap."""
    return SkipReason(text, SKIP_NOT_APPLICABLE)


def not_needed(text):
    """An earlier result settled it, so running this would add nothing — not a gap."""
    return SkipReason(text, SKIP_NOT_NEEDED)


def unverified(text):
    """The layer APPLIES and could not be checked — the only class that is a gap."""
    return SkipReason(text, SKIP_UNVERIFIED)


def skip_kind(obj, default=SKIP_UNVERIFIED):
    """The skip class of a reason string, a SkipReason, or a materialised SKIP row."""
    md = getattr(obj, "metadata", None)
    if isinstance(md, dict) and md.get(SKIP_KIND_META) in SKIP_KINDS:
        return md[SKIP_KIND_META]
    k = getattr(obj, "kind", None)
    if k in SKIP_KINDS:
        return k
    return default if default in SKIP_KINDS else SKIP_UNVERIFIED


def is_unverified_skip(check):
    """Is this row a layer the report genuinely could NOT verify?

    True for a gate skip classified `unverified` (or unclassified), and for a check
    that RAN and returned SKIP — the latter attempted nothing conclusive either and
    has no gate class to consult. False for a declared not-applicable / not-needed
    skip: those are answers, not gaps.
    """
    if status_value(check) != "skip":
        return False
    return skip_kind(check) == SKIP_UNVERIFIED


# ---------------------------------------------------------------------------
# ONE definition of "which network plane does this check conclude about?"
# ---------------------------------------------------------------------------
# `dns_pe_alignment` produced a CRITICAL-shaped FAIL row on a HEALTHY serverless
# session : it compared the serverless runtime's own resolver
# address (192.168.200.10) against the workspace's classic-plane private-endpoint
# IPs (10.40.6.4-8), concluded the customer's A record was stale, and its
# recommendation told them to rewrite a healthy `privatelink.azuredatabricks.net`
# zone. Serverless compute does not sit in the customer's spoke VNet — it resolves
# the workspace name through Databricks' own internal path, so the customer's PE
# addresses are simply not on that path and the two facts are not comparable.
#
# The check's own logic was sound (it even distinguished a public-internet bypass
# from a wrong private target). It was applied to the wrong plane. Two things let
# it get there, and both are mechanism, not this one check:
#
#  1. "Is this the classic plane?" was a COPIED EXPRESSION, spelled four different
#     ways in six places (per-check `== "serverless"` in the gate list, plus its
#     inverse, plus a third spelling that also admitted a since-removed `both`
#     plane, and again inside individual correlation rules). Nothing was the
#     authority, so a new check
#     joined the gate by OMISSION instead of by declaring its plane — which is
#     exactly how a cross-check added later, with a hand-written rationale for
#     opting out, escaped six sibling gates that were all correct.
#  2. The guard for this subject matter had been placed in the CONSUMING RULE
#     (`_rule_dns_pe_misalignment` does return None on serverless) and not in the
#     gate that produces the ROW. A check row is an independent customer-visible
#     output path: the chat guide renders every fail/error row WITH its
#     recommendation, and the dashboard reprints it under "Quick Fix Checklist".
#     So no diagnosis fired and the harmful prescription still reached the
#     customer. Same shape as the NSG/AllRules rows (doctrine 3) and the same
#     shape as before (a guard that lived in only one of two code paths).
#
# Hence: the plane is DATA, declared per check key, and there is one predicate.
# Every key in the orchestrator's execution order must appear in exactly one
# bucket, and `plane_bucket_gaps` makes that mechanically checkable instead of
# something a reviewer has to notice.

# Conclusions about the CUSTOMER DATA-PLANE VNET — its DNS records, NSGs, route
# tables, peerings and the private endpoints inside it. Only sound when the
# runtime doing the measuring sits in that VNet.
CLASSIC_PLANE_CHECKS = frozenset((
    "nsg", "routes", "subnet_egress", "subnet_egress_firewall", "peering",
    "dns_zones", "dns_pe_alignment",
))

# Conclusions about the ACCOUNT/NCC layer, which is where serverless egress is
# actually governed. Gated the other way round (they need serverless).
SERVERLESS_PLANE_CHECKS = frozenset(("ncc_attach", "ncc_pe", "egress_policy"))

# Neither: an in-session probe measures whatever plane THIS runtime is on, which
# is the right measurement on both, and makes no plane-specific prescription.
#
# `pe` is in here deliberately: private endpoints do live in the customer VNet,
# but the row is consumed as TARGET-side posture ("does this service have a private
# path at all"), which informs the NCC conclusion. The ARM collection is RG-wide,
# so its producer attributes each PE to the target by exact custom-DNS FQDN or the
# existing Azure resource-type/name detector; `pe_ips` is target-scoped and the full
# unrelated inventory lives under explicit `all_*` metadata keys. That attribution is
# what makes the row plane-neutral without letting an unrelated workspace PE turn a
# public hostname into a Private-Link target.
PLANE_NEUTRAL_CHECKS = frozenset((
    "dns", "dns_local_override", "ping", "tcp", "traceroute", "tls", "latency", "pe",
))

# Names the ACCOUNT LAYER, not "the NCC". The NCC is only one of the two objects in that
# layer and it is the private-endpoint one; what governs whether serverless may reach a
# destination at all is the serverless network policy's egress allow-list. This sentence
# rides SIX skip rows, so getting it wrong mislabelled the layer six times per report —
# the customer's objection in the field ("nothing NCC-related in this case") was aimed
# at exactly this kind of sentence.
CLASSIC_PLANE_SKIP_REASON = (
    "Classic-plane check (workspace VNet) — serverless egress is governed by the Databricks "
    "account layer (the serverless network policy's egress allow-list, plus the NCC when the "
    "target is an Azure resource reached privately); not applicable to a serverless-only problem")

# One key needs a longer sentence, because "not applicable" alone would read as
# arbitrary for a cross-check whose inputs both exist on this run.
_CLASSIC_PLANE_SKIP_REASONS = {
    "dns_pe_alignment": (
        "Classic-plane cross-check (workspace VNet) — serverless compute resolves names "
        "through Databricks' own internal resolver, outside the workspace VNet, so its "
        "answer cannot be compared with the private endpoints inside that VNet; not "
        "applicable to a serverless-only problem"),
}


def is_data_plane_vnet(context):
    """Does the runtime performing this diagnosis sit in the customer data-plane VNet?

    False for a serverless-only diagnosis: serverless compute runs in
    Databricks-managed infrastructure with its own internal resolver and egress, so
    NO statement about the customer's VNet DNS/NSG/routes/peering/PEs can be
    concluded from what this runtime observes.

    `both` and `classic` are True — a classic diagnosis measures the VNet plane,
    driven from a cluster in it (SKILL.md 4d `run_on_cluster`).

    Deliberately reads ONLY `compute_type`. `topology.build_topology` treats "no
    customer VNet was discovered" as serverless too, and that is right there but it is
    a DISCOVERY fact about one ARM read, not the plane the diagnosis is running on —
    folding it in here would let an absent/empty key silently switch off classic-plane
    reasoning for every caller. If a caller needs both conditions it should say so.
    """
    return str((context or {}).get("compute_type", "classic")).lower() != "serverless"


# ---------------------------------------------------------------------------
# Companion egress hosts
# ---------------------------------------------------------------------------
# Some services answer on one hostname and serve their PAYLOAD from a second one.
# Allow-listing only the host the customer named leaves the job still broken in a
# confusing way: the index responds, metadata resolves, and then the download is
# refused. `%pip install` is the canonical case — pypi.org serves the index, but the
# wheels come from files.pythonhosted.org.
#
# In the field: the engine's prescription named only pypi.org. The CDN was mentioned
# by the CONVERSATIONAL layer, which volunteered it unprompted — so a customer who
# followed the engine's fix literally could have allow-listed one host and still failed,
# and nothing in the product would have caught it.
#
# Exact-host keys only. These are "commonly required alongside", not "always required":
# the prescription says so rather than asserting a certainty we have not measured.
COMPANION_EGRESS_HOSTS = {
    "pypi.org":            ("files.pythonhosted.org",),
    "pypi.python.org":     ("files.pythonhosted.org",),
    "files.pythonhosted.org": ("pypi.org",),
    "cran.r-project.org":  ("cloud.r-project.org",),
    "cloud.r-project.org": ("cran.r-project.org",),
    "repo1.maven.org":     ("repo.maven.apache.org",),
    "repo.maven.apache.org": ("repo1.maven.org",),
    "conda.anaconda.org":  ("repo.anaconda.com",),
    "repo.anaconda.com":   ("conda.anaconda.org",),
}


def companion_egress_hosts(host):
    """Hosts usually needed ALONGSIDE `host` for the workload to actually succeed.

    Returns a tuple (possibly empty). Empty is the common case and callers must render
    nothing extra for it — never invent a companion for an unknown host.
    """
    return COMPANION_EGRESS_HOSTS.get(str(host or "").strip().lower(), ())


# The DECLARED plane and the MEASURED plane are different facts, and conflating them
# produced a CRITICAL false positive (in the field).
#
# `is_data_plane_vnet` answers "which plane is the PROBLEM about". It reads only
# `compute_type`, deliberately, and its docstring says a caller needing more should say so.
# This is that caller. `dns_pe_alignment` does not reason about the problem's plane: it
# compares the address THE PROBE RESOLVED against private endpoints inside the customer
# VNet, and that comparison is sound only if the probe ran INSIDE that VNet.
#
# In-session probes (`classic_probers.check_dns` and friends) execute IN-PROCESS, on
# whatever runtime runs the notebook cell — NOT on the `cluster_id` the intake collected,
# which belongs to the separate `run_on_cluster` path (SKILL.md 4d). So a customer can
# truthfully declare `classic`, have no classic cluster to offer, and the probes still run
# on the serverless notebook. That is exactly what happened: DNS resolved to 192.168.200.20
# (Databricks-managed serverless space, the same range as the notebook's own source
# address), it was compared against the workspace's PE IPs 10.40.6.6/7, and the run declared
# the customer's A record wrong — while the customer's zone held precisely the right record.
# The advice was to rewrite a healthy private DNS zone, and it outranked the real cause.
#
# HOW `probe_runtime` MAY BE ESTABLISHED — read this before "improving" it. The only signal
# that separates the planes is IMDS: a real Azure VM answers on the link-local address and
# serverless does not. `spark.databricks.clusterUsageTags.clusterId` does NOT separate them
# (serverless populates it too); inferring `classic` from it mislabelled a serverless session
# in the field and contributed to a confident `all_healthy` on a workspace whose peering had
# been deleted. And IMDS is usable in the POSITIVE direction ONLY: unreachable does not mean
# serverless, because a classic cluster with filtered link-local egress would be mislabelled.
#
# So `probe_runtime` is "classic" or it is UNKNOWN, and unknown answers False here: without
# evidence that the probe ran in the VNet, a VNet-vs-probe comparison must not be attempted.
# Silence is the honest failure mode — this is a cross-check, not the core verdict.
PROBE_PLANE_UNKNOWN_SKIP = (
    "cannot establish that the in-session probes ran INSIDE the customer VNet (the runtime "
    "did not answer on the Azure instance-metadata address, which is what distinguishes a "
    "VNet VM from serverless). A probe running on the serverless notebook resolves names "
    "through Databricks' own internal resolver, so its answer cannot be compared with the "
    "private endpoints inside that VNet — whatever compute the problem is about. To make "
    "this cross-check meaningful, start a classic cluster and give me its id, then re-run: "
    "the probes are executed on that cluster, inside the VNet, and this comparison becomes "
    "sound")


def probes_measured_data_plane_vnet(context):
    """Did the IN-SESSION probes actually execute inside the customer data-plane VNet?

    Returns (bool, reason). Distinct from `is_data_plane_vnet`, which answers a different
    question — see the comment above. `context["probe_runtime"]` is a MEASUREMENT the caller
    takes from the live runtime, never an inference from the answers: "classic" means IMDS
    answered. Anything else, including absent, is unknown and answers False.
    """
    if not is_data_plane_vnet(context):
        return False, CLASSIC_PLANE_SKIP_REASON
    if str((context or {}).get("probe_runtime") or "").strip().lower() == "classic":
        return True, ""
    return False, PROBE_PLANE_UNKNOWN_SKIP



def companion_egress_clause(host):
    """One sentence to append to an allow-list prescription, or "" when there is none."""
    extra = companion_egress_hosts(host)
    if not extra:
        return ""
    names = ", ".join(f"`{h}`" for h in extra)
    return (f"Add {names} in the same pass — {host} serves the index, but the payload is "
            f"served from {'that host' if len(extra) == 1 else 'those hosts'}, so "
            f"allow-listing {host} alone typically leaves the download still blocked.")


def classic_plane_skip(check_name, context):
    """THE gate for a data-plane-VNet check. Returns (should_skip, SkipReason).

    Every classic-plane check and cross-check asks here — one predicate, one
    reason vocabulary, one class (`not_applicable`, because a wrong-plane check is
    an answer and not a gap in the diagnosis).
    """
    if is_data_plane_vnet(context):
        return False, SkipReason("", SKIP_NOT_APPLICABLE)
    return True, not_applicable(
        _CLASSIC_PLANE_SKIP_REASONS.get(str(check_name), CLASSIC_PLANE_SKIP_REASON))


def plane_bucket_gaps(check_keys):
    """THE INVARIANT: every executed check key declares exactly one plane.

    Returns {'unbucketed': [...], 'multiple': [...]}. Empty lists mean no check can
    silently default into "runs everywhere" — which is how `dns_pe_alignment` ran on
    a serverless session for as long as it did.
    """
    out = {"unbucketed": [], "multiple": []}
    for key in (check_keys or []):
        k = str(key)
        hits = sum(1 for b in (CLASSIC_PLANE_CHECKS, SERVERLESS_PLANE_CHECKS,
                               PLANE_NEUTRAL_CHECKS) if k in b)
        if hits == 0:
            out["unbucketed"].append(k)
        elif hits > 1:
            out["multiple"].append(k)
    return out


def gate_skip_title(name):
    """Customer-facing name for a check key that never ran."""
    return GATE_SKIP_TITLES.get(str(name),
                                str(name).replace("_", " ").strip().title())


def gate_skip_row(name, reason, target=""):
    """One 'this never ran' row, in the same shape as every other row.

    Carries the skip CLASS in metadata so every downstream reader (the limits
    block, the healthy card, the dashboard) can tell a not-applicable answer from a
    layer that genuinely could not be verified, without re-deriving it from prose.
    """
    return CheckResult(
        check_name=gate_skip_title(name),
        target=target or "(not run)",
        status=Status.SKIP,
        message=str(reason or "").strip() or "This check did not run.",
        metadata={GATE_SKIP_META: True, "check_key": str(name),
                  SKIP_KIND_META: skip_kind(reason)},
    )


def _skip_pairs(skipped):
    """`report.skipped` as [(check_key, SkipReason)], tolerating tuples/lists/strings.

    A recorded skip may be `(key, reason)` or `(key, reason, kind)`. The third slot
    exists so the class survives the checkpoint / saved JSON round-trip, where a
    `SkipReason` degrades to a plain `str` and would otherwise lose it. An entry with
    no class is `unverified` — the pessimistic default.
    """
    out = []
    for entry in (skipped or []):
        kind = None
        if isinstance(entry, (list, tuple)):
            name = entry[0] if len(entry) else ""
            reason = entry[1] if len(entry) > 1 else ""
            kind = entry[2] if len(entry) > 2 else None
        else:
            name, reason = entry, ""
        if not name:
            continue
        if kind not in SKIP_KINDS:
            kind = skip_kind(reason)
        out.append((str(name), SkipReason(reason, kind)))
    return out


def merge_gate_skips(checks, skipped):
    """The canonical row set: executed rows + one SKIP row per gate skip.

    Idempotent (safe to apply twice) and order-stable: executed rows keep their
    order, gate skips follow in the order they were recorded. A key already in
    `checks` WINS — it ran, so its real outcome is the truth.
    """
    rows = dict(checks or {})
    for name, reason in _skip_pairs(skipped):
        if name in rows:
            continue
        rows[name] = gate_skip_row(name, reason)
    return rows


def unaccounted_skips(report):
    """THE INVARIANT: gate skips with no row in `report.checks`.

    Empty list means the report's rows account for every skip it recorded. A
    non-empty list means any consumer counting `report.checks` is about to
    under-report unverified layers — the skip-accounting defect, detected rather than
    trusted.
    """
    checks = getattr(report, "checks", None)
    if checks is None:
        return []
    names = set(checks.keys()) if hasattr(checks, "keys") else set()
    return [n for n, _ in _skip_pairs(getattr(report, "skipped", None))
            if n not in names]


def skip_class_ambiguity(report):
    """THE COUNTERPART INVARIANT: does the gap count depend on WHICH container you read?

    Returns {} when it does not. Otherwise {"from_rows": N, "from_skipped": M, ...} — and a
    non-empty result means the saved artefact can be counted two ways that disagree, so a
    consumer will get a number that is defensible and wrong.

    ── Why `unaccounted_skips` did not catch this, which is the question worth answering ──

    Observed in the field: `report["checks"]` carried 11 rows with status `skip` while
    `report["skipped"]` carried 10. `ncc_attach` was in the first and absent from the
    second, so counting `skip_kind` over the array yielded `unverified: 1` while the prose
    (counting rows) said 2.

    `unaccounted_skips` asks "is there an entry in `skipped` with no row in `checks`?" —
    skips that would be INVISIBLE, i.e. under-reported gaps. That is a different question,
    and the answer here was legitimately "no". The inverse — a skip ROW with no entry in
    `skipped` — is **not an error at all**: `ncc_attach` RAN and returned SKIP, so it has
    no gate-skip provenance to record, and inventing one would be a lie about what
    happened. So the invariant did not miss its own case; the case was never its case.

    The real defect is one level up, in the ARTEFACT CONTRACT. `skipped` is provenance for
    GATE skips only, but the saved JSON presents both containers as equally countable and
    names neither as authoritative — and the skip CLASS lives in a row's metadata for an
    executed SKIP while living in both places for a gate skip. Two plausible derivations,
    one right. That is why the fix is not another guard: `report_to_dict` now STATES the
    number (`verdict_counts.unverified` + `unverified_layers`), so nothing has to be
    derived, and this function exists so a build can assert the two readings agree wherever
    a consumer still derives one.
    """
    if not hasattr(report, "checks"):
        return {}
    rows = report_rows(report) or {}
    from_rows = sum(1 for c in (rows.values() if hasattr(rows, "values") else rows)
                    if is_unverified_skip(c))
    from_skipped = sum(1 for _n, r in _skip_pairs(getattr(report, "skipped", None))
                       if skip_kind(r) == SKIP_UNVERIFIED)
    if from_rows == from_skipped:
        return {}
    return {
        "from_rows": from_rows,
        "from_skipped": from_skipped,
        "authoritative": "from_rows",
        "why": ("`report.skipped` records GATE skips only; a check that RAN and returned "
                "SKIP appears in `checks` alone. Count rows (report_rows / "
                "check_verdict_counts), or read the stated verdict_counts.unverified."),
    }


def unverified_layer_items(report):
    """[{key, name, reason}] for every layer this run could NOT settle.

    The artefact's own answer to "how many gaps, and which?", derived once through the
    canonical reader so the chat, the dashboard and the saved JSON cannot disagree about
    it — and so no consumer has to reconstruct it from a container that was never meant to
    carry it.
    """
    out = []
    for key, c in split_skipped_rows(report)[0]:
        out.append({"key": key,
                    "name": check_label(key, c),
                    "reason": _norm_ws(getattr(c, "message", ""))})
    return out


_ROWS_WARNED = set()


def report_rows(report):
    """Every row the customer can read — from a report OR a bare checks container.

    The single READER for row-level accounting. Pass it a DiagnosticReport and it
    returns the materialised rows, healing (loudly) a report that was assembled
    without them. Pass it a plain dict/list and it hands it back untouched, so
    existing `check_verdict_counts(report.checks)` calls keep working.
    """
    if not hasattr(report, "checks"):
        return report
    missing = unaccounted_skips(report)
    if not missing:
        return report.checks or {}
    key = id(report)
    if key not in _ROWS_WARNED:
        _ROWS_WARNED.add(key)
        print(f"[Doctor] INTERNAL: {len(missing)} skipped check(s) were not materialised "
              f"into report.checks ({', '.join(missing[:6])}"
              f"{', ...' if len(missing) > 6 else ''}) — counting them from report.skipped "
              "so the skip total cannot read as 0. Report this: the report was assembled "
              "without models.merge_gate_skips.")
    return merge_gate_skips(report.checks, report.skipped)


def check_verdict_counts(checks):
    """Row-level tally used by both the headline and the customer-facing text.

    Accepts a DiagnosticReport (preferred — it can see the gate skips) or a bare
    checks dict/list. Returns
    {'pass','warn','fail','error','skip','unverified','inconclusive','not_passed','total'}.
    'inconclusive' overlaps the status buckets on purpose (an inconclusive check
    is usually reported as WARN); 'not_passed' is every row that is not a clean
    PASS.

    'unverified' is the subset of 'skip' that is a real GAP (`is_unverified_skip`),
    i.e. skips minus the declared not-applicable / not-needed answers. The two are
    NOT interchangeable and the distinction is the whole point of the skip classes:
    a COUNT may be the raw total (10 rows genuinely did not run), but a CLAIM about
    what the report failed to establish may only ever be about the gaps. `skip`
    feeds the tiles; `unverified` feeds the headline.
    """
    vals = _check_values(report_rows(checks))
    counts = {k: 0 for k in ("pass", "warn", "fail", "error", "skip", "inconclusive")}
    unverified_rows = 0
    for c in vals:
        sv = status_value(c)
        if sv in counts:
            counts[sv] += 1
        if is_inconclusive(c):
            counts["inconclusive"] += 1
        if is_unverified_skip(c):
            unverified_rows += 1
    counts["unverified"] = unverified_rows
    counts["total"] = len(vals)
    counts["not_passed"] = counts["total"] - counts["pass"]
    return counts


def derive_overall_status(checks, diagnoses):
    """The report HEADLINE verdict. See the block comment above for the policy."""
    counts = check_verdict_counts(checks)
    worst = worst_severity(diagnoses)

    if worst in _HEADLINE_FAIL_SEVERITIES:
        return Status.FAIL
    if worst:                                     # medium / low conclusion
        return Status.WARN
    if counts["fail"] or counts["error"] or counts["warn"] or counts["inconclusive"]:
        # A row that did not pass, with nothing concluding on it: honest middle
        # ground. Never PASS (we would be laundering it) and never FAIL (no rule
        # claimed a blocking problem).
        return Status.WARN
    if cannot_conclude(diagnoses):
        return Status.WARN
    return Status.PASS


def worst_status(statuses):
    """The most severe Status in an iterable (fail/error > warn > skip > pass)."""
    vals = [s for s in (statuses or []) if s is not None]
    if not vals:
        return Status.PASS
    return sorted(vals, key=lambda s: _STATUS_RANK.get(
        str(getattr(s, "value", s)).lower(), 9))[0]


def headline_words(overall, counts):
    """(banner_text, banner_colour) for a derived verdict — one definition so the
    dashboard banner cannot contradict `report.overall_status`.

    D3. The qualifier counts UNVERIFIED rows, not raw skips, and that distinction was
    latent until the account-403 fix exposed it. The raw-count branch below was
    unreachable on every run we had ever graded: `warn` returns two lines above, and
    something was always WARN — on the healthy serverless run it was the account-API
    403 that `check_ncc_attached` mislabelled `Status.ERROR`. Reclassifying that 403
    as the gap it is makes the run all-pass and lands here for the first time, where
    the raw skip total would have printed "HEALTHY — 10 NOT CHECKED" over ONE genuine
    gap and nine layers that do not apply to this plane at all.

    The tile stays at the raw total (10 rows really did not run — that is a count, and
    it is true). The banner is a CLAIM about what this diagnosis failed to establish,
    so it may only count gaps. Same split as `check_verdict_counts`.

    The fallback is deliberately pessimistic: a caller that passes only {"skip": N}
    (an older/partial counts dict) still gets the qualifier off the raw total, so
    forgetting to pass `unverified` can only over-report a gap, never hide one.
    """
    ov = str(getattr(overall, "value", overall) or "pass").lower()
    if ov in ("fail", "error"):
        return "ISSUES DETECTED", "#dc3545"
    if ov == "warn":
        return "WARNINGS", "#ffc107"
    c = counts or {}
    gaps = c["unverified"] if "unverified" in c else c.get("skip", 0)
    if gaps:
        # "ALL HEALTHY" while N applicable layers were never verified is a false clean
        # claim. "UNVERIFIED" (not "NOT CHECKED") because that is the word the limits
        # section, the healthy card and the dashboard all use for a gap — one grep over
        # any surface finds every one of them, and the number now matches that list.
        return f"HEALTHY — {gaps} UNVERIFIED", "#28a745"
    return "ALL HEALTHY", "#28a745"


# ---------------------------------------------------------------------------
# "Limits of this diagnosis" — ONE composer, for the chat AND the dashboard
# ---------------------------------------------------------------------------
# It lived in doctor.py, so only the chat had it. Grep of the rendered dashboard
# on the live serverless-healthy run: ZERO hits for "limits of this diagnosis",
# "unverified" and "not checked", while the same run's chat named nine layers. The
# customer's own words: *"The dashboard is the artefact I'd forward to my platform
# team, and it is markedly more reassuring than the chat"* — they graded PARTLY
# VERIFIED from the chat and VERIFIED from the dashboard alone. A deliverable that
# is more reassuring than the truth is the defect we keep removing, and this copy
# is the one that gets forwarded.
#
# `report_builder` cannot import `doctor` (doctor imports report_builder), so the
# composer lives here — next to `headline_words`, for the same reason that one
# does: two surfaces render it, and they must not be able to disagree.

# The engine's own wording for "these specific layers were never tested". The limits
# block already lists them from the rows, so a hoisted restatement is duplication.
# Keep in step with `_rule_all_healthy`'s sentences — the phrases are the contract.
SKIP_RESTATEMENT_MARKERS = (
    "not tested, and therefore unverified",
    "not checked at all",
    "deliberately not run",
)

# Sentences the ENGINE ITSELF writes to admit it may be blind to something. Generic
# self-limitation wording (never a scenario or resource literal), hoisted out of the
# individual diagnosis because burying them there is how the relay lost them.
CAVEAT_MARKERS = (
    "invisible", "unverified", "not evidence of health", "could not reach a verdict",
    "not a confirmation", "i will not claim", "does not claim", "cannot verify",
    "hypothesis", "absence of evidence",
)

_LIMITS_HEADING_GAPS = "**Limits of this diagnosis — what this run could not settle**"
_LIMITS_HEADING_SCOPE = "**Scope of this diagnosis — what did not apply, and why**"


def _norm_ws(s):
    return _re.sub(r"\s+", " ", str(s or "")).strip()


def check_label(key, c):
    """The human check name the report already carries ('Local DNS Override').

    The guide used to print the internal dict key (`dns_local_override`,
    `subnet_egress`), which reads like log output and is not a string the customer
    can find anywhere in the report or the portal.
    """
    name = (getattr(c, "check_name", "") or "").strip()
    return name or str(key).replace("_", " ").strip().title()


def self_limitation_sentences(d):
    """Caveat sentences the engine wrote inside a diagnosis, so they can be hoisted."""
    out = []
    blobs = [getattr(d, "root_cause", "") or ""] + list(getattr(d, "prescription", None) or [])
    for blob in blobs:
        for sentence in _re.split(r"(?<=[.;])\s+", str(blob)):
            s = sentence.strip()
            if not s or len(s) > 400:
                continue
            if any(mark in s.lower() for mark in CAVEAT_MARKERS):
                out.append(s)
    return out[:4]


def split_skipped_rows(report):
    """Every SKIP row, split into the ONE set that is a gap and the set that is not.

    Returns (unverified_rows, declared_rows), each [(key, CheckResult)] in row order.

    This is the distinction the live run flattened. Six rows said "Classic-plane check
    ... NOT APPLICABLE to a serverless-only problem", one said "TCP succeeded —
    traceroute not needed", one said "Target is a Databricks first-party host" — and
    exactly ONE said "the NCC attachment could not be READ (HTTP 403) ... is UNKNOWN",
    which is the layer that governs serverless egress and therefore the only thing the
    customer needed to see. Presenting all nine as "unverified" both contradicted the
    rows and buried the one that mattered. The skip COUNT is unchanged (nine really
    were not run); the *unverified* set is the narrow one.
    """
    unver, declared = [], []
    for key, c in (report_rows(report) or {}).items():
        if status_value(c) != "skip":
            continue
        (unver if is_unverified_skip(c) else declared).append((key, c))
    return unver, declared


def _declared_skip_line(declared):
    """One line for the not-a-gap skips, grouped by their own row reason.

    Grouped, and quoting the row's reason VERBATIM, so the limits section and the
    check rows say the same words about the same layers. The contradiction the
    customer hit was a paraphrase problem as much as a classification one.
    """
    groups, order = {}, []
    for key, c in declared:
        reason = _norm_ws(getattr(c, "message", "")) or "did not run"
        if reason not in groups:
            groups[reason] = []
            order.append(reason)
        groups[reason].append(f"**{check_label(key, c)}**")
    parts = []
    for reason in order:
        parts.append(", ".join(groups[reason]) + " — " + reason.rstrip("."))
    return ("- Deliberately not run, and NOT gaps in this diagnosis — they do not apply to "
            "this problem, or a result above made them unnecessary: " + "; ".join(parts) + ".")


def limitations_items(report, already=""):
    """The bullet list of everything this run could not settle, gaps FIRST.

    `already` is text composed BEFORE this block. an earlier defect hoisted the engine's own caveat
    sentences up here because the relay dropped them when they were buried in
    prescription step 4-of-4; an earlier defect moved the findings above the limits, which makes an
    unconditional hoist pure duplication — so a caveat is hoisted only when it is NOT
    already in the text above.
    """
    items = []
    seen_above = _norm_ws(already)
    checks = report_rows(report) or {}

    unver, declared = split_skipped_rows(report)

    # GAPS FIRST, and each one named with its own reason. Previously the genuine
    # can't-check sat inside an undifferentiated list of nine names, with no more
    # prominence than the six that did not matter.
    for key, c in unver:
        msg = _norm_ws(getattr(c, "message", ""))
        # Only spell out the consequence when the row's own reason does not already —
        # the NCC 403 reason, for instance, ends by saying the answer is UNKNOWN and what
        # to fix, and repeating it reads as boilerplate. Reuses the caveat vocabulary
        # rather than inventing a second matcher for the same idea.
        low = msg.lower()
        spelled_out = "unknown" in low or any(m in low for m in CAVEAT_MARKERS)
        if spelled_out:
            tail = ""
        else:
            tail = (("" if msg.endswith((".", "!", "?")) else ".")
                    + " This layer was not checked at all, so nothing in this report covers it.")
        # The word "UNVERIFIED" is deliberate and load-bearing: it is the term the
        # limits section, the healthy card and the dashboard all use for a real gap, so
        # one grep over any surface finds every one of them.
        items.append(f"- **UNVERIFIED — {check_label(key, c)} (NOT CHECKED)**: {msg}{tail}")
    for name, c in checks.items():
        if is_inconclusive(c):
            items.append(f"- **{check_label(name, c)}** could not reach a verdict: "
                         f"{(getattr(c, 'message', '') or '').strip()}")

    for d in report.diagnoses or []:
        if getattr(d, "needs_confirmation", False):
            q = (getattr(d, "follow_up_questions", None) or [""])[0]
            items.append(f"- **{getattr(d, 'title', d.pattern_id)}** is a HYPOTHESIS I cannot "
                         "verify from probes/ARM alone" + (f" — confirm: {q}" if q else "."))
        for sentence in self_limitation_sentences(d):
            if seen_above and _norm_ws(sentence) in seen_above:
                continue
            # The engine's own words for "these layers were never tested" state exactly
            # what the skip items already list, in different phrasing, so the verbatim
            # dedupe cannot catch it — and that is ~40 words of the same list twice.
            if (unver or declared) and any(m in sentence.lower()
                                          for m in SKIP_RESTATEMENT_MARKERS):
                continue
            items.append(f"- From *{getattr(d, 'title', d.pattern_id)}*: {sentence}")
    for pid in cannot_conclude(report.diagnoses):
        items.append(f"- The engine reported low confidence (`{pid}`): treat this report as "
                     "incomplete, not as a clean result.")

    gaps = len(items)
    # The not-a-gap skips come LAST and are explicitly labelled as such, so the section
    # can no longer re-label as "unverified" the same rows whose own reason says "not
    # applicable". They are still named: the run did not check them and the count says so.
    if declared:
        items.append(_declared_skip_line(declared))
    return list(dict.fromkeys(items)), gaps


def limitations_block(report, already=""):
    """The composed 'Limits of this diagnosis' section, or '' when there is nothing.

    The heading follows the content: with a real gap it is what this run could not
    SETTLE; with nothing but declared not-applicable rows it is the SCOPE of the run.
    A "could not settle" heading over a list of things that did not need settling is
    the same contradiction as calling a not-applicable row unverified.
    """
    items, gaps = limitations_items(report, already=already)
    if not items:
        return ""
    heading = _LIMITS_HEADING_GAPS if gaps else _LIMITS_HEADING_SCOPE
    return heading + "\n" + "\n".join(items)
