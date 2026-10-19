"""Single entry point for the Network Connectivity Doctor.

    result = run_network_doctor(problem_text)                 # first call
    result = run_network_doctor(answers={...}, session_path=r"<printed>")

The ORCHESTRATION lives here, in code: path classification (A/B/C), the intake
gate, SP-secret handling (names only — resolved internally), the chunked
execution contract (ONE unit of work per call, session persisted to disk so a
Genie session reset costs nothing), correlation, and the presentation payload.
The LLM's job is reduced to what it is good at: relaying the structured
questions to the customer and presenting the returned chat prescription.

Every call PRINTS the literal next action ("[Doctor] NEXT ...") and returns a
JSON-friendly dict with `status`:

    NEED_INPUT   -> ask the customer result["questions"], call again with answers
    IN_PROGRESS  -> run result["next_step"] in a NEW cell
    DONE         -> present: chat prescription FIRST, then the dashboard
    ERROR        -> something the customer must resolve; message says what

Requires the sibling modules (models/orchestrator/report_builder/...) on
sys.path — SKILL.md Step 1 does this.
"""

import hashlib
import json
import os
import re as _re
import traceback as _traceback
from datetime import datetime, timezone

from models import (
    CAVEAT_MARKERS as _CAVEAT_MARKERS,
    CheckResult, Diagnosis, Severity, Status,
    SERVERLESS_PLANE_CHECKS as _SERVERLESS_PLANE_CHECKS,
    SKIP_RESTATEMENT_MARKERS as _SKIP_RESTATEMENT_MARKERS,
    actionable_diagnoses, cannot_conclude, check_label as _check_label,
    check_verdict_counts, headline_words,
    is_inconclusive as _is_inconclusive, is_unverified_skip, limitations_block,
    rank_diagnoses, report_rows,
    self_limitation_sentences as _self_limitation_sentences, severity_value,
    split_skipped_rows, status_value,
)
from models import _norm_ws
from cluster_start_checks import parse_nhc_error, probe_arm_reachability
from correlation_engine import (_NO_CHANGE_MARKERS, cleared_appliances,
                                established_blocking_causes, make_egress_firewall_diagnosis)
from orchestrator import (
    _ACCOUNT_BLIND_ROW, _ARM_BLIND_ROW, continue_diagnosis, diagnose_cluster_start,
    finalize_diagnosis,
    load_checkpoint, reopen_checks, start_diagnosis,
)
from serverless_ncc_checks import (
    ACCOUNT_HANDOFF_META as _HANDOFF_META,
    ACCOUNT_SCRIPT_PATH_TOKEN as _ACCOUNT_SCRIPT_PATH_TOKEN,
    infer_resource_type as _infer_resource_type,
)
from report_builder import (
    _default_report_dir, build_dashboard_v2, report_to_dict,
    save_account_snapshot_script, save_dashboard_html,
)
from secret_utils import load_azure_sp_from_secrets
from serverless_ncc_checks import (
    _get_dbutils, _get_spark,
    discover_account_id, get_workspace_context,
)
from storage_access_checks import (
    build_storage_report, check_storage_firewall, check_storage_nsp, check_storage_roles,
    find_storage_account_scope, get_access_connector_for_table, get_arm_token,
    get_table_storage_info, resolve_access_connector_principal,
)

_SESSION_SCHEMA = "network_doctor_session_v1"

_STORAGE_STRONG_SIGNS = (
    "permission_denied", "abfsrestoperationexception", "user delegation",
    "storage blob delegator", "storage blob", "authorizationfailure",
    "request not authorized",
)
_STORAGE_ACCESS_SIGNS = (
    "permission_denied", "permission", "permissions", "permiss", "access denied",
    "acesso negado", "request not authorized", "not authorized", "unauthorized",
    "authorizationfailure", "autoriz", "403", "forbidden",
)
# Verbatim Azure Storage / AAD authorization errors. These are unambiguous on
# their own and need NO second keyword — which matters because the canonical ADLS
# 403 ("This request is not authorized to perform this operation using this
# permission.") contains none of the context words below, so a customer who
# pastes the raw error, or calls the account "our data lake", used to land in
# Path A and be asked for a host:port instead of getting the storage credential
# and firewall checks.
_STORAGE_DECISIVE_SIGNS = (
    "request not authorized to perform this operation",
    "this request is not authorized",
)
_STORAGE_CONTEXT_SIGNS = (
    "storage", "storage account", "adls", "blob", "abfs", "abfss", "dfs.core.windows.net",
    "unity catalog", "uc", "volume", "external table", "external location", "catalog",
    "schema", "table", "tabela",
    # What customers actually call ADLS in their own words.
    "data lake", "datalake", "lakehouse",
)

_HOST_RE = _re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9])(?::(\d{2,5}))?\b",
    _re.IGNORECASE,
)
_PORT_RE = _re.compile(r"\bport(?:a)?\s+(\d{2,5})\b", _re.IGNORECASE)
# A backticked 3-part UC name (`cat`.`schema`.`table`) is unambiguous — only
# auto-extract that form; a bare `a.b.c` could be a hostname (e.g. the storage
# FQDN), so for bare names we ask in intake instead of guessing.
_UC_TABLE_RE = _re.compile(r"`([A-Za-z0-9_-]+)`\.`([A-Za-z0-9_-]+)`\.`([A-Za-z0-9_-]+)`")


# ---------------------------------------------------------------------------
# Session persistence
# ---------------------------------------------------------------------------

def _session_dir(base_dir=None):
    return base_dir or _default_report_dir()

def _session_path_for(problem_text, base_dir=None):
    digest = hashlib.sha256((problem_text or "").strip().encode()).hexdigest()[:10]
    return os.path.join(_session_dir(base_dir), f"doctor_{digest}.session.json")

def _save_session(s, path):
    s["updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)

def _load_session(path):
    with open(path, "r", encoding="utf-8") as f:
        s = json.load(f)
    if s.get("schema") != _SESSION_SCHEMA:
        raise ValueError(f"Not a network-doctor session file: {path}")
    return s


# ---------------------------------------------------------------------------
# Build identity + session age
# ---------------------------------------------------------------------------
# Field experience: a brand-new notebook on a brand-new kernel found the
# previous session for the same problem and OFFERED to show it — a result produced by
# the code from before that day's fix, with nothing saying the build had changed
# underneath it. A customer re-runs precisely BECAUSE they changed something, so serving
# findings that predate their change is worse than useless.
#
# The driver cannot see a git commit at runtime, but it can see the code it is actually
# executing: the sibling module files it imported. Hashing their CONTENT gives a build
# identity that changes on every redeploy of the engine and is stable across kernels and
# notebooks. (Content, not mtime: a redeploy that rewrites an identical file must not
# invalidate a still-valid session.)

_BUILD_MODULES = (
    "models.py", "classic_probers.py", "azure_infra_checks.py", "topology.py",
    "storage_access_checks.py", "cluster_start_checks.py", "serverless_ncc_checks.py",
    "correlation_engine.py", "orchestrator.py", "report_builder.py", "secret_utils.py",
    "doctor.py",
)
_BUILD_FINGERPRINT = ""


def _build_fingerprint():
    """A short hash of the diagnostic code currently loaded. "" if unreadable."""
    global _BUILD_FINGERPRINT
    if _BUILD_FINGERPRINT:
        return _BUILD_FINGERPRINT
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        h = hashlib.sha256()
        for name in _BUILD_MODULES:
            fp = os.path.join(here, name)
            if not os.path.exists(fp):
                continue
            with open(fp, "rb") as f:
                h.update(name.encode())
                h.update(f.read())
        _BUILD_FINGERPRINT = h.hexdigest()[:12]
    except Exception:
        _BUILD_FINGERPRINT = ""     # never fail a diagnosis over this
    return _BUILD_FINGERPRINT


def _session_age(s):
    """Wall-clock age of a session as a plain-English phrase, e.g. '3h 42m ago'."""
    stamp = s.get("updated") or s.get("created") or ""
    try:
        then = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return f"unknown age (timestamp {stamp or 'missing'})"
    secs = max(0, int((datetime.now(timezone.utc) - then).total_seconds()))
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    if days:
        phrase = f"{days}d {hours}h ago"
    elif hours:
        phrase = f"{hours}h {mins}m ago"
    else:
        phrase = f"{mins}m ago"
    return f"{phrase} ({stamp})"


def _build_changed(s):
    """True when this session was produced by a DIFFERENT build of the diagnostic code.

    Unknown (older session with no recorded build, or an unreadable script dir) is
    reported as False — we only claim staleness when we can actually see it, and say so
    in the message rather than implying certainty we do not have.
    """
    now = _build_fingerprint()
    was = s.get("build") or ""
    return bool(now and was and now != was)


# ---------------------------------------------------------------------------
# Intake: path classification + question synthesis
# ---------------------------------------------------------------------------

# Safety preamble (M2 / ROUND #1 safety-gate mitigation): the Genie Code safety
# classifier deny-by-defaults the FIRST run_network_doctor() cell (opaque fn +
# external host:port + sp_scope/account_id looks credential/privilege-shaped). A
# retry that LED with a safety-explaining comment passed. So every driver-emitted
# call cell now leads with this comment, and the printed instructions tell the
# agent to lead the cell with it too. Code reduces the deny FREQUENCY; deterministic
# zero-denials needs the platform allowlist (M3 escalation).
_SAFETY_PREAMBLE = (
    "# Safe: reads Databricks secrets by KEY NAME only (never values), runs read-only "
    "DNS/TCP probes + Azure ARM GETs via a Reader-scoped SP, and mutates nothing."
)


def _safe_cell(call):
    """Prefix a call string with the safety preamble comment on its own line."""
    return f"{_SAFETY_PREAMBLE}\n{call}"


# Progressive-disclosure routing (Approach C): every result names the reference
# doc the agent should open for the classified path, plus a one-line inline
# summary so the flow is robust even if Genie Code does not auto-read the file.
_REFERENCE_DOC = {
    "A": "reference/PATH_A_connectivity.md",
    "B": "reference/PATH_B_storage.md",
    "C": "reference/PATH_C_cluster_start.md",
}
_PATH_HINT = {
    "A": ("Path A (connectivity): driver runs DNS/TCP/TLS/routes/NSG/peering/PE; "
          "serverless=NCC layer, classic=VNet. See reference/PATH_A_connectivity.md."),
    "B": ("Path B (storage/UC access): driver traces the credential chain and runs "
          "storage checks network-before-RBAC. See reference/PATH_B_storage.md."),
    "C": ("Path C (cluster start/NHC/launch): driver runs the ARM diagnostic LIVE; if this "
          "runtime cannot reach ARM it guides the customer to enable egress and re-run (no "
          "offline mode); never bail to 'Databricks bug' before it runs. "
          "See reference/PATH_C_cluster_start.md."),
}


def _decorate(res, path_label):
    """Attach the routing fields to a result dict (idempotent).

    reference_doc names the path-specific doc to open; for IN_PROGRESS results we
    also prepend a one-line inline hint to next_step so the agent still has the
    path context even if the reference file is never read.
    """
    if not isinstance(res, dict):
        return res
    doc = _REFERENCE_DOC.get(path_label)
    if doc:
        res.setdefault("reference_doc", doc)
    hint = _PATH_HINT.get(path_label)
    if hint and res.get("status") == "IN_PROGRESS" and "reference_hint" not in res:
        res["reference_hint"] = hint
    return res


def _classify(problem_text):
    nhc = parse_nhc_error(problem_text or "")
    if nhc.get("is_nhc") or nhc.get("is_launch_failure"):
        return "C"
    low = (problem_text or "").lower()
    if _looks_like_storage_access_problem(problem_text or ""):
        return "B"
    return "A"

def _looks_like_storage_access_problem(problem_text):
    """Return True for UC/storage authorization failures.

    Keep this intentionally small: Path B is for storage access/authorization.
    Plain "storage timed out on 443" remains Path A unless the prompt also
    carries an access/permission or UC table/volume signal.
    """
    low = (problem_text or "").lower()
    has_access = any(sig in low for sig in _STORAGE_ACCESS_SIGNS)
    has_storage_context = any(sig in low for sig in _STORAGE_CONTEXT_SIGNS)
    has_strong_storage_error = any(sig in low for sig in _STORAGE_STRONG_SIGNS)
    has_decisive_storage_error = any(sig in low for sig in _STORAGE_DECISIVE_SIGNS)
    has_uc_table = bool(_UC_TABLE_RE.search(problem_text or ""))
    has_compute_asymmetry = (
        "serverless" in low and "classic" in low
        and any(sig in low for sig in ("falha", "falhando", "fail", "fails", "funciona", "works"))
    )

    return (
        # A verbatim Azure authorization error needs nothing else to be believed.
        has_decisive_storage_error
        or (has_access and has_storage_context)
        or (has_strong_storage_error and (has_storage_context or has_uc_table))
        # A backticked 3-part `cat`.`schema`.`table` is a UC table/Volume identifier
        # by itself — never a network host (the backticks break _HOST_RE, so
        # _extract_target won't grab it). Presenting it as "the failing query" IS a
        # storage/UC-access signal, even without permission/storage keywords (T3).
        or has_uc_table
        or (has_compute_asymmetry and has_storage_context and has_access)
    )

def _extract_target(problem_text):
    host, port = "", 0
    for m in _HOST_RE.finditer(problem_text or ""):
        cand = m.group(1)
        # skip obvious non-targets that show up in error pastes
        if cand.lower().endswith((".html", ".json", ".py")):
            continue
        host, port = cand, int(m.group(2) or 0)
        break
    if not port:
        pm = _PORT_RE.search(problem_text or "")
        if pm:
            port = int(pm.group(1))
    return host, port

_SP_QUESTION = {
    "ids": ["sp_scope", "sp_tenant_key", "sp_client_key", "sp_secret_key", "sp_declined"],
    "question": (
        "To inspect the Azure infrastructure I need a Service Principal (Reader) stored in "
        "Databricks Secrets. What is the NAME of the scope? (e.g. `my-reader-sp`). "
        "If you don't have one yet, answer `create` and I'll walk you through making it "
        "(three CLI commands, values typed in your own terminal). Or answer `none` to skip "
        "the Azure inspection and continue with network probes only."
    ),
}

# THIRD BRANCH — `create`. Until now the credential ask offered exactly two exits: a
# scope name, or `none`, which declines the whole Azure layer. A customer who simply
# does not have a scope yet is the COMMON field case, and the wording pushed them onto
# the decline. The walkthrough that answers them has existed all along (reference/
# DIAGNOSTIC_MACHINERY.md "Scope-creation walkthrough"), but nothing in the relayed
# question pointed at it, so reaching it depended on the LLM remembering it was there.
# The driver now owns that branch: `create` is an ANSWER, it keeps the ask open, and the
# walkthrough text is emitted from here so it is relayed verbatim like every other
# question. `create` must never fold into `sp_declined` — declining is a different
# answer with a different consequence.
_SP_SETUP_TOKENS = ("create", "criar", "setup", "new", "novo", "help", "ajuda")
_SP_SETUP_PHRASES = ("don't have", "dont have", "do not have", "não tenho", "nao tenho",
                     "no scope", "sem scope", "how do i", "how can i", "walk me through",
                     "set up", "set it up", "guide me")
_SP_SETUP_FLAG = "sp_setup_requested"
_SP_SETUP_DELIVERED = "_sp_setup_delivered"


def _is_scope_setup_request(value):
    v = _norm_ws(str(value or "")).strip().lower().strip("`.!?")
    if not v:
        return False
    return v in _SP_SETUP_TOKENS or any(p in v for p in _SP_SETUP_PHRASES)


def _scope_setup_question(account_layer=False):
    """The walkthrough, as a QUESTION so the ask stays open.

    Two flavours, because the ONE credential object is consumed by two layers that need
    two unrelated grants (see _ACCOUNT_CRED_QUESTION): Azure **Reader** for ARM reads,
    **account admin on the Databricks account** for the account layer. Handing the ARM
    wording to someone who needs the account layer is the same category error the two
    separate asks exist to prevent.
    """
    grant = (
        "The service principal itself must be an **account admin on your Databricks "
        "account** (accounts.azuredatabricks.net > User management > Service principals > "
        "your SP > Roles > Account admin). No Azure role grants this — an Azure Reader "
        "cannot read that layer."
        if account_layer else
        "If you don't have the service principal yet: Azure Portal > Microsoft Entra ID > "
        "App registrations > New registration, then add a client secret under "
        "Certificates & secrets, and have it granted **Reader** — subscription scope is "
        "best, Reader on the relevant resource groups also works. Reader is read-only; I "
        "never ask for write access."
    )
    return {
        "ids": ["sp_scope", "sp_declined", "sp_tenant_key", "sp_client_key", "sp_secret_key"],
        "question": (
            "No problem — here is how to create it. Run these in YOUR OWN terminal, where "
            "the Databricks CLI is signed in to this workspace. The credential values are "
            "typed at your local prompt and never pasted into this chat:\n"
            "```\n"
            "databricks secrets create-scope <scope-name>\n"
            "databricks secrets put-secret <scope-name> azure-tenant-id\n"
            "databricks secrets put-secret <scope-name> azure-client-id\n"
            "databricks secrets put-secret <scope-name> azure-client-secret\n"
            "databricks secrets list-secrets <scope-name>\n"
            "```\n"
            f"{grant}\n"
            "When the scope exists, reply with just its NAME — I read the values by key "
            "name, never in chat. If you'd rather not create one (no CLI access, or your "
            "platform team owns it), answer `none` and I'll carry on without the Azure "
            "inspection and tell you honestly what that leaves unproven."
        ),
    }

# ---------------------------------------------------------------------------
# How deep should this go? — the fork asked BEFORE any credential
# ---------------------------------------------------------------------------
# A customer who has just described a problem does not know that "diagnose it" can
# mean two very different amounts of work on THEIR side. The engine has always had
# both, but the only route to the cheap one was to answer `none` to two questions
# worded as requirements — so the common field case (no service principal to hand,
# wants an answer now) was reached by DECLINING, which reads like losing something.
# Nothing in the conversation ever said the choice existed.
#
#   simple — everything that needs no Azure credential: DNS / TCP / TLS probes run
#            from inside the workspace (on classic, from inside the VNet, on a
#            cluster), the Databricks-side configuration, and the serverless egress
#            verdict. Answers "is the path open, and where does it stop?"
#   deep   — all of the above PLUS the Azure configuration itself: NSGs, route
#            tables, VNet peering, the hub firewall, Private Endpoints, Private DNS.
#            Answers "which Azure object is responsible, and what exactly to change."
#            Needs a read-only service principal in a Databricks secret scope.
#
# Path C is deliberately NOT asked. A cluster that will not start is diagnosed from
# the workspace's ARM configuration and nothing else, so there is no credential-free
# version of it to offer — a customer without a service principal is handed the Cloud
# Shell dump flow instead (_stage_C), which reads ARM under their OWN identity.
# Offering "simple" there would promise less work and then ask for more.
_DEPTH_DEEP_TOKENS = ("deep", "full", "complete", "completa", "completo", "profunda",
                      "profundo", "detalhada", "detailed", "thorough", "everything",
                      "second", "segunda", "segundo", "option 2", "opcao 2", "op\u00e7\u00e3o 2")
_DEPTH_SIMPLE_TOKENS = ("simple", "simples", "quick", "rapida", "r\u00e1pida", "rapido",
                        "r\u00e1pido", "basic", "basica", "b\u00e1sica", "fast", "light",
                        "shallow", "none", "skip", "no credential", "no service principal",
                        "without credential", "sem credencia", "nao tenho credencia",
                        "n\u00e3o tenho credencia", "not have credential",
                        "have no credential", "first", "primeira", "primeiro",
                        "option 1", "opcao 1", "op\u00e7\u00e3o 1")
# A bare digit is answered often enough to accept, but only as the WHOLE answer — as a
# substring it would match a port number or an id.
_DEPTH_ORDINALS = {"1": "simple", "2": "deep"}
# ONE bound for every intake ask, counting REPLIES THAT DID NOT ANSWER — which is
# neither turns nor calls. Both of the other two ways were tried and both were wrong:
#
#   Counting CALLS burned asks the customer never saw. The driver is re-invoked for
#   reasons that have nothing to do with them — the relay runs the next-step cell without
#   answers, a safety-gate denial is retried, the kernel restarts — so three no-answer
#   calls flipped a `deep` run to `simple` and marked the credential refused, after
#   asking exactly once.
#
#   Counting the ARRIVAL of a value under the expected key (all `_normalize_answers` can
#   see, since it gets the merged dict) missed the opposite failure: a reply that lands
#   under ANOTHER key, or empty, increments nothing, so the question came back every turn
#   forever. Eight replies of {"compute_type": "classic"} to the depth question left it
#   still NEED_INPUT on the depth question.
#
# So the driver remembers which question it emitted; if a reply arrives and the SAME
# question is still pending, that reply failed to answer it. Counted at the emit site,
# for the reason CLAUDE.md records: `_normalize_answers` sees only the incoming delta.
_ASK_COUNTS = "_ask_counts"
_LAST_ASKED = "_last_asked"
_MAX_UNANSWERED_ASKS = 2
# Exactly what `simple` switched off, so a later `deep` switches back on that and
# nothing else — it must never revoke a decline the customer made deliberately.
_DEPTH_AUTO_DECLINED = "_depth_auto_declined"


def _read_depth(value):
    """`"deep"`, `"simple"`, or `""` when the answer does not decide anything."""
    v = _norm_ws(str(value or "")).strip().lower().strip("`.!?*\"'")
    if not v:
        return ""
    if v in _DEPTH_ORDINALS:
        return _DEPTH_ORDINALS[v]
    # WHICH WORD CAME FIRST decides, because both words turn up in one answer often and
    # the second one is usually the qualifier. Scanning one whole list before the other
    # read "simple, not the deep one" as `deep` — and then asked for a credential the
    # customer had just refused in the same sentence.
    choice, earliest, negated = "", len(v) + 1, ""
    for depth, tokens in (("deep", _DEPTH_DEEP_TOKENS), ("simple", _DEPTH_SIMPLE_TOKENS)):
        for tok in tokens:
            at = 0
            while True:
                at = v.find(tok, at)
                if at == -1:
                    break
                # "no deep dive, keep it simple" names `deep` FIRST and means the
                # opposite. A negated match is not a choice: skip it and keep scanning,
                # so the word the customer actually asked for still wins on position.
                if not _negated_before(v, at):
                    if at < earliest:
                        choice, earliest = depth, at
                    break
                negated = negated or depth
                at += len(tok)
    # "nothing too deep" / "don't do the full read" name only the option they are
    # refusing. Refusing one of two is choosing the other, and it beats re-asking a
    # customer who already told us.
    if not choice and negated:
        return "simple" if negated == "deep" else "deep"
    return choice


_DEPTH_NEGATIONS = ("no", "not", "n't", "dont", "don't", "nao", "n\u00e3o", "sem",
                    "nothing", "never", "skip", "avoid", "without", "menos", "evite",
                    "nem")
# Two-word refusals that put distance between the negation and the noun, which the
# three-word look-back alone misses.
_DEPTH_NEGATION_PHRASES = ("dont do", "don't do", "do not do", "no need", "nao precisa",
                           "n\u00e3o precisa", "nao quero", "n\u00e3o quero", "rather not",
                           "instead of")


def _negated_before(text, at):
    """Is the token at `at` being refused rather than chosen?

    Looks at the three words immediately before it, plus a few two-word refusals that
    put distance between the negation and the noun ("don't do the full read", "n\u00e3o
    precisa a an\u00e1lise completa"). A plain CHARACTER window was tried first and was
    worse than nothing: in "no deep dive, keep it simple" a 22-character look-back
    reached the `no` belonging to `deep` and negated `simple` too, so an answer that is
    obvious to a human decided nothing.
    """
    before = text[:at]
    words = [w.strip(",;:.!?()-") for w in before.split()]
    if any(w in _DEPTH_NEGATIONS for w in words[-3:]):
        return True
    return any(p in " ".join(words[-4:]) for p in _DEPTH_NEGATION_PHRASES)


def _read_depth(value):
    """`"deep"`, `"simple"`, or `""` when the answer does not decide anything.

    This is a free-text answer from a human, relayed by a model, so it arrives as
    anything from "deep" to "n\u00e3o precisa a an\u00e1lise completa, faz a simples".
    Three rules, in this order:

    1. A REFUSED option is not a chosen one. Reading "no deep dive, keep it simple" as
       `deep` then asked for the credential the customer had declined in the same breath.
    2. Refusing one of two options chooses the other — better than re-asking someone who
       has already told us.
    3. When both options are named, neither is refused, and the sentence still carries a
       negation, GUESS NOTHING. Returning "" costs one short re-ask (which exists for
       exactly this) and is far cheaper than sending them down the path they rejected.
    """
    v = _norm_ws(str(value or "")).strip().lower().strip("`.!?*\"'")
    if not v:
        return ""
    if v in _DEPTH_ORDINALS:
        return _DEPTH_ORDINALS[v]
    chosen, refused = {}, {}
    for depth, tokens in (("deep", _DEPTH_DEEP_TOKENS), ("simple", _DEPTH_SIMPLE_TOKENS)):
        for tok in tokens:
            at = v.find(tok)
            while at != -1:
                if _negated_before(v, at):
                    refused.setdefault(depth, at)
                    at = v.find(tok, at + len(tok))
                    continue
                if depth not in chosen or at < chosen[depth]:
                    chosen[depth] = at
                break
    if len(chosen) == 1:
        return next(iter(chosen))
    if not chosen:
        if len(refused) == 1:
            return "simple" if "deep" in refused else "deep"
        return ""
    # Both named and neither refused. A negation somewhere in the sentence means it is
    # doing work we cannot locate, so the earliest word is not evidence of intent.
    if any(w.strip(",;:.!?()-") in _DEPTH_NEGATIONS for w in v.split()):
        return ""
    return min(chosen, key=chosen.get)


def _depth_question(a, path="A"):
    """Both options, with what each one costs the customer, and every claim true.

    Relayed verbatim like every other question, so this text IS what a customer reads.
    Three things it must not do, all of which the first version did:

    * promise that `simple` needs "nothing from you" — it still asks which compute and,
      on classic, for a cluster to probe from (the in-VNet probes are the reason `simple`
      is worth anything, and they need one). What `simple` costs nothing IN is credentials.
    * imply the deeper checks can be picked up in the SAME session afterwards. They
      cannot: a finished session re-serves its stored result, so upgrading is a fresh run.
    * describe `simple` the same way on Path B. There is no DNS/TCP/TLS suite there —
      without a credential the storage account's firewall, perimeter and role assignments
      are all unreadable, so `simple` on a storage error frequently ends without naming a
      cause. Saying otherwise sells an answer the run cannot produce.
    """
    if int((a.get(_ASK_COUNTS) or {}).get("analysis_depth") or 0) >= 1:
        # They answered something we could not read. Ask shorter, not louder — and say
        # this is the last ask, because _normalize_answers assumes `deep` after it.
        return {"ids": ["analysis_depth"], "question": (
            "Sorry — I need one of two words. `simple` = I check what I can reach without "
            "any Azure credential. `deep` = I also read your Azure network configuration, "
            "to name the exact object at fault; for that I need your workspace's Azure "
            "resource id and a read-only service principal. Which one — `simple` or "
            "`deep`? (If you'd rather not choose, I'll assume `deep` and you can still "
            "answer `none` to anything I ask for.)")}
    if path == "B":
        simple = (
            "**`simple`** — no Azure credential needed. I trace the Unity Catalog side of "
            "this: the table, its external location, the storage credential and the access "
            "connector behind it. Worth knowing what that cannot see — the storage "
            "account's own firewall, its network perimeter and its Azure role assignments "
            "are all read from Azure, so on a storage error `simple` often finishes "
            "without naming a cause. It will tell you exactly what it ruled out and what "
            "it could not.")
        deep = (
            "**`deep`** — the above plus the Azure side, which is usually where a storage "
            "error is decided: the storage account's firewall and private endpoints, its "
            "network perimeter, the role assignments, and whether a firewall in your "
            "network is dropping the traffic before it arrives. This is what names the "
            "cause. It needs your workspace's Azure resource id and a **read-only** "
            "service principal stored in a Databricks secret scope.")
    else:
        simple = (
            "**`simple`** — no Azure credential needed. I test the network path itself: "
            "whether the name resolves, whether the port answers, whether TLS completes, "
            "plus the Databricks-side configuration. I do still need a couple of facts — "
            "which compute, and on classic the id of a running cluster to probe FROM (that "
            "is what makes the test happen inside your own network — a single-node cluster "
            "you start is enough, and you can also decline). It tells you whether the path "
            "is open and where it stops.")
        deep = (
            "**`deep`** — all of that, plus your Azure network configuration: firewall "
            "rules, routing, network security groups, peering, private DNS and private "
            "endpoints. This is what names the exact object at fault and the change to "
            "make. On top of the questions above it needs your workspace's Azure resource "
            "id and a **read-only** service principal stored in a Databricks secret "
            "scope.")
    return {"ids": ["analysis_depth"], "question": (
        "Before I start, one choice — how far should I go?\n\n"
        f"{simple}\n\n"
        f"{deep}\n\n"
        "If you don't have a service principal, say so and I'll give you the commands to "
        "create one — I only ever need the NAME of the secret scope, never the values.\n\n"
        "Answer `simple` or `deep`. `simple` is a real answer, not a half-measure: the "
        "report names every layer it could not check. You can run the deep analysis later "
        "once the credential exists — that is a fresh run, so I would ask these few "
        "questions again.")}


# The ONE credential object the intake collects (an Entra service principal in a
# Databricks secret scope) is consumed by TWO layers that need TWO UNRELATED grants:
#
#   ARM (management.azure.com)          -> Azure **Reader**
#       the classic-plane graph: VNet, subnets, NSGs, routes, peering, hub firewall,
#       plus a target Azure resource's own firewall / private endpoints.
#   Databricks ACCOUNT API              -> **account admin on the Databricks account**
#       (accounts.azuredatabricks.net)     the NCC and the serverless network policy —
#       i.e. the layer that actually governs serverless egress.
#
# Asking the ARM question on a serverless-only run was a category error twice over:
# every classic-plane check plane-skips (models.classic_plane_skip), so ARM buys
# nothing; and the prompt asked for Reader while the layer that answers the question
# (`egress_policy`) refuses any principal that is not an account admin. A customer who
# granted exactly what we asked for got HTTP 403 on the only read that mattered
# (surfaced by a live smoke test on `%pip install` from pypi.org).
#
# So the two asks are now separate questions with separate wording, each gated on the
# layer that actually consumes it.
_ACCOUNT_CRED_QUESTION = {
    "ids": ["sp_scope", "account_id", "account_declined", "sp_tenant_key",
            "sp_client_key", "sp_secret_key"],
    "question": (
        "To name the exact policy and give you the exact fix I need to read your "
        "Databricks ACCOUNT configuration — the serverless network policy attached to "
        "this workspace, whose egress allow-list is what decides whether serverless "
        "compute may reach this destination. Two things in one answer: (1) the NAME of the Databricks Secrets "
        "scope holding a service principal that is an **account admin on your Databricks "
        "account** (this is a Databricks account grant — Azure Reader is NOT what it "
        "needs, and no Azure permission helps here), and (2) your Databricks **account "
        "id** (the UUID in the URL once you sign in to accounts.azuredatabricks.net). "
        "If you don't have such a scope yet, answer `create` and I'll walk you through "
        "making it. Or answer `none` and I'll stand on the probe evidence I already have."
    ),
}

# Serverless + a destination that IS an Azure resource (ADLS, Azure SQL, MySQL): here,
# and ONLY here, a serverless run has something to read in ARM — the target resource's
# own firewall and private-endpoint posture. A package index or an external API has no
# Azure resource behind it, so the ARM layer is switched off entirely for those.
def _serverless_target_is_azure_resource(answers):
    host = str((answers or {}).get("target_host") or "")
    if not host:
        return False
    try:
        port = int((answers or {}).get("target_port") or 443)
    except (TypeError, ValueError):
        port = 443
    rtype, _group, _name = _infer_resource_type(host, port)
    return not str(rtype).startswith("unknown")


def _governing_layer_phrase(answers):
    """WHICH account-layer object governs egress to THIS destination.

    Getting this wrong is not cosmetic. The NCC is a private-endpoint mechanism: its
    rules name an Azure resource id and a group id, so it decides how serverless reaches
    an AZURE RESOURCE privately. It says nothing about whether serverless may reach a
    PUBLIC host — that is the serverless network policy's egress allow-list. Live
    In the field a `%pip install` case against pypi.org was correctly diagnosed as the
    network policy's allow-list, and the surrounding prose still called the layer "the
    NCC and the serverless network policy" throughout; the customer's reading was "there
    is nothing NCC-related in this case", and they were right.
    """
    if _serverless_target_is_azure_resource(answers):
        return ("the NCC's private-endpoint rules and the serverless network policy's "
                "egress allow-list")
    return "the serverless network policy attached to this workspace (its egress allow-list)"


def _sp_refs(answers):
    if not answers.get("sp_scope"):
        return None
    return {
        "scope": answers["sp_scope"],
        "tenant_id_key": answers.get("sp_tenant_key", "azure-tenant-id"),
        "client_id_key": answers.get("sp_client_key", "azure-client-id"),
        "client_secret_key": answers.get("sp_secret_key", "azure-client-secret"),
    }

# A storage endpoint the customer can name even when they cannot name the table:
# `acct.dfs.core.windows.net`, `abfss://container@acct.dfs.core.windows.net/path`,
# or the bare account name. Path B treats any of these as a first-class target.
_STORAGE_HOST_RE = _re.compile(
    r"\b([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.(dfs|blob|z\d+\.dfs|z\d+\.blob)\.core\.windows\.net\b",
    _re.IGNORECASE)
_STORAGE_ACCOUNT_NAME_RE = _re.compile(r"^[a-z0-9]{3,24}$")


def _implausible_table(value):
    """Is `value` structurally impossible as a Unity Catalog table/volume name?

    Field experience: asked for the failing table, the customer answered like a
    real person — "I don't have the exact table name to hand right now ... the external
    location points at our storage account <acct>, and the host is
    <acct>.dfs.core.windows.net. Can you work from that?" The whole SENTENCE was
    stored as `full_table`, the UC API returned HTTP 400, and the run aborted: zero
    checks, no report, no diagnoses. The two facts the storage checks actually need had
    already been supplied and were thrown away.

    Same shape of guard as `_implausible_target`: validate POSITIVELY (a UC name is
    1-3 dot-separated identifiers, no whitespace, no sentence punctuation) instead of
    blocklisting the improvisations we have already seen. Returns a reason string when
    the value must be rejected as a table name, else "".
    """
    v = (value or "").strip()
    if not v:
        return ""
    if any(ch in v for ch in " \t\n"):
        return "the answer is free text (a sentence), not a catalog.schema.table identifier"
    if any(ch in v for ch in ",;?!\"'"):
        return "the answer contains sentence punctuation, so it is not a table identifier"
    if _STORAGE_HOST_RE.search(v) or v.lower().startswith(("abfss://", "abfs://", "https://")):
        return f"'{v[:60]}' names a storage endpoint, not a Unity Catalog table"
    parts = [p for p in v.replace("`", "").split(".") if p != ""]
    if not 1 <= len(parts) <= 3:
        return f"'{v[:60]}' has {len(parts)} dot-separated parts — a UC name has 1-3"
    for part in parts:
        if not _re.match(r"^[A-Za-z0-9_\-]+$", part):
            return f"'{part[:40]}' is not a valid Unity Catalog identifier"
    return ""


def _storage_ref_from_text(text):
    """Pull a storage account + host out of free text. Returns (account, host).

    Deliberately reads the customer's own words rather than demanding a re-answer:
    the host and the account are exactly what the storage checks need, and in that case the
    customer had already written both in the sentence we rejected.
    """
    t = str(text or "")
    m = _STORAGE_HOST_RE.search(t)
    if m:
        return m.group(1), m.group(0)
    # "our storage account <acct>" / "storage account: <acct>"
    m = _re.search(r"storage\s+account\s*(?:name\s*)?[:=]?\s*`?([a-z0-9]{3,24})`?", t, _re.IGNORECASE)
    if m:
        return m.group(1).lower(), ""
    return "", ""


def _storage_target_from_answers(a):
    """(account, host) for a Path B target given only an account and/or a host."""
    host = str(a.get("storage_host") or "").strip()
    account = str(a.get("storage_account") or "").strip().lower()
    if host and not account:
        m = _STORAGE_HOST_RE.search(host)
        account = m.group(1).lower() if m else ""
    if account and not host:
        host = f"{account}.dfs.core.windows.net"
    return account, host


def _implausible_target(host, answers):
    """Is `host` structurally impossible as a customer's network target?

    Field experience: the agent was given the workspace ARM id and called the driver
    with `target_host='Microsoft.Databricks'` — the ARM PROVIDER NAMESPACE. Nothing caught
    it, so the whole diagnosis ran against a hostname that cannot exist: DNS failed with
    "Name or service not known", which SKIPPED the NSG and route checks ("DNS failed — no
    resolved IP"), and the customer was handed a report headed
    `Microsoft.Databricks:443 — FAIL` naming a host they had never mentioned, with a
    high-severity DNS diagnosis and a checklist telling them to go fix Private DNS zones
    and port-53 NSG rules.

    The prior guard only recognised the sentinel words ('setup', 'none', 'n/a', 'nothing'),
    i.e. a BLOCKLIST of the improvisations already seen. `Microsoft.Databricks` even
    contains a dot, so shape alone does not save us. Validate positively instead, and note
    that resolvability is NOT a usable test: a customer's genuinely-unresolvable on-prem
    host is a legitimate Path A target and the thing we are often asked to diagnose.

    Returns a reason string when the value must be rejected, else "".
    """
    h = (host or "").strip()
    if not h:
        return ""
    if _re.match(r"^Microsoft\.[A-Za-z0-9]+$", h):
        return f"'{h}' is an Azure resource-provider namespace, not a hostname"
    if any(ch in h for ch in " \t/\\"):
        return f"'{h}' contains characters a hostname cannot contain"
    if "." not in h and ":" not in h:
        return f"'{h}' is a single label with no domain — not a reachable target"
    # A segment lifted out of an ARM id the customer pasted (provider, RG, workspace name…).
    for key in ("workspace_arm_id", "storage_arm_id", "arm_id"):
        arm = str((answers or {}).get(key) or "")
        if arm and h.lower() in [seg.lower() for seg in arm.split("/") if seg]:
            return f"'{h}' is a segment of the ARM resource id, not a hostname"
    return ""


_HOST_SENTINELS = ("setup", "none", "n/a", "nothing", "classic")


def _canonicalize_hostname(host):
    """Strip URL chrome so a pasted workspace URL is a hostname, not a reject.

    `https://adb-123.4.azuredatabricks.net/?o=…` used to fail `_implausible_target`
    (it contains `/`) and get rewritten to `setup`, which is how a customer who
    DID name the workspace still fell into the empty-context audit loop.
    """
    h = str(host or "").strip().strip("`\"'")
    if not h:
        return ""
    low = h.lower()
    if low.startswith("https://") or low.startswith("http://"):
        rest = h.split("://", 1)[1]
        h = rest.split("/")[0].split("?")[0]
    return h.strip().strip("/")


def _split_host_port(host):
    """Return (hostname, port_or_\"\") from `host` or `host:port` (not IPv6)."""
    h = _canonicalize_hostname(host)
    if h.count(":") == 1:
        left, right = h.rsplit(":", 1)
        if right.isdigit():
            return left, right
    return h, ""


def _current_user_email():
    try:
        return _get_spark().sql("SELECT current_user()").collect()[0][0]
    except Exception:
        return os.environ.get("USER") or ""


def _normalize_answers(s):
    """Fold the plain-language 'no' answers into the canonical decline flags, so the
    customer can just type `none` instead of having to know the `*_declined=true` key.
    Also normalizes the cluster answer: `create` is kept verbatim (provisioning is
    handled at stage time); a running id stays as-is; `none`/`no` clears it.
    """
    a = s["answers"]
    # DEPTH is the first fork, so it is normalized first: everything below is allowed to
    # override it, because what the customer supplied LAST is what they mean.
    if s.get("path") == "C":
        # Not a choice on Path C — there is no credential-free cluster-start diagnosis to
        # offer (see _depth_question). Set explicitly so the question is never asked and
        # nothing downstream reads an empty depth as "not decided yet".
        a["analysis_depth"] = "deep"
    if not a.get("analysis_depth") and s.get("checkpoint_path"):
        # A session that already has recorded work predates this question (or was mid-run
        # when it landed). Asking "how far should I go?" halfway through a diagnosis is
        # noise, so infer what the run in fact had rather than dragging it back to intake.
        a["analysis_depth"] = "deep" if _sp_refs(a) else "simple"
    _depth = _read_depth(a.get("analysis_depth"))
    if _depth:
        a["analysis_depth"] = _depth
    elif "analysis_depth" in a:
        # An answer that decides nothing must not read as answered, or the intake would
        # walk on with an undefined depth. Bounding this is the emit site's job
        # (_bound_intake_asks): from here the answer that never arrived is invisible.
        a.pop("analysis_depth", None)
    if a.get("analysis_depth") == "simple":
        # `simple` is not a decline of something the customer was asked for; it is a
        # choice that removes those asks. It therefore has to SET the flags, or the
        # intake would keep asking for the very credentials simple does not use.
        _auto = list(a.get(_DEPTH_AUTO_DECLINED) or [])
        if not a.get("sp_scope") and not a.get("sp_declined"):
            a["sp_declined"] = True
            _auto.append("sp_declined")
        if (not str(a.get("workspace_arm_id") or "").startswith("/subscriptions/")
                and not a.get("workspace_arm_declined")):
            a["workspace_arm_declined"] = True
            _auto.append("workspace_arm_declined")
        if _auto:
            a[_DEPTH_AUTO_DECLINED] = sorted(set(_auto))
    elif a.get("analysis_depth") == "deep":
        # Upgrading back: clear ONLY what `simple` set, never a deliberate `none`. The
        # ask budget goes too — the flags saying "deep is on again" and a counter saying
        # "exhausted" would disagree, and the credential question would be skipped
        # without ever being put to the customer.
        # Only on the TRANSITION out of `simple`. `_normalize_answers` runs on every
        # call, so resetting unconditionally meant the credential budget was wiped every
        # turn of a `deep` run and the ask could never reach its bound — the loop this
        # whole mechanism exists to stop. The gate caught it; `_depth_auto_declined` is
        # present only while `simple` is what set the flags, so it marks the edge.
        _was_simple = bool(a.get(_DEPTH_AUTO_DECLINED))
        for _flag in (a.pop(_DEPTH_AUTO_DECLINED, None) or []):
            a.pop(_flag, None)
        if _was_simple:
            _counts = dict(a.get(_ASK_COUNTS) or {})
            if _counts.pop("sp_scope", None) is not None:
                a[_ASK_COUNTS] = _counts
            a.pop(_CREDENTIAL_REFUSED, None)
    # `create` on the CREDENTIAL ask is the third branch, not a decline: flag it and leave
    # the ask open so `_maybe_scope_setup` can hand over the creation walkthrough.
    if _is_scope_setup_request(a.get("sp_scope")):
        a.pop("sp_scope", None)
        a.pop("sp_declined", None)
        a[_SP_SETUP_FLAG] = True
    if str(a.get("sp_scope", "")).strip().lower() in ("none", "no", "não", "nao", "n/a"):
        a.pop("sp_scope", None)
        a.pop(_SP_SETUP_FLAG, None)
        a["sp_declined"] = True
    _acct = str(a.get("account_id", "")).strip()
    if _acct.lower() in ("none", "no", "não", "nao", "n/a", "skip"):
        a.pop("account_id", None)
        a["account_declined"] = True
    elif _acct and not _ACCOUNT_ID_RE.match(_acct):
        # Not a UUID and not a decline. Keeping it would send "I need to ask our admin" to
        # the account API as an id and blame the failure on the customer's account.
        a.pop("account_id", None)
        a["_account_id_unparsed"] = _acct[:120]
    # A DECLINE IS NOT PERMANENT. `sp_declined` used to be write-once — nothing anywhere
    # cleared it — so a customer who answered `none`, went off and created the scope, and
    # came back with its name was still treated as having no credential: the intake stopped
    # re-asking (`_all_missing_questions`), the serverless account offer stayed suppressed
    # (`_serverless_account_offer`), and Path B took its "cannot determine root cause
    # without a Reader SP" branch while holding a perfectly good scope. That journey is the
    # whole point of the `create` branch, so it has to survive the round trip. What the
    # customer supplied LAST is what they mean.
    if a.get("sp_scope"):
        a.pop("sp_declined", None)
        a.pop(_SP_SETUP_FLAG, None)
        a.pop(_SP_SETUP_DELIVERED, None)
        # Handing over a credential IS the upgrade, so it has to undo the whole of what
        # `simple` switched off — not just the credential half. Clearing `sp_declined`
        # alone left `workspace_arm_declined` set and the run still labelled `simple`:
        # the ARM-id question never came back, so the topology egress trace (the layer
        # that finds a hub firewall dropping the traffic) could not run. The customer had
        # followed the scope-creation walkthrough precisely to get that answer.
        if "workspace_arm_declined" in (a.get(_DEPTH_AUTO_DECLINED) or []):
            a.pop("workspace_arm_declined", None)
        if a.get("analysis_depth") == "simple":
            a["analysis_depth"] = "deep"
            a.pop(_DEPTH_AUTO_DECLINED, None)
            a.pop(_CREDENTIAL_REFUSED, None)
    if a.get("account_id"):
        a.pop("account_declined", None)
    # `both` IS NOT A PLANE. Classic egresses through the customer's VNet; serverless
    # never touches it and is governed by the Databricks account's network policy. A single
    # run that accepted "both" had to pick one set of probes anyway, so it attributed
    # evidence from one network to a question about the other — the exact error the
    # plane-scoped checks exist to prevent. One diagnosis, one plane; the customer runs a
    # second one for the other. Dropped rather than guessed, and remembered so the re-ask
    # can explain itself instead of looking like the same question again.
    if str(a.get("compute_type", "")).strip().lower() in _COMPUTE_BOTH_TOKENS:
        a.pop("compute_type", None)
        a["_compute_both_answered"] = True
    cid = str(a.get("cluster_id", "")).strip()
    if cid.lower() in ("none", "no", "não", "nao", "n/a", "skip"):
        a["cluster_id"] = "none"
    elif cid and not a.get("_cluster_id_autodetected") and not _CLUSTER_ID_RE.match(cid):
        # Not an id and not a decline: the customer said something else — most often that
        # they are off creating the cluster we just told them to create. Dropping it keeps
        # the ask open so they can come back with the real id, instead of the id field
        # holding prose that the probe dispatch would carry to the Command Execution API.
        a.pop("cluster_id", None)
        a["_cluster_id_unparsed"] = cid[:120]
    # A customer who realises the problem is actually on CLASSIC (not serverless) can reply
    # `classic` to the serverless target question — switch the compute and re-ask.
    if str(a.get("target_host", "")).strip().lower() == "classic":
        a["compute_type"] = "classic"
        a.pop("target_host", None)
        a.pop("_serverless_control_plane_redirect", None)
    # Paste of `https://adb-….azuredatabricks.net/…` used to be rejected as containing
    # `/` and rewritten to `setup`, which then looped when workspace context was empty.
    _host_in = str(a.get("target_host") or "").strip()
    if _host_in and _host_in.lower() not in _HOST_SENTINELS:
        _canon, _port = _split_host_port(_host_in)
        if _canon:
            a["target_host"] = _canon
        if _port and not str(a.get("target_port") or "").isdigit():
            a["target_port"] = _port
        if _canon.lower().endswith(".azuredatabricks.net"):
            a["_target_is_workspace_audit"] = True
        a.pop("_workspace_audit_unresolved", None)
    # "Audit my setup" intake: a customer validating a workspace before onboarding has
    # NO failing host, but Path A cannot run without a target. Rather than dead-ending
    # (or leaving the model to improvise a target, as it did in the field), accept
    # `setup` and validate the workspace's own control-plane endpoint — which exercises
    # the real egress path: DNS -> NSG -> routes -> peering -> hub firewall.
    _raw_host = str(a.get("target_host") or "").strip()
    if _raw_host.lower() not in _HOST_SENTINELS:
        _bad_target = _implausible_target(a.get("target_host"), a)
        if _bad_target:
            print(f"[Doctor] target_host rejected — {_bad_target}. Falling back to the "
                  f"workspace's own control-plane endpoint rather than diagnosing a target "
                  f"that cannot exist.")
            a["target_host"] = "setup"
            a["_target_was_rejected"] = _bad_target
    if str(a.get("target_host", "")).strip().lower() in ("setup", "none", "n/a", "nothing"):
        # The workspace-audit fallback is a CLASSIC path: a classic cluster in the VNet
        # really egresses DNS -> NSG -> routes -> peering -> hub firewall to reach the
        # control plane. Serverless does NOT — it runs in the Databricks-managed serverless
        # plane and reaches the control plane over Databricks-managed networking, which does
        # not fail the way in-VNet compute can and is not a customer-diagnosable surface. So
        # on serverless a workspace/control-plane "audit" is a category error: it would probe
        # a path that always succeeds and measures nothing. Redirect to the real EGRESS
        # target instead of auditing the workspace host.
        if a.get("compute_type") == "serverless":
            a.pop("target_host", None)
            a["_serverless_control_plane_redirect"] = True
        elif a.get("_workspace_audit_unresolved"):
            # Already tried auto-detect and it returned empty. Re-answering `setup`
            # must NOT silently drop the host and re-ask the identical question
            # (an infinite intake loop, seen in a real deployment). Keep the host empty so the
            # recovery question fires instead.
            a.pop("target_host", None)
        else:
            ws_host = ""
            try:
                ws_host = (get_workspace_context() or {}).get("workspace_url", "")
            except Exception:
                pass
            ws_host = _canonicalize_hostname(ws_host)
            if ws_host:
                a["target_host"] = ws_host
                a["_target_is_workspace_audit"] = True
                a.pop("_workspace_audit_unresolved", None)
            else:
                a.pop("target_host", None)
                a["_workspace_audit_unresolved"] = True
                # NOTE: do not count attempts here. This function normalises the
                # INCOMING answers delta, not the accumulated session, so a counter
                # incremented here resets to 1 on every turn. The ask is counted at
                # the emit site in _drive_network_doctor, where the session persists.
                print("[Doctor] workspace audit requested but get_workspace_context() "
                      "returned no workspace_url — asking the customer for the workspace "
                      "hostname rather than re-asking the same destination question.")
    # Order-independent: if the compute turns out to be serverless AFTER a workspace audit
    # was already set up (compute answered on a later turn than the target), undo it and
    # redirect the same way — the category error does not depend on answer order.
    if a.get("compute_type") == "serverless" and a.get("_target_is_workspace_audit"):
        a.pop("target_host", None)
        a.pop("_target_is_workspace_audit", None)
        a["_serverless_control_plane_redirect"] = True
    # The port must ALWAYS be numeric: _stage_A does int(target_port). In the field
    # the agent answered the audit question by passing BOTH fields as
    # 'setup' ({'target_host': 'setup', 'target_port': 'setup'}), which would have
    # raised ValueError deep in the run. Coerce anything non-numeric to 443 rather than
    # letting a stray word crash the diagnostic.
    _p = str(a.get("target_port", "")).strip()
    if _p and not _p.isdigit():
        a["target_port"] = "443"
    if str(a.get("workspace_arm_id", "")).strip().lower() in ("none", "no", "não", "nao", "n/a"):
        a.pop("workspace_arm_id", None)
        a["workspace_arm_declined"] = True
    _normalize_storage_target(a)
    _autofill_runtime_answers(a)


def _normalize_storage_target(a):
    """Keep the Path B target usable: a storage ACCOUNT or HOST is a first-class target.

    a free-text sentence was accepted as `full_table`, the UC lookup 400'd and the
    whole run aborted — while the sentence itself contained the account and the host the
    storage checks need. So: reject an implausible table name the same way
    `_implausible_target` rejects an implausible host, and RESCUE the account/host from
    whatever the customer actually wrote instead of discarding it.
    """
    raw = str(a.get("full_table") or "").strip()
    if raw:
        bad = _implausible_table(raw)
        if bad:
            acct, host = _storage_ref_from_text(raw)
            a.pop("full_table", None)
            a["_table_rejected"] = bad
            if acct and not a.get("storage_account"):
                a["storage_account"] = acct
            if host and not a.get("storage_host"):
                a["storage_host"] = host
            if acct or host:
                print(f"[Doctor] That is not a table name ({bad}) — but it names a storage target, "
                      f"so I will diagnose `{host or acct}` directly instead of stopping.")
            else:
                print(f"[Doctor] That is not a table name ({bad}) and it names no storage account "
                      "either — I will ask for the storage account or the failing host.")
    # A storage account / host answered as an abfss URL, an FQDN, or with a sentence
    # around it: normalise both directions so either one is enough to run.
    for key in ("storage_account", "storage_host"):
        val = str(a.get(key) or "").strip()
        if not val:
            continue
        if val.lower() in ("none", "no", "n/a", "não", "nao"):
            a.pop(key, None)
            continue
        acct, host = _storage_ref_from_text(val)
        if not (acct or host) and key == "storage_account" and _STORAGE_ACCOUNT_NAME_RE.match(val.lower()):
            acct = val.lower()
        if acct:
            a["storage_account"] = acct
        if host:
            a["storage_host"] = host
    acct, host = _storage_target_from_answers(a)
    if acct:
        a["storage_account"] = acct
    if host:
        a["storage_host"] = host


def _autofill_runtime_answers(a):
    """Answer from the RUNTIME what we can, instead of asking the customer.

    Every intake question is a separate Genie turn, and each turn is a chance for the
    session to stall (observed in the field: a healthy-baseline run burned 5 turns
    and stalled 4 times, never reaching the diagnostic). Two of those answers are
    already sitting in the notebook context, so asking for them is pure risk:

      * `compute_type`  — `get_workspace_context()["is_serverless"]` (IMDS probe).
      * `cluster_id`    — the attached cluster's own id from the Spark conf.

    We only ever FILL A BLANK: an explicit customer answer always wins, so this
    cannot override someone telling us the problem is on the other plane. Failure to
    detect is silent by design — we simply fall back to asking.

    POSITIVE SIGNAL ONLY, and the signal must actually SEPARATE the planes.

    An earlier version of this inferred `classic` from the mere PRESENCE of
    `spark.databricks.clusterUsageTags.clusterId`. That was wrong: **serverless also
    populates that conf**, so a serverless session was labelled `classic` and its own
    serverless compute id was handed over as "the classic cluster to probe from". In a
    field run that made the probes measure the serverless plane while the report
    claimed to be diagnosing a classic VNet — which contributed to a confident
    `all_healthy` on a workspace whose peering had been deleted.

    IMDS is the signal that genuinely separates them (a real Azure VM answers on the
    link-local address; serverless does not). We only use it in the POSITIVE direction:
    IMDS reachable ⇒ classic. IMDS unreachable is NOT taken as serverless, because a
    classic cluster with filtered link-local egress would then be mislabelled — so in
    that case we detect nothing and simply ask. Being one question slower beats being
    silently wrong about the plane.
    """
    if not a.get("_runtime_probed"):
        a["_runtime_probed"] = True
        imds_classic = False
        try:
            import requests as _req
            _req.get("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                     headers={"Metadata": "true"}, timeout=2)
            imds_classic = True   # answered ⇒ real VM ⇒ classic compute
        except Exception:
            imds_classic = False  # says NOTHING conclusive — do not infer serverless
        # Record the OUTCOME, not just that we probed. `_ctx_for_A` needs to know whether the
        # runtime running these cells is a VNet VM, because that is what makes a
        # probe-vs-private-endpoint comparison sound (models.probes_measured_data_plane_vnet).
        # Reusing this single probe keeps it one network call, and keeps the IMDS
        # positive-only rule in exactly one place.
        a["_imds_classic"] = bool(imds_classic)
        if imds_classic:
            if a.get("compute_type") not in ("serverless", "classic"):
                a["compute_type"] = "classic"
                a["_compute_type_autodetected"] = True
            if a.get("compute_type") == "classic" and "cluster_id" not in a:
                try:
                    # Use the shared resolver, NOT SparkSession.getActiveSession() directly:
                    # from a module context getActiveSession() returns None (which is why
                    # _get_spark exists), so a direct call silently detects nothing.
                    cid_rt = _get_spark().conf.get(
                        "spark.databricks.clusterUsageTags.clusterId", "") or ""
                except Exception:
                    cid_rt = ""
                if cid_rt:
                    a["cluster_id"] = cid_rt
                    a["_cluster_id_autodetected"] = True


# The classic probes need a machine INSIDE the customer VNet, and the only such machine
# is one of their clusters. The doctor used to offer to create that cluster itself. It no
# longer does, and the reason is ownership, not capability: compute we create in someone
# else's workspace is compute we then owe them — it bills, it has to be waited for, it has
# to be torn down on every exit path including the crash ones, and a leak is our fault. So
# the ask names what to build and hands the choice back. Deleting the offer also deleted
# the defect that made this change urgent: `create` provisioned a cluster and did NOT wait
# for it, so the probes ran on this session instead and a serverless measurement was
# presented as the customer's VNet (in the field, 1 of 18 checks, `loc=None`).
_CLUSTER_QUESTION = (
    "The network probes have to run from INSIDE your workspace VNet, which means running "
    "them on one of your classic clusters. Do you have one running?\n"
    "- Paste its **cluster id** — it looks like `0903-123456-abc12345`. You will find it in "
    "Compute, or at the end of the cluster's URL.\n"
    "- If none is running, **start or create one** and come back with the id: Compute > "
    "Create compute > **Single node**, smallest node type, any runtime, and set "
    "**Terminate after 20 minutes** so it cannot be forgotten. Nothing needs to be "
    "installed on it. I do not create compute in your workspace — it would bill you and it "
    "would be mine to clean up, so the cluster stays yours.\n"
    "- `none` — skip the in-VNet probes. Everything that does not need one still runs, and "
    "the report names exactly which layers that leaves unverified.")

def _cluster_question(a):
    """The cluster ask, prefixed with an acknowledgement when the last reply was not an id.

    Re-showing an identical question reads as the driver not having heard the customer, and
    this ask now invites non-answers by design (it sends them off to build something). So
    the re-ask says what came back and what is still needed.
    """
    unparsed = str((a or {}).get("_cluster_id_unparsed") or "").strip()
    if not unparsed:
        return _CLUSTER_QUESTION
    return ("I could not read a cluster id in that (`" + unparsed + "`), so I have not "
            "started the probes. If the cluster is still coming up, take your time and send "
            "the id when it is running.\n\n" + _CLUSTER_QUESTION)


# What a Databricks cluster id looks like. The ask is the one place where a reply that is
# not an answer is EXPECTED — "ok, creating it now", "still starting", "can you make one" —
# because the customer has been sent away to build something. Storing any of those as the
# cluster id sends a nonsense id to the Command Execution API and the probes then fall back
# to this session, which is the exact lie this change removes. So the answer is recognised
# by SHAPE, and anything else leaves the question open (bounded by _bound_intake_asks).
_CLUSTER_ID_RE = _re.compile(r"^[0-9]{4}-[0-9]{6}-[A-Za-z0-9_]{4,}$")

# The Databricks account id is a UUID, and this ask has the same two failure modes the
# cluster ask had: a reply that is not an id gets stored AS the id (the account read then
# fails with an error that reads like the customer's configuration is wrong), and a reply
# that lands under another key leaves the question pending forever. This ask is emitted
# from _maybe_reopen_for_account_layer, OUTSIDE _missing_questions, so the intake bound
# never saw it — the third instance of the unbounded-ask class CLAUDE.md records.
_ACCOUNT_ID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", _re.IGNORECASE)

_COMPUTE_BOTH_TOKENS = ("both", "ambos", "os dois", "as duas", "todos", "todas",
                        "both of them", "serverless and classic", "classic and serverless",
                        "serverless e classic", "classic e serverless", "either", "any")


def _compute_question(a, storage=False):
    """Which plane — and never `both`, with the reason stated.

    Asked as one of two, because the two planes are two different networks and a run that
    mixed them would present evidence from one as an answer about the other.
    """
    if a.get("_compute_both_answered"):
        return {"ids": ["compute_type"], "question": (
            "I can only diagnose one of them per run, and it is not a limitation I can work "
            "around: classic compute egresses through YOUR VNet, while serverless does not "
            "touch that VNet at all — its egress is governed by your Databricks account's "
            "network policy. The checks, the probes and the fixes are different for each, so "
            "one run mixing them would hand you evidence about the wrong network.\n\n"
            "Pick the one to look at now — `serverless` or `classic` — and when this is "
            "done, start a new conversation for the other and I will diagnose that one "
            "properly too.")}
    if storage:
        return {"ids": ["compute_type"], "question": (
            "Which compute does the query fail on — `serverless` or `classic`? One diagnosis "
            "covers one of them: a classic consumer reaches storage through your own VNet, a "
            "serverless one does not. If both fail, answer with the one to look at first and "
            "run a second diagnosis for the other.")}
    return {"ids": ["compute_type"], "question": (
        "Which compute is this happening on — `serverless` or `classic`? One diagnosis "
        "covers one of them, because they are different networks: classic egresses through "
        "your own VNet, serverless does not touch it at all and is governed by your "
        "Databricks account's network policy. If it is failing on both, answer with the one "
        "you want to look at first and run a second diagnosis for the other — a single run "
        "that mixed the two would attribute evidence to the wrong network.")}


def _account_id_question(a):
    """The NCC account-id ask. Terse by default; the full 'here is how to find it'
    explanation is appended ONLY after self-discovery already failed (so we don't
    front-load a paragraph the customer rarely needs)."""
    q = ("To really inspect the NCC I need the Databricks ACCOUNT ID (a UUID) — and the same "
         "Service Principal must be an account admin. Give me the account id, or `none` to "
         "continue without inspecting the NCC.")
    if a.get("_account_discovery_log"):
        q = ("I couldn't discover the account id automatically. It appears in the URL after you "
             "sign in to accounts.azuredatabricks.net (ask an account admin). The same Service "
             "Principal must be an account admin. Give me the account id, or `none` to continue "
             "without inspecting the NCC (the serverless diagnosis then stays at hypothesis level).")
    unparsed = str((a or {}).get("_account_id_unparsed") or "").strip()
    if unparsed:
        q = ("That didn't read as an account id (`" + unparsed + "`) — it is a UUID, like "
             "`12345678-1234-1234-1234-123456789abc`. Send it, or `none` to continue "
             "without inspecting the NCC and I'll say what that leaves unproven.")
    return {"ids": ["account_id", "account_declined"], "question": q}


def _all_missing_questions(s):
    """Every still-unanswered intake question for this path, in ask order.
    _missing_questions() returns only the FIRST of these — we ask one thing at a
    time so the customer is never handed a wall of stacked questions (field
    feedback). Order for Path A/B: symptom-specific facts first, then
    the SP, then the NCC account id (which only becomes relevant once the SP exists)."""
    a = s["answers"]
    qs = []
    # HOW FAR, FIRST — before a single question about the customer's infrastructure,
    # because the answer decides whether two of those questions get asked at all.
    if s["path"] in ("A", "B") and not a.get("analysis_depth"):
        qs.append(_depth_question(a, s["path"]))
    if s["path"] == "A":
        if not a.get("target_host"):
            if a.get("compute_type") == "serverless" or a.get("_serverless_control_plane_redirect"):
                # Serverless has no customer-diagnosable path to the Databricks control
                # plane — its network surface is EGRESS to a resource OUTSIDE Databricks.
                # Steer the customer to that target instead of accepting a workspace audit.
                qs.append({"ids": ["target_host", "target_port"],
                           "question": (
                               "On serverless, connectivity to Databricks itself is managed by "
                               "Databricks and is not a customer-diagnosable path — serverless "
                               "network problems are about reaching a resource OUTSIDE Databricks. "
                               "Which EXTERNAL destination host:port is failing? e.g. your storage "
                               "`mystorage.dfs.core.windows.net:443`, a package index "
                               "`pypi.org:443`, or an external API/database. If the problem is "
                               "actually on a CLASSIC cluster, reply `classic` and I'll switch.")})
            elif a.get("_workspace_audit_unresolved"):
                qs.append({"ids": ["target_host", "target_port"],
                           "question": (
                               "I couldn't auto-detect this workspace's hostname from the "
                               "notebook runtime, so a generic `setup` audit cannot start yet. "
                               "Paste the workspace URL (e.g. `adb-1234567890.12.azuredatabricks.net`) "
                               "to validate the control-plane path, or name a destination host:port "
                               "that's failing.")})
            else:
                qs.append({"ids": ["target_host", "target_port"],
                           "question": ("Which destination host (and port) is failing? e.g. "
                                        "sql01.corp.internal:1433 — or answer `setup` if nothing "
                                        "specific is failing and you want a general validation of "
                                        "this workspace's network path.")})
        if a.get("compute_type") not in ("serverless", "classic"):
            qs.append(_compute_question(a))
        if a.get("compute_type") == "classic" and "cluster_id" not in a:
            qs.append({"ids": ["cluster_id"], "question": _cluster_question(a)})
        # Topology-first for classic: with the workspace ARM id (+ a Reader SP) I can
        # DISCOVER the network graph — the VNet Databricks sits in, subnets, NSGs,
        # peering, routes and the hub firewall — and trace the real egress path to the
        # target, instead of isolated checks. Serverless never sees this (its egress is
        # account NCC, not the VNet). `none` → basic classic probes only.
        if (a.get("compute_type") == "classic"
                and not a.get("workspace_arm_id", "").startswith("/subscriptions/")
                and not a.get("workspace_arm_declined")):
            qs.append({"ids": ["workspace_arm_id", "workspace_arm_declined"],
                       "question": (
                           "Since this is classic: with the workspace ARM resource id (plus the Reader "
                           "Service Principal I'll ask about next) I can DISCOVER your network first — "
                           "VNet, subnets, NSGs, peering, routes and the hub firewall — and diagnose "
                           "against that graph (it finds, for example, a firewall in the peered hub "
                           "dropping your egress). The ARM id is in Azure Portal > your workspace > "
                           "Properties > Resource ID (it starts with /subscriptions/...). Give me the "
                           "ARM id, or `none` to continue with basic classic probes only "
                           "(NSG/routes/peering).")})
        # Credential asks are PLANE-SCOPED — see _ACCOUNT_CRED_QUESTION for why the one
        # SP object needs two different grants and must therefore be asked for twice,
        # differently.
        if a.get("compute_type") == "serverless":
            # SERVERLESS-ONLY. The ARM/Reader ask is worth making only when the
            # destination is an Azure resource whose own firewall/PE posture we can
            # read; for a public destination it is asked for nothing (and _ctx_for_A
            # switches the ARM layer off outright).
            if (_serverless_target_is_azure_resource(a) and "sp_scope" not in a
                    and not a.get("sp_declined")):
                qs.append(dict(_SP_QUESTION, question=(
                    f"`{a.get('target_host')}` is an Azure resource, so an Azure Reader "
                    "Service Principal would let me also check the resource's OWN firewall "
                    "and private-endpoint posture. What is the NAME of the Databricks "
                    "Secrets scope holding it? (e.g. `my-reader-sp`) — answer "
                    "`create` if you don't have one yet and I'll walk you through making "
                    "it, or `none` to diagnose from the serverless egress layer alone.")))
            # The ACCOUNT credential is deliberately NOT an intake question: it is
            # offered by `_serverless_account_offer` AFTER the free in-session probes
            # have produced a verdict, so the customer sees an answer before being
            # asked for a credential (and often needs no credential at all).
        else:
            if "sp_scope" not in a and not a.get("sp_declined"):
                qs.append(dict(_SP_QUESTION))
    elif s["path"] == "C":
        if (not a.get("workspace_arm_id", "").startswith("/subscriptions/")
                and not a.get("workspace_arm_declined")):
            qs.append({"ids": ["workspace_arm_id", "workspace_arm_declined"],
                       "question": (
                           "What is the workspace's FULL ARM resource id? (Azure Portal > your "
                           "workspace > Properties > Resource ID; it starts with /subscriptions/...). "
                           "Path C cannot run without it — answer `none` only if you cannot provide "
                           "it, and I will stop rather than guessing from the error text.")})
        if not a.get("sp_scope") and not a.get("sp_declined"):
            qs.append(dict(_SP_QUESTION))
    elif s["path"] == "B":
        # a storage ACCOUNT or the failing HOST is a first-class Path B target.
        # A customer who has to go back to the analyst for the exact table name still
        # knows their external location, and that is all the storage checks need. Asking
        # only for the table dead-ended the run.
        _acct, _host = _storage_target_from_answers(a)
        # Also re-ask when a table name we accepted turned out to be unresolvable
        # mid-run (`_table_unresolved`): degrading to the account is better than the
        # ERROR-and-stop that an earlier defect produced, but we still need SOMETHING to point at.
        if not (_acct or _host) and (not a.get("full_table") or a.get("_table_unresolved")):
            _q = ("What is the FULL name of the Unity Catalog table/volume that fails, in "
                  "catalog.schema.table form (e.g. `nsp-catalog`.`nsp-schema`.`test_asq_data`)? "
                  "If you don't have the exact table name to hand, the STORAGE ACCOUNT name or the "
                  "failing host (e.g. `mystorage.dfs.core.windows.net`) is enough — I'll diagnose "
                  "that storage account directly.")
            if a.get("_table_rejected"):
                _q = (f"I can't use that as a table name ({a['_table_rejected']}). Give me either the "
                      "table in catalog.schema.table form, OR just the storage account name / the "
                      "failing host (e.g. `mystorage.dfs.core.windows.net`) — either one is enough "
                      "and I'll diagnose the storage account directly.")
            elif a.get("_table_unresolved"):
                _q = (f"Unity Catalog would not resolve that table ({a['_table_unresolved']}), so I "
                      "can't trace the credential chain from it. Give me the storage ACCOUNT name or "
                      "the failing host (e.g. `mystorage.dfs.core.windows.net`) and I'll diagnose the "
                      "storage account directly.")
            qs.append({"ids": ["full_table", "storage_account", "storage_host"], "question": _q})
        # Compute type matters for storage too: the strategy differs by plane. A
        # CLASSIC consumer egresses through the workspace VNet (and, on forced
        # tunneling, a hub firewall that can silently drop the storage FQDN — the
        # egress trace in _stage_B keys on compute_type == "classic"); a
        # SERVERLESS consumer egresses via the account NCC / storage perimeter. Ask
        # BEFORE the SP so the diagnosis runs the right plane (field feedback
        # In the field: without this, compute_type is always empty and the classic
        # forced-tunnel firewall trace never fires).
        if a.get("compute_type") not in ("serverless", "classic"):
            qs.append(_compute_question(a, storage=True))
        # For a CLASSIC/both consumer, the workspace ARM id unlocks the forced-tunnel
        # hub-firewall egress trace (a clean storage ACL can still be dropped by the
        # hub firewall). Ask only for classic/both; serverless doesn't need it.
        if (a.get("compute_type") == "classic"
                and not a.get("workspace_arm_id", "").startswith("/subscriptions/")
                and not a.get("workspace_arm_declined")):
            qs.append({"ids": ["workspace_arm_id", "workspace_arm_declined"],
                       "question": ("Since this is classic, the workspace ARM resource id lets me check "
                                    "whether a forced-tunnel firewall is dropping the egress to storage. "
                                    "Give me the ARM resource id (it starts with /subscriptions/...), or "
                                    "`none` to skip that trace.")})
        if "sp_scope" not in a and not a.get("sp_declined"):
            qs.append(dict(_SP_QUESTION))
    return qs


def _missing_questions(s):
    """Only the NEXT unanswered question (one at a time). Callers that need to know
    whether ANY intake is pending just check truthiness — a one-item list is truthy."""
    qs = _all_missing_questions(s)
    return qs[:1]


# ---------------------------------------------------------------------------
# Presentation payload
# ---------------------------------------------------------------------------

def _verification_line(report):
    # A healthy / no-actionable report has nothing to apply, so "apply the fix"
    # is nonsensical — offer a re-run instead.
    #
    # ...but "connectivity is healthy" must never be emitted while a check is failing.
    # Observed in the field: the prescription correctly opened with "Unresolved — I will
    # not claim your setup is healthy" and then closed with "connectivity is healthy in this
    # report", because this line keyed only on the diagnosis list. Fixing the header without
    # the footer just moved the contradiction down the page.
    if any(status_value(c) in ("fail", "error") for c in report_rows(report).values()):
        return ("Fix or explain the failing check(s) above, then ask me to re-verify against "
                "this report.")

    if not actionable_diagnoses(report.diagnoses):
        counts = check_verdict_counts(report)
        # D3, third surface. "N check(s) were skipped ... so this is not a clean bill of
        # health" is a CLAIM about gaps, so it counts gaps: filled with the raw skip
        # total it called nine not-applicable classic-plane layers "gaps to close" on a
        # serverless run, which sends the customer to close nine things that do not
        # exist. The closing line and the headline now read the same arithmetic.
        unproven = counts["unverified"] + counts["inconclusive"]
        if unproven:
            return (f"There is no fix to apply from what I could verify, but {unproven} "
                    "layer(s) that DO apply here were left unverified — so this is not a clean "
                    "bill of health. Close those gaps (see above) and ask me to re-verify.")
        return ("There is no fix to apply — every check I ran passed. If the problem comes back, "
                "ask me to re-verify and I'll run the diagnostic again.")
    return ("Apply the fix above and ask me to re-verify — I'll run the diagnostic again and "
            "compare against this report.")

def _chat_steps(d):
    """Chat-only view of a diagnosis's prescription list.

    The dashboard HTML renders the FULL prescription (report_builder reads
    d.prescription untouched). But some rules — notably the C2 NSG "three options"
    rule — carry a ~360-word multi-option prescription whose Option B (back-end
    Private Link) and Option C (manual NSG rules) paragraphs bury the PRIMARY fix
    (Option A: the one-line `az ... --required-nsg-rules AllRules`) in chat. For
    CHAT we keep Option A in full and collapse Options B/C to a single pointer line
    each; the full detail still renders in the dashboard report. Returns the list of
    chat step strings.
    """
    presc = d.prescription or []
    collapsed = False
    out = []
    for p in presc:
        head = p.lstrip().upper()
        if head.startswith("OPTION B") or head.startswith("OPTION C"):
            label = "Option B" if head.startswith("OPTION B") else "Option C"
            out.append(f"{label}: see the dashboard/report for the full steps.")
            collapsed = True
        else:
            out.append(p)
    return out, collapsed


# ---------------------------------------------------------------------------
# The customer-facing chat text
# ---------------------------------------------------------------------------
# observed in the field: the relay dropped the load-bearing
# sentences. On a report with FIVE WARN rows (both routing rows among them) the chat
# said "All standard ARM checks (subnet delegation, NSG rules, route tables, egress
# IP) came back clean"; on another it said "all probes passed" with 3 of 6 probe rows
# WARN, never mentioned the local DNS override, and never gave the overall status. On
# the blackhole run it omitted an entire diagnosis — including that diagnosis's own
# caveat that "a real misconfig could be invisible here", the one sentence that would
# have told the customer to distrust a clean-looking verdict.
#
# The fix is NOT to ask the prompt to behave (prompt changes are not even testable in
# a live Genie session, and "hope the relay preserves the nuance" is not a control).
# Everything load-bearing is composed HERE, deterministically, so there is nothing
# left to drop:
#   * the overall verdict and the full row counts, always, including the zeros;
#   * every row that did not pass, named individually — never summarised;
#   * a "Limits of this diagnosis" block ABOVE the findings, which hoists the
#     engine's own self-limitation sentences out of prescription step 4-of-4;
#   * every diagnosis with its severity word and fix_order, so a `medium` cannot be
#     re-headlined as "Root cause" and a lower-ranked one cannot be promoted;
#   * a self-check (`_false_clean_claims`) that refuses to let this function emit a
#     "clean"/"passed" claim while any row in the report is not a pass.

# The chat headline REUSES the dashboard banner's vocabulary (models.headline_words), so
# the same run cannot be called "NEEDS ATTENTION" in chat and "WARNINGS" on the banner
#. Only the explanatory tail is chat-specific.
_VERDICT_TAIL = {
    "fail": "I found a blocking problem you need to fix.",
    "warn": ("Nothing I could prove is blocking this target — and this is NOT a clean bill "
             "of health."),
    "pass": "No blocking problem found, and every check I ran passed.",
    # Same verdict, honest tail: a skip is a declared non-observation, so it does not
    # demote the verdict, but it must not read as "your whole setup is fine" either.
    #
    # D3 — {skipped} is the UNVERIFIED count, not the raw skip total, and the sentence
    # says so. Filled with the raw total it asserted "those layers are unverified"
    # about not-applicable ones too (10 skips / 1 real gap on the all-pass serverless
    # shape), which is the mirror image of the false-clean claim: over-claiming
    # blindness is still a wrong number in the customer's headline.
    "pass_partial": ("Every check that ran passed and I found no blocking problem, but {skipped} "
                     "layer(s) that DO apply here could not be verified (listed below)."),
}

_SEVERITY_NOTE = {
    "critical": "blocking",
    "high": "blocking",
    "medium": "not proven to be blocking this target",
    "low": "minor / best-practice",
    "info": "context only",
}

# Sentences the ENGINE ITSELF writes to admit it may be blind to something. They are
# generic self-limitation wording (not scenario or resource literals), and they are
# hoisted out of the individual diagnosis because burying them there is exactly how the
# relay lost them (blackhole run). Any rule that writes a new caveat should reuse
# this vocabulary.
# `_SKIP_RESTATEMENT_MARKERS` and `_CAVEAT_MARKERS` moved to models, imported above:
# the limits block they belong to is now composed there so the dashboard can render the
# same text as the chat, and a second copy of the vocabulary is how the two would drift.

# Claims that must never survive next to a row that did not pass. This is a guard on
# OUR OWN composed text: the live flattening happened because the material invited it,
# so the composer is not allowed to hand the relay a sentence like this in the first
# place.
# Only claims of BLANKET cleanliness — the exact shape the relay produced live ("All
# standard ARM checks ... came back clean", "all probes passed"). A negated form
# ("this is NOT a clean bill of health") is the honest wording we deliberately use, so
# matches preceded by a negation are ignored.
# "every"/"each" was missing, so `all_healthy`'s own sentence — "Every check that
# ran passed (10 of 10)" on a report with three WARN rows — went straight through the
# guard and out to the customer. A blanket claim is a blanket claim whichever quantifier
# it uses.
_FALSE_CLEAN_PATTERNS = (
    r"\b(?:all|every|each)\b[^.\n]{0,60}\b(?:checks?|probes?|rows?|tests?)\b[^.\n]{0,40}\b(?:passed|clean|succeeded|are fine|were ok)\b",
    r"\b(?:checks?|probes?)\b[^.\n]{0,40}\b(?:all (?:passed|clean)|came back clean)\b",
    r"\bcame back clean\b",
    r"\beverything (?:works|worked|is working|is fine|looks fine|checks out)\b",
    r"\bnothing (?:is )?(?:wrong|failing)\b",
)
_NEGATIONS = ("not ", "n't ", "never ", "no ")
# A claim that NAMES ITS OWN SCOPE is not a blanket claim, and flagging it made the
# composer append a "**Correction** — ignore any sentence above that reads as everything
# passed" block to a text that had said the opposite. Seen on every cluster-start report:
# `launch_failure_arm_clean` deliberately writes "this card does NOT claim every layer was
# proven healthy — only that the checks listed above came back clean in the resources
# visible to the Reader SP". That sentence is the honest form we want rules to use, so it
# must not be punished.
_SCOPE_QUALIFIERS = ("only ", "listed above", "that ran", "that reached a verdict",
                     "i could check", "i could verify", "on the layers")

# claims about the CUSTOMER'S SCREEN. Nothing in this process can observe the
# notebook, so any sentence asserting that something rendered, is visible, or sits in a
# particular place is unfalsifiable from here — and one of them shipped as the last line
# of the deliverable ("Dashboard rendered in the notebook cell ... to the left of this
# chat") on a notebook that had ZERO cells. Same mechanism as _false_clean_claims: the
# composer is not allowed to hand the relay a sentence it cannot stand behind.
# `_UI_CLAIM_LICENCE` are the hedges that turn an assertion into an offer, which is the
# honest form ("it MAY also be displayed inline"; "IF you do not see it").
_UI_CLAIM_PATTERNS = (
    r"\b(?:rendered|displayed|shown|visible)\b[^.\n]{0,40}\b(?:above|below|to the left|to the right|on screen|in the (?:notebook|cell|chat))\b",
    r"\b(?:to the left|to the right)\b[^.\n]{0,30}\bchat\b",
    r"\bsee (?:it|the dashboard|the report)\b[^.\n]{0,20}\babove\b",
    r"\b(?:the )?(?:dashboard|report|chart|table) (?:is|was) (?:now )?(?:rendered|displayed|visible|shown)\b",
    r"\byou (?:can|will) (?:now )?see\b",
)
_UI_CLAIM_LICENCE = ("may ", "might ", "if you ", "unless ", "should be", "in this cell",
                     "no longer visible", "cannot confirm", "i cannot see")


def _unverifiable_ui_claims(text):
    """Sentences asserting something about the customer's screen. Empty list when clean.

    A hedged form is allowed through: "it MAY also be displayed inline ... IF you do not
    see it there" offers a possibility, which is true. An unhedged "the dashboard is
    rendered in the notebook cell to the left of this chat" is a claim, and this process
    has no way to know it.
    """
    hits = []
    low = (text or "").lower()
    for pat in _UI_CLAIM_PATTERNS:
        for m in _re.finditer(pat, low):
            window = low[max(0, m.start() - 90):m.end() + 90]
            if any(lic in window for lic in _UI_CLAIM_LICENCE):
                continue
            hits.append(m.group(0).strip())
    return hits


def _false_clean_claims(text, report):
    """Claims of cleanliness that contradict the rows. Empty list when the text is honest.

    Returns the offending matches when the report has ANY row that is not a pass and is
    not a DECLARED non-applicable skip (i.e. fail/error/warn/inconclusive, or an
    unverified gap) and `text` nevertheless asserts that things passed / came back clean
    / no issue was found. Used as a self-check on the text this module composes, and
    directly testable against the sentences the relay actually produced live.

    D3 — this guard used to key on `not_passed`, which counts declared skips. On an
    all-pass serverless run (nine classic-plane layers correctly marked NOT APPLICABLE,
    zero gaps) it fired on the composer's own honest "every check I ran passed" and
    appended a "Correction" telling the customer to disregard it. The guard was reading
    an answer as a gap — the same conflation the skip classes exist to end. Any
    fail/error/warn/inconclusive row, and any UNVERIFIED skip, still trips it, so the
    guard has lost none of its teeth: it has stopped biting a true sentence.
    """
    counts = check_verdict_counts(report)
    declared_skips = max(0, counts["skip"] - counts["unverified"])
    unclean = max(0, counts["not_passed"] - declared_skips)
    if not unclean and not counts["inconclusive"]:
        return []          # a genuinely all-pass report may say so
    low = (text or "").lower()
    hits = []
    for pat in _FALSE_CLEAN_PATTERNS:
        for m in _re.finditer(pat, low):
            if any(neg in low[max(0, m.start() - 24):m.start()] for neg in _NEGATIONS):
                continue
            if any(q in low[max(0, m.start() - 60):m.end()] for q in _SCOPE_QUALIFIERS):
                continue
            hits.append(m.group(0).strip())
    return hits


# ---------------------------------------------------------------------------
# Text primitives for the guide
# ---------------------------------------------------------------------------

_SENT_SPLIT = _re.compile(r"(?<=[.!?])\s+")
_BULLET_RE = _re.compile(r"^(?:[-*•]|\d{1,2}[.)])\s+")


def _debullet(s):
    """Drop a leading list marker only ('- ', '* ', '1. '). Never touches '10.40.2.132'."""
    return _BULLET_RE.sub("", _norm_ws(s)).strip()


def _rec_lines(rec):
    """A recommendation's own lines, list markers stripped, blanks dropped."""
    return [x for x in (_debullet(line) for line in str(rec or "").splitlines()) if x]


def _render_recommendation(rec, indent="  "):
    """Render a recommendation COMPLETE — every line of it. Never a prefix.

    Field experience: this used to render `rec.splitlines()[0]`, so a
    multi-line recommendation lost everything after its first line. The FAIL peering row
    reached the customer as "What to do: Fix peering:" and stopped — the header survived
    while the actual instruction ("'Allow forwarded traffic' is OFF — traffic forwarded
    by an NVA/gateway in the peered VNet is dropped") and the Azure Portal path were
    dropped, though both were sitting in the same field. A truncated instruction is worse
    than none, because it looks complete.

    So there is no first-line path any more. A row either renders its whole
    recommendation here, or it is compressed to a no-action one-liner that renders NONE
    of it and says where the text lives (`_compact_row_line`). Those are the only two
    options, and `_guide_audit` fails the build if any third one appears.
    """
    lines = _rec_lines(rec)
    if not lines:
        return ""
    out = [f"{indent}- What to do: {lines[0]}"]
    out += [f"{indent}  - {line}" for line in lines[1:]]
    return "\n".join(out)


def _clip_message(msg, max_sentences=2, max_words=60):
    """First sentences of an OBSERVATION, with an explicit marker when anything is cut.

    Applies to `message` only, NEVER to `recommendation`. An observation's tail is
    usually the audit trail ("Evaluated all 1 route(s) in UDR ...") which `raw_output`
    and the report keep in full; an instruction has no droppable tail, so it is never
    cut. Returns (text, elided).
    """
    text = _norm_ws(msg)
    if not text:
        return "", False
    sents = [s for s in _SENT_SPLIT.split(text) if s]
    kept, words = [], 0
    for s in sents[:max_sentences]:
        w = len(s.split())
        if kept and words + w > max_words:
            break
        kept.append(s)
        words += w
    return " ".join(kept), len(kept) < len(sents)


# Wording a check uses to say, in its OWN words, that nothing needs doing. Generic
# self-description — no scenario, resource or chaos literal may ever be added here.
_NO_ACTION_MARKERS = (
    "no action needed", "no action required", "no action is needed", "nothing to do",
    "normal and benign", "this is expected", "(expected)", "informational only",
    "does not necessarily mean", "is often blocked", "is usually blocked",
)


def _no_action_row(c):
    """Does this row declare that there is nothing to do?

    Never true for fail/error — a red row always gets its complete recommendation. The
    marker must sit in the recommendation's FIRST sentence, so a row that opens with an
    imperative can never be compressed away. A row with no recommendation at all has
    nothing prescribed by definition.
    """
    if status_value(c) in ("fail", "error"):
        return False
    rec = _norm_ws(getattr(c, "recommendation", "") or "")
    if not rec:
        return True
    first = (_SENT_SPLIT.split(_debullet(rec.splitlines()[0]))[0] or "").lower()
    return any(m in first for m in _NO_ACTION_MARKERS)


def _scope_clause(c, siblings=None, ambiguous=False):
    """" (snet-a, snet-b)" — which object(s) this line is about.

    Needed for two reasons, both seen on the cluster-start report: a per-subnet check
    emits one row per subnet under the SAME `check_name`, so two rows read as literal
    duplicates with nothing to tell them apart; and when several such rows are merged
    into one line, the line has to name every object it now covers.
    """
    targets = [t for t in ((getattr(x, "target", "") or "").strip()
                           for x in (siblings or [c])) if t]
    targets = list(dict.fromkeys(targets))
    if len(targets) > 1 or (ambiguous and targets):
        return " (" + ", ".join(targets) + ")"
    return ""


# There was a `_dedupe_rows` presenter merge here, which folded rows the guide would render
# identically into one line. It is DELETED on purpose (an earlier defect #3). It made the output legible
# by accident and it was load-bearing for the wrong reason: per-subnet route tables are
# perfectly normal, so one topology away a merge fuses two genuinely DIFFERENT facts and
# hides one, and the moment the underlying check starts naming its subnet the merge stops
# firing and the duplication returns. Worst of all, the report JSON — which is what a
# support ticket carries — was never fixed by it at all.
# The duplication is now fixed where it originates (cluster_start_checks.check_subnet_route_table
# names its subnet, matching check_subnet_egress_ip's convention), and audit rule 9 fails
# the build if any pair of rows becomes indistinguishable again. `_scope_clause` stays: it
# solves the other half — telling the reader WHICH object a row is about when two rows
# legitimately share a check name.


def _ambiguous_labels(*row_lists):
    """Check names that more than one rendered line would carry, so each must be scoped."""
    seen = {}
    for rows in row_lists:
        for key, c in rows:
            label = _check_label(key, c)
            seen[label] = seen.get(label, 0) + 1
    return {label for label, n in seen.items() if n > 1}


def _row_line(key, c, siblings=None, ambiguous=False):
    """One named, non-pass check row: human name, status, message, FULL recommendation.

    The message is an observation and may be clipped (with the cut declared); the
    recommendation never is. A WARN row that is about to be handed a complete instruction
    needs its observation only to IDENTIFY the object — the consequence and the action are
    in the instruction underneath it — so it gets one sentence. A red row keeps two,
    because a red row's observation is itself part of the answer.
    """
    sv = status_value(c).upper()
    if _is_inconclusive(c):
        sv += "/INCONCLUSIVE"
    hard = status_value(c) in ("fail", "error")
    has_rec = bool(_rec_lines(getattr(c, "recommendation", "")))
    msg, elided = _clip_message(getattr(c, "message", ""),
                                max_sentences=1 if (has_rec and not hard) else 2)
    line = f"- **{_check_label(key, c)}**{_scope_clause(c, siblings, ambiguous)} [{sv}] — {msg}"
    if elided:
        line += " (more in the report)"
    rec = _render_recommendation(getattr(c, "recommendation", ""))
    if rec:
        line += "\n" + rec
    return line


def _compact_row_line(labels, c, ambiguous=frozenset()):
    """One line for a no-action observation, in the check's own words.

    Renders the message's first sentence plus the sentence in which the check itself
    said this is benign — and NO part of the recommendation, which the line declares
    rather than truncates. Rationale (a pre-release run): `dns` and `dns_local_override`
    spent ~200 of 697 words saying the same thing twice about an override the check
    itself calls "normal and benign", directly above the one row that had an action. A
    no-action observation earns one sentence, not two paragraphs.
    """
    sv = status_value(c).upper()
    sents = [s for s in _SENT_SPLIT.split(_norm_ws(getattr(c, "message", ""))) if s]
    keep = sents[:1]
    for s in sents[1:]:
        if any(m in s.lower() for m in _NO_ACTION_MARKERS):
            keep.append(s)
            break
    name = " / ".join(f"**{l}**" for l in labels)
    name += _scope_clause(c, None, any(l in ambiguous for l in labels))
    if (getattr(c, "recommendation", "") or "").strip():
        tail = "the check reports no action needed; detail in the report"
    else:
        tail = "no fix prescribed; full text in the report"
    return f"- {name} [{sv}] — {' '.join(keep)} *({tail}.)*"


def _fold_derived(rows):
    """Fold a DERIVED no-action row into the row it derives from.

    `metadata["derived_from"] = "<row key>"` is a structural declaration by the check
    ("I am a second view of that row's fact"), so this is a rule about check topology,
    not a name match on any particular check. Returns [(labels, check)] in input order,
    the derived row's own check kept as the one that speaks (it names the fact directly).
    """
    by_key = dict(rows)
    children = {}
    for key, c in rows:
        parent = ((getattr(c, "metadata", None) or {}).get("derived_from") or "")
        if parent and parent in by_key:
            children.setdefault(parent, []).append(key)
    folded, done = [], set()
    for key, c in rows:
        if key in done:
            continue
        kids = children.get(key) or []
        if kids:
            speaker = kids[0]
            labels = [_check_label(key, c)] + [_check_label(k, by_key[k]) for k in kids]
            folded.append((labels, by_key[speaker]))
            done.add(key)
            done.update(kids)
        else:
            folded.append(([_check_label(key, c)], c))
            done.add(key)
    return folded


def _counts_sentence(report):
    c = check_verdict_counts(report)
    # "(of N run)" was true only while the skipped rows were missing from the count.
    # With them present it would claim 18 checks ran on a run where 11 never did. Kept to
    # one extra word: this sentence sits in front of the first instruction, and the guide
    # audit measures how many words the customer reads before reaching an action.
    ran = c["total"] - c["skip"]
    return (f"Checks: {c['pass']} passed, {c['warn']} warning, "
            f"{c['fail'] + c['error']} failed, {c['skip']} skipped, "
            f"{c['inconclusive']} inconclusive ({ran} of {c['total']} ran).")


def _limitations_block(report, already=""):
    """Everything this run could NOT settle. Composed in models so the DASHBOARD
    renders the identical text (that copy had none of it — 0 grep hits for
    "limits of this diagnosis"/"unverified"/"not checked" — and is the artefact
    customers forward to their platform team).

    Also the ONLY place inconclusive and skipped rows are named, so they are stated
    once with their reason instead of twice.
    """
    return limitations_block(report, already=already)


def _context_block(d, index, other_titles=(), skips_already_listed=False):
    """A card that asks for NO action, at the size of a no-action row (an earlier defect volume).

    an earlier defect fixed the TIER — a "this is correct, do not change it" card is demoted to INFO,
    `fix order 90`, `context only`, and it names the finding that actually explains the
    failure. It did not fix the VOLUME: in the field that card was ~460 words of a
    909-word deliverable, the single largest element in the message, and its entire content
    was "do not touch this". Worse, it printed a bold **Fix** heading, so a customer
    scanning for their next action started reading about private endpoints and DNS zones.

    So a context card gets: its title, its attributes, its protective "do not change X"
    instruction IN FULL (short, and the whole point of the card), and the closing sentences
    of its root cause, which are where the engine names the finding that supersedes it.
    Everything else is a declared omission pointing at the report — never a bold **Fix**,
    because that heading is what makes a scanner treat it as work to do.
    """
    sev = severity_value(d) or "info"
    order = getattr(d, "fix_order", 99)
    layer = _LAYER_LABEL.get(getattr(d, "layer", ""), "")
    title = (getattr(d, "title", "") or "").strip()
    meta = [f"{sev.upper()} severity", f"fix order {order}", "context only"]
    if layer:
        meta.append(layer)
    out = [f"**Context #{index}{(' — ' + title) if title else ''}**\n" + " · ".join(meta)]

    steps = list(getattr(d, "prescription", None) or [])
    protective = [_norm_ws(p) for p in steps
                  if any(m in str(p).lower() for m in _NO_CHANGE_MARKERS)]
    pointer = _supersession_sentences(getattr(d, "root_cause", ""), other_titles)
    if skips_already_listed:
        # The limits block above already lists every skipped layer by name. When this
        # card's fallback sentence is the engine's own restatement of that same list, it
        # is the identical ~30 words a few lines apart — the an earlier defect duplication, in a new
        # place, and it appears exactly BECAUSE the skips are now counted properly.
        pointer = [x for x in pointer
                   if not any(m in x.lower() for m in _SKIP_RESTATEMENT_MARKERS)]
    body = protective + pointer
    text = " ".join(x for x in body if x)
    if not text:
        if skips_already_listed:
            # Everything this card had to say is the skip list printed above. Say that,
            # rather than leaving a bare heading with nothing under it.
            out.append("**No action needed here** — nothing beyond the unverified layers "
                       "already listed above; the full text is in the saved report.")
        return "\n\n".join(out)
    dropped = len(steps) > len(protective) or _norm_ws(getattr(d, "root_cause", "")) != " ".join(pointer)
    if dropped:
        text += " (Full justification is in the saved report.)"
    out.append("**No action needed here** — " + text)
    return "\n\n".join(out)


def _supersession_sentences(text, other_titles=(), max_words=45):
    """The sentence(s) of a context card that name ANOTHER finding in this same report.

    Selection is by comparison against the report's own diagnosis titles — not by matching
    the engine's prose — so it keeps the one sentence a customer must not miss ("the cause
    has already been identified in this report: <title> (fix order N) — fix that") and drops
    the paragraph of justification that belongs in the report. Falls back to the closing
    sentences, which is where the engine appends that pointer, when no title matches.
    """
    sents = [x for x in _SENT_SPLIT.split(_norm_ws(text)) if x]
    titles = [_norm_ws(t) for t in (other_titles or []) if _norm_ws(t)]
    named = [x for x in sents if any(t and t in x for t in titles)]
    pool = named or list(reversed(sents))
    kept, words = [], 0
    for x in (pool if named else pool):
        w = len(x.split())
        if kept and words + w > max_words:
            break
        kept.append(x)
        words += w
    return kept if named else list(reversed(kept))


def _diagnosis_block(d, index, is_top):
    """One diagnosis: TITLE on the header line, its attributes on their own line.

    the relay re-headlined a `medium` finding as "Root cause" and promoted a
    lower-ranked finding while dropping the top one. Only a CRITICAL/HIGH top finding is
    labelled "Root cause"; everything else is labelled for what it is, and every block
    states severity + fix order, so no re-ranking is possible downstream.

    those six attributes used to be concatenated onto the header, so the title
    collided with its own metadata. The title now owns the header line and the
    attributes sit on the line below it.
    """
    sev = severity_value(d) or "info"
    note = _SEVERITY_NOTE.get(sev, "")
    order = getattr(d, "fix_order", 99)
    layer = _LAYER_LABEL.get(getattr(d, "layer", ""), "")
    if sev in ("critical", "high") and is_top:
        label = "Root cause"
    elif sev == "info":
        label = f"Context #{index}"
    else:
        label = f"Finding #{index}"
    title = (getattr(d, "title", "") or "").strip()
    head = f"**{label}{(' — ' + title) if title else ''}**"
    meta = [f"{sev.upper()} severity", f"fix order {order}"]
    if note:
        meta.append(note)
    if layer:
        meta.append(layer)
    if getattr(d, "needs_confirmation", False):
        meta.append("UNCONFIRMED HYPOTHESIS")
    block = [head + "\n" + " · ".join(meta)]
    # the IMPERATIVE goes above the explanation. The root cause on this report is 128
    # words, so with the fix underneath it the first thing the customer could act on sat
    # ~190 words into the guide — about a minute of reading before any instruction. The
    # reasoning still has to be here (a customer will not change a peering they do not
    # understand), it just no longer stands between them and the action.
    if getattr(d, "prescription", None):
        steps, collapsed = _chat_steps(d)
        fix = "**Fix** —\n" + "\n".join(f"- {p}" for p in steps)
        if collapsed:
            # "below" was a claim about where the dashboard sits on screen, which this
            # process cannot see. Point at the artifact, not at a position.
            fix += ("\n\n(Chat shows the primary fix; the full multi-option detail is in the "
                    "saved dashboard report.)")
        block.append(fix)
    root = (getattr(d, "root_cause", "") or "").strip()
    if root:
        block.append(("**Why** — " if getattr(d, "prescription", None) else "") + root)
    return "\n\n".join(x for x in block if x)


def _chat_prescription(report):
    """Compose the whole customer-facing guide deterministically (an earlier defect + an earlier defect).

    Order is deliberate, and an earlier defect changed it: verdict -> counts -> **what to do** ->
    limits -> no-action observations -> context -> verification.

    an earlier defect had put the limits and every non-pass row above the findings, on the reasoning
    that a summarising relay truncates the tail. That protected the caveats and buried
    the instruction: on a pre-release report the customer had to read through four
    warning paragraphs, two of them saying the same benign thing, before reaching the
    one row that told them what to change. Actions now come first and the limits sit
    immediately after them — still high, still ahead of the noise — so if anything is
    lost off the end it is the no-action observations, which is the cheapest thing to
    lose rather than the most expensive.
    """
    # `report.checks` used to hold only the checks that RAN, so on an
    # ARM-blind run all four sources of _limitations_block below were empty and the
    # whole "Limits of this diagnosis" section was never COMPOSED: not dropped by the
    # relay (as first assumed), simply never written, which leaves no text to grep for.
    checks = report_rows(report)
    counts = check_verdict_counts(checks)
    overall = str(getattr(report.overall_status, "value", report.overall_status) or "pass").lower()
    if overall == "error":
        overall = "fail"

    banner, _ = headline_words(overall, counts)
    # D3 — gaps, not raw skips, in both the branch and the number (see _VERDICT_TAIL).
    # `counts` already carries both, from the one tally the dashboard banner also reads.
    tail_key = "pass_partial" if (overall == "pass" and counts["unverified"]) else overall
    tail = _VERDICT_TAIL.get(tail_key, _VERDICT_TAIL["warn"]).format(
        skipped=counts["unverified"])
    parts = [f"**Overall: {banner}** — {tail}\nTarget: `{report.target}`\n"
             + _counts_sentence(report)]

    # Every row that did not pass is named — individually, by its human name, never
    # "all the ARM checks came back clean". Inconclusive and skipped rows are named in
    # the limits block instead, WITH their reason, so they are stated once not twice.
    hard, warn_action, quiet = [], [], []
    for key, c in checks.items():
        sv = status_value(c)
        if sv == "pass" or sv == "skip" or _is_inconclusive(c):
            continue
        if sv in ("fail", "error"):
            hard.append((key, c))
        elif _no_action_row(c):
            quiet.append((key, c))
        else:
            warn_action.append((key, c))

    ranked = rank_diagnoses(report.diagnoses)
    info = [d for d in (report.diagnoses or []) if d not in ranked]

    action = []
    if ranked:
        for i, d in enumerate(ranked, start=1):
            action.append(_diagnosis_block(d, i, is_top=(i == 1)))
    else:
        # A check can FAIL while no correlation rule claims it — several rules require a
        # TCP failure as their trigger, so e.g. a peering fault on a workspace whose
        # probes still succeed lands here. Saying "no blocking problem found" next to a
        # FAILED check is a contradiction the customer cannot resolve, and it is how a
        # real fault gets silently dropped (live on the healthy baseline:
        # peering=fail, zero diagnoses, prose claiming nothing was wrong).
        if counts["fail"] or counts["error"]:
            action.append(
                f"**Unresolved** — {counts['fail'] + counts['error']} check(s) did not pass and no "
                "diagnosis rule matched them, so I will not tell you your setup is healthy. Review "
                "the failing check(s) named below; if they are expected in your design, tell me and "
                "I will note it. A failing check with no matching diagnosis is itself worth "
                "reporting back to the Doctor's maintainers.")
        elif counts["warn"] or counts["inconclusive"]:
            action.append("**No root cause identified** — no diagnosis rule matched. That is not the "
                          "same as a clean result: the rows and limits listed below were not proven "
                          "healthy.")
        elif counts["unverified"]:
            # D3 — gaps, not raw skips. Filled with the raw total on an all-pass
            # serverless run this said "10 check(s) never ran ... this report does not
            # cover those layers" when nine of the ten do not apply to serverless at all.
            action.append(f"**No root cause identified** — every check that ran passed, and no "
                          f"diagnosis rule matched. {counts['unverified']} layer(s) that DO apply "
                          "here could not be verified (listed below), so this report does not "
                          "cover them.")
        else:
            action.append("**No root cause identified** — every check I ran passed and no diagnosis "
                          "rule matched, so I have nothing to prescribe for this target.")
    ambiguous = _ambiguous_labels(hard, warn_action, quiet)
    if hard:
        action.append("**Checks that FAILED — the red rows in the report**\n"
                      + "\n".join(_row_line(k, c, None, _check_label(k, c) in ambiguous)
                                   for k, c in hard))
    if warn_action:
        action.append(f"**Warnings that still need an action ({len(warn_action)})** — a warning is "
                      "not a pass\n"
                      + "\n".join(_row_line(k, c, None, _check_label(k, c) in ambiguous)
                                   for k, c in warn_action))
    parts.extend(action)

    limits = _limitations_block(report, already="\n\n".join(parts))
    if limits:
        parts.append(limits)

    # A GAP WITH AN ACTION MUST SHOW THE ACTION.
    #
    # The limits block prints a row's MESSAGE and drops its RECOMMENDATION, which is
    # correct for a gap that can only be described. It is wrong for a gap the customer
    # can actually close: the account-layer 403 has a read-only hand-off attached (a
    # snapshot an EXISTING account admin runs — no new grant), and dropping it leaves
    # the customer with a description of their blindness and nothing to do about it,
    # which is how the graded run ended up with a single unactionable sentence as its
    # whole deliverable.
    #
    # The alternative was to mislabel the row WARN so the actions section would pick it
    # up — which is what the ARM row does, and which D1 has just shown to be harmful
    # here (a permission boundary must not read as a warning about the network). So the
    # composer learns the distinction instead: an unverified row that flags a hand-off
    # gets its recommendation rendered, in full, in its own section.
    _handoffs = [(k, c) for k, c in checks.items()
                 if (getattr(c, "metadata", None) or {}).get(_HANDOFF_META)
                 and (getattr(c, "recommendation", "") or "").strip()]
    if _handoffs:
        _blocks = []
        for k, c in _handoffs:
            _blocks.append(f"*{_check_label(k, c)}*\n" + (c.recommendation or "").strip())
        parts.append("**Closing the gap — no new permission required**\n\n"
                     + "\n\n".join(_blocks))

    if quiet:
        folded = _fold_derived(quiet)
        parts.append(f"**Also observed, no action needed ({len(folded)})**\n"
                     + "\n".join(_compact_row_line(labels, c, ambiguous) for labels, c in folded))

    other_titles = [(getattr(x, "title", "") or "").strip() for x in ranked]
    _skips_listed = bool(limits) and bool(counts["skip"])
    for i, d in enumerate(info, start=len(ranked) + 1):
        parts.append(_context_block(d, i, other_titles, skips_already_listed=_skips_listed))

    parts.append(f"**Verification** — {_verification_line(report)}")
    text = "\n\n---\n\n".join(parts)

    # Self-check: never hand the relay a cleanliness claim while a row is not a pass.
    bad = _false_clean_claims(text, report)
    if bad:
        print("[Doctor] WARNING — the chat text asserted a clean result while "
              f"{counts['not_passed']} row(s) did not pass: {bad}. Appending an explicit "
              "correction; this is a bug in the chat composer, please report it.")
        text += ("\n\n---\n\n**Correction** — ignore any sentence above that reads as "
                 f"\"everything passed\": {counts['not_passed']} of {counts['total']} checks did "
                 "not return a clean pass. The per-row list above is the truth.")

    # Self-check: never hand the customer a partially-rendered instruction, and never
    # silently drop a non-pass row. Budget is excluded here on purpose — a long report is
    # not a correctness bug and must not print a scary warning into the customer's
    # notebook; `_guide_audit(..., include_budget=True)` is the offline gate for that.
    for problem in _guide_audit(text, report, include_budget=False):
        print(f"[Doctor] WARNING — guide self-check: {problem}")
    return text


def _first_sentence(text, max_words=32):
    """The opening sentence of a root-cause paragraph, capped — the one-line 'why'.

    The full reasoning stays in the dashboard (build_dashboard_v2 renders every
    diagnosis' complete root_cause); the chat keeps only enough to act on.
    """
    sents = [x for x in _SENT_SPLIT.split(_norm_ws(text)) if x]
    if not sents:
        return ""
    words = sents[0].split()
    return sents[0] if len(words) <= max_words else " ".join(words[:max_words]) + "…"


def _chat_summary(report):
    """Objective customer-facing chat message; the exhaustive detail lives in the dashboard.

    The an earlier defect/an earlier defect completeness guarantees are preserved by RELOCATION, not truncation:
    every check row, each finding's full 'Why', the 'Limits of this diagnosis' block and
    the benign observations are rendered by build_dashboard_v2, so the saved dashboard
    carries all of it. The chat keeps only what a customer must read to act:
      - the verdict + the honest counts,
      - every CRITICAL/HIGH cause named, with its full fix (never truncated) + a one-line
        why; if nothing is that severe, the single top-ranked finding,
      - the actionable warning rows named (not merely counted),
      - a pointer to the dashboard for the rest.
    """
    checks = report_rows(report)
    counts = check_verdict_counts(checks)
    overall = str(getattr(report.overall_status, "value", report.overall_status) or "pass").lower()
    if overall == "error":
        overall = "fail"
    banner, _ = headline_words(overall, counts)
    tail_key = "pass_partial" if (overall == "pass" and counts["unverified"]) else overall
    tail = _VERDICT_TAIL.get(tail_key, _VERDICT_TAIL["warn"]).format(skipped=counts["unverified"])
    parts = [f"**Overall: {banner}** — {tail}\nTarget: `{report.target}` · " + _counts_sentence(report)]

    ranked = rank_diagnoses(report.diagnoses)
    # Never drop a CRITICAL/HIGH cause from the chat; if none is that severe, keep the
    # single top-ranked finding so the customer still gets a named cause + fix.
    causes = [d for d in ranked if severity_value(d) in ("critical", "high")] or ranked[:1]
    for d in causes:
        sev = severity_value(d) or "info"
        note = _SEVERITY_NOTE.get(sev, "")
        label = "Root cause" if sev in ("critical", "high") else "Most likely cause"
        title = (getattr(d, "title", "") or "").strip()
        head = (f"**{label}{(' — ' + title) if title else ''}** "
                f"({sev.upper()}{' · ' + note if note else ''})")
        why = _first_sentence(getattr(d, "root_cause", ""))
        blk = [head + ((" — " + why) if why else "")]
        if getattr(d, "prescription", None):
            steps, collapsed = _chat_steps(d)
            fix = "**Fix** —\n" + "\n".join(f"- {p}" for p in steps)
            if collapsed:
                fix += "\n(Primary fix shown; full options in the dashboard.)"
            blk.append(fix)
        parts.append("\n\n".join(blk))

    if not ranked and (counts["fail"] or counts["error"]):
        # NAME them here. Pointing at the dashboard for the failing rows made the chat text
        # useless on its own, and the dashboard is rendered by a notebook cell this process
        # neither controls nor can observe — so a customer whose cell did not paint was told
        # a count and nothing else.
        _bad = [f"{_check_label(_k, _c)} — {(getattr(_c, 'message', '') or '').strip()}"
                for _k, _c in checks.items() if status_value(_c) in ("fail", "error")]
        _list = ("\n" + "\n".join("- " + _b for _b in _bad)) if _bad else ""
        parts.append(f"**Unresolved** — {counts['fail'] + counts['error']} check(s) did not pass and no "
                     "diagnosis rule matched them, so I will not tell you the setup is "
                     f"healthy.{_list}")

    # Actionable warning rows NAMED (not just counted); their fix detail is in the dashboard.
    warn_action = [_check_label(k, c) for k, c in checks.items()
                   if status_value(c) not in ("pass", "skip", "fail", "error")
                   and not _is_inconclusive(c) and not _no_action_row(c)]
    if warn_action:
        parts.append(f"**Warnings that need a look ({len(warn_action)})** — "
                     + ", ".join(warn_action) + " _(what to do: see the dashboard)_")

    # An INFO diagnosis with LOW confidence is the engine saying "I could not reach a
    # verdict" (models.cannot_conclude). `ranked` drops INFO, so when that is the only
    # diagnosis the chat carried a verdict line, a counts line and nothing else — no
    # cause, and no mention of the one thing that would produce one. `storage_needs_sp`
    # is exactly that, and a customer who picks the credential-free analysis on Path B
    # now lands there BY DESIGN, so it went from an edge case to a common one. What gets
    # rendered is the engine's own root_cause and prescription: no new claim, and the
    # same reasoning as the hand-off block below.
    if not ranked:
        _named = cannot_conclude(report.diagnoses)
        _unsettled = [d for d in (report.diagnoses or [])
                      if (getattr(d, "pattern_id", "") or getattr(d, "title", "")) in _named
                      and getattr(d, "pattern_id", "") != "all_healthy"]
        for d in _unsettled[:1]:
            _why = _first_sentence(getattr(d, "root_cause", ""))
            _fix = [str(x).strip() for x in (getattr(d, "prescription", None) or [])
                    if str(x).strip()]
            _title = (getattr(d, "title", "") or "").strip() or "I could not settle this"
            _blk = ["**No verdict — " + _title + "**" + ((" — " + _why) if _why else "")]
            if _fix:
                _blk.append("\n".join("- " + x for x in _fix))
            parts.append("\n".join(_blk))

    # A hand-off is an ACTION, not detail — the account admin runs a read-only snapshot
    # that needs no new grant. It stays in the chat in full (same as _chat_prescription),
    # because dropping it leaves the customer with a description of their blindness and
    # nothing to do about it.
    _handoffs = [(k, c) for k, c in checks.items()
                 if (getattr(c, "metadata", None) or {}).get(_HANDOFF_META)
                 and (getattr(c, "recommendation", "") or "").strip()]
    if _handoffs:
        _blocks = [f"*{_check_label(k, c)}*\n" + (c.recommendation or "").strip()
                   for k, c in _handoffs]
        parts.append("**Closing the gap — no new permission required**\n\n"
                     + "\n\n".join(_blocks))

    # Everything else — every row, each finding's full reasoning, the limits and the
    # benign observations — is in the dashboard. State the deferred counts honestly.
    # NAME the unsettled layers in the chat, do not merely count them. The dashboard is
    # rendered by a notebook cell we neither control nor can observe, so the chat text has
    # to stand on its own as the diagnosis — a customer who never sees the HTML must still
    # be able to act, and to know what was NOT checked. A bare count told them a number and
    # sent them to a file that may not have appeared.
    deferred = []
    if counts["unverified"]:
        # Same predicate the COUNT uses (models.is_unverified_skip): a real gap, not a
        # declared not-applicable. Naming a not-applicable row as "not checked" would
        # invent a gap.
        _names = [_check_label(_k, _c) for _k, _c in checks.items()
                  if is_unverified_skip(_c)]
        _seen, _uniq = set(), []
        for _n in _names:
            if _n and _n not in _seen:
                _seen.add(_n)
                _uniq.append(_n)
        if _uniq:
            _shown = ", ".join(_uniq[:8])
            _more = f" (+{len(_uniq) - 8} more)" if len(_uniq) > 8 else ""
            parts.append(f"**Not checked — {counts['unverified']} layer(s)**\n{_shown}{_more}"
                         "\nThese were not read, so nothing above covers them.")
        deferred.append(f"{counts['unverified']} layer(s) not settled")
    quiet_n = sum(1 for k, c in checks.items()
                  if status_value(c) not in ("pass", "skip") and not _is_inconclusive(c)
                  and _no_action_row(c))
    if quiet_n:
        deferred.append(f"{quiet_n} benign observation(s)")
    lead = ("; ".join(deferred) + " — ") if deferred else ""
    parts.append(f"_{lead}full rows, reasons and limits are in the dashboard. "
                 f"{_verification_line(report)}_")

    text = "\n\n".join(parts)
    bad = _false_clean_claims(text, report)
    if bad:
        text += ("\n\n**Correction** — ignore any 'everything passed' reading: "
                 f"{counts['not_passed']} of {counts['total']} checks did not return a clean pass.")

    for problem in _summary_audit(text, report):
        print(f"[Doctor] WARNING — chat-summary self-check: {problem}")
    return text


def _summary_word_budget(report):
    """Per-cause budget for the concise chat (same philosophy as guide_word_budget).

    A summary with N real causes HAS more to say than one with a single cause, and a
    hand-off is a full procedure the customer runs — so the budget scales with them and
    is never a flat cap that would force truncating an instruction. Everything else lives
    in the dashboard, so the base is small.
    """
    checks = report_rows(report)
    ranked = rank_diagnoses(report.diagnoses)
    causes = [d for d in ranked if severity_value(d) in ("critical", "high")] or ranked[:1]
    warn_action = sum(1 for k, c in checks.items()
                      if status_value(c) not in ("pass", "skip", "fail", "error")
                      and not _is_inconclusive(c) and not _no_action_row(c))
    handoffs = sum(1 for k, c in checks.items()
                   if (getattr(c, "metadata", None) or {}).get(_HANDOFF_META)
                   and (getattr(c, "recommendation", "") or "").strip())
    # Measured across the captured corpus, not chosen: a healthy baseline runs ~114 words
    # (base), a single cause adds a title + one-line why + a COMPLETE multi-step fix (up to
    # ~160 on the blackhole route remediation), a named warning ~12, and a hand-off is a
    # full procedure (275, the same measured constant the guide uses). The budget must fit
    # the longest legitimate fix — it guards against a regression that balloons the summary,
    # it must never be a cap that forces truncating an instruction.
    return (120                                  # verdict, target, counts, deferred line, verification
            + 160 * len(causes)                  # title + one-line why + a complete fix
            + 12 * warn_action                   # one named warning
            + _GUIDE_BUDGET_PER_HANDOFF * handoffs)


def _summary_audit(text, report):
    """Chat-critical invariants for the concise summary. Empty list means it passed.

    Completeness (every row, every finding's full reasoning, the limits) is guaranteed by
    build_dashboard_v2 rendering the report directly — a pure code path with no relay to
    truncate — so it is NOT re-checked here. This audit protects only what the chat itself
    must carry:
      1. the verdict banner is present;
      2. every CRITICAL/HIGH cause is named AND its first fix step appears verbatim (a
         blocking cause and its action can never be relocated out of the chat);
      3. no false claim of cleanliness and no unverifiable UI claim;
      4. the summary is within its per-cause word budget.
    """
    problems = []
    norm = _norm_ws(text)
    if "**Overall:" not in text:
        problems.append("the verdict banner is missing from the summary")
    for d in rank_diagnoses(report.diagnoses):
        if severity_value(d) not in ("critical", "high"):
            continue
        title = _norm_ws(getattr(d, "title", ""))
        if title and title not in norm:
            problems.append(f"CRITICAL/HIGH cause {title[:60]!r} is not named in the summary")
        steps = list(getattr(d, "prescription", None) or [])
        if steps and _debullet(str(steps[0])) not in norm:
            problems.append(f"CRITICAL/HIGH cause's first fix step is absent: "
                            f"{_debullet(str(steps[0]))[:70]!r}")
    problems += [f"false claim of cleanliness: {h!r}" for h in _false_clean_claims(text, report)]
    problems += [f"unverifiable claim about the notebook/UI: {h!r}"
                 for h in _unverifiable_ui_claims(text)]
    words = _guide_word_count(text)
    budget = _summary_word_budget(report)
    if words > budget:
        problems.append(f"summary is {words} words, over its {budget}-word budget (+{words - budget})")
    return problems


# ---------------------------------------------------------------------------
# The guide's own acid test
# ---------------------------------------------------------------------------
# `_false_clean_claims` exists because the composer must not be trusted to be honest by
# construction. Same reasoning, one level up: the composer must not be trusted to be
# COMPLETE by construction either. The truncation this catches was live for a whole
# a pre-release run and read as finished text, so no human review caught it.
#
# Deliberately mechanical and content-blind. It compares the composed guide against the
# report's OWN fields, so it works on any report — captured, synthetic, or live — and it
# cannot be satisfied by rewording.

# Two budgets. Both come from one number, so they can be argued with rather than
# believed: technical prose is read for comprehension at roughly 190 wpm.
#
#   TIME TO ACTION — the customer's actual question was "can I name what to change and
#   where, in about thirty seconds?". Thirty-eight seconds at 190 wpm is ~120 words, so
#   the first imperative must appear within the first 120 words. This is the budget that
#   bit hardest: the pre-release guide put the top finding's fix ~190 words in, behind a
#   128-word explanation, so the answer was "no" even though the instruction was present.
#
#   TOTAL LENGTH — "the body is too long and I would not finish it". A flat total is the
#   wrong control, because the guide is not allowed to truncate an instruction: a report
#   with five faults HAS more to say than one with a single fault, and capping it would
#   force exactly the truncation this whole change exists to remove. So the budget is a
#   PER-ITEM allowance and the total is its sum — it measures verbosity, not volume.
#   Allowances, all in words, with their reading time at 190 wpm:
_GUIDE_BUDGET_SKELETON = 150       # ~47s — verdict, target, counts, limits, verification, headings
_GUIDE_BUDGET_PER_FINDING = 210    # ~66s — title, attributes, complete fix, root cause
_GUIDE_BUDGET_PER_CONTEXT = 80     # ~25s — see _context_block: a no-action row's space
                                   # (40) plus room for one protective imperative kept in
                                   # full and the pointer to the finding that supersedes
                                   # it. Not 40: capping it there would force truncating
                                   # "Do NOT change requiredNsgRules", which is the only
                                   # actionable words the card has and the reason it exists.
_GUIDE_BUDGET_PER_ACTION_ROW = 85  # ~27s — one identifying sentence + a COMPLETE instruction.
                                   # Set from measurement, not from a reading-time wish:
                                   # across the captured reports the engine's own actionable
                                   # recommendations run median 30 words, p90 56, max 60, and
                                   # a row adds ~15 for the identifying sentence and ~5 for
                                   # the label. 70 sat below the p90 row, so it flagged
                                   # reports whose only sin was carrying instructions this
                                   # code is forbidden to truncate.
_GUIDE_BUDGET_PER_QUIET_ROW = 40   # ~13s — "a no-action observation earns one sentence"
# A skipped row is NEVER given a paragraph — it is one name inside the limits list. It
# still has to be NAMED (that is the whole point of counting skips honestly).
#
# Re-measured. "Naming a layer costs about four words" stopped being true when the skip
# classes landed: the declared-skip line now names each row AND carries the shared reason
# it did not apply ("Classic-plane check (workspace VNet) — serverless egress is governed
# by the NCC..."), which measures ~10.5 words per row across the serverless shapes. Four
# was a measurement of an older sentence, so the audit was failing reports for text the
# class split deliberately added. 11 matches what the composer actually writes; it does
# not license a paragraph.
_GUIDE_BUDGET_PER_SKIP_ROW = 11
# ...but a DECLARED skip is what costs four words. An UNVERIFIED one is a gap, and since
# the skip classes landed, the limits block prints its own REASON — which is the sentence
# that stops it being misread ("this is NOT a finding that no NCC is attached"). Budgeting
# a gap at four words meant the audit failed any report that explained its blindness,
# i.e. it charged the product for the honesty it was built to have. Measured at ~50 words
# for the two account-layer gaps; 60 leaves headroom without licensing a paragraph.
_GUIDE_BUDGET_PER_UNVERIFIED_ROW = 60
# A HAND-OFF is a deliverable, not commentary, and this number is MEASURED, not chosen.
# The block carries six things, four of them added because the customer asked for them:
# who can settle it without a new grant (~50), the script's file path (~25), what the file
# collects for a security review (~50), how to resume after a one-to-two-day human wait
# (~50), the Option B fallback and why it IS the fallback (~40), and the scope note (~40).
# Measured at 271 words on the graded shape; 275 is that measurement plus nothing.
#
# Worth being precise about, since raising a budget is a smell: this is NOT absorbing the
# inline script. That payload never entered `chat_prescription` at all — it rode in the
# text the RELAY was told to add, and the prose measures 707 words before and after its
# removal. What grew here is prose the review asked to exist, and the message it lives in
# got 61% shorter.
_GUIDE_BUDGET_PER_HANDOFF = 275
_GUIDE_WORDS_TO_ACTION = 120


def _guide_word_count(text):
    """Words the customer actually reads: markdown rules are separators, not prose."""
    return len([w for w in str(text or "").split() if set(w) != {"-"}])


def guide_budget_breakdown(report):
    """(budget, {item: (count, allowance)}) — so an overage says WHICH item is verbose."""
    checks = report_rows(report)
    findings = len(actionable_diagnoses(report.diagnoses))
    context = len([d for d in (report.diagnoses or []) if severity_value(d) in ("info", "")])
    action_rows = quiet_rows = skip_rows = unverified_rows = handoffs = 0
    for _k, c in checks.items():
        if (getattr(c, "metadata", None) or {}).get(_HANDOFF_META) and \
                (getattr(c, "recommendation", "") or "").strip():
            handoffs += 1
        sv = status_value(c)
        if sv == "skip":
            # A gap prints its reason; a declared not-applicable prints its name. Two
            # different costs, so two different line items — otherwise an overage says
            # "your report is verbose" when what it means is "your report is honest".
            if is_unverified_skip(c):
                unverified_rows += 1
            else:
                skip_rows += 1
            continue
        if sv == "pass" or _is_inconclusive(c):
            continue
        if _no_action_row(c):
            quiet_rows += 1
        else:
            action_rows += 1
    items = {
        "skeleton": (1, _GUIDE_BUDGET_SKELETON),
        "findings": (findings, _GUIDE_BUDGET_PER_FINDING),
        "context cards": (context, _GUIDE_BUDGET_PER_CONTEXT),
        "actionable rows": (action_rows, _GUIDE_BUDGET_PER_ACTION_ROW),
        "no-action rows": (quiet_rows, _GUIDE_BUDGET_PER_QUIET_ROW),
        "unverified rows (named + reason)": (unverified_rows, _GUIDE_BUDGET_PER_UNVERIFIED_ROW),
        "declared skips (named only)": (skip_rows, _GUIDE_BUDGET_PER_SKIP_ROW),
        "hand-offs": (handoffs, _GUIDE_BUDGET_PER_HANDOFF),
    }
    return sum(n * w for n, w in items.values()), items


def guide_word_budget(report):
    return guide_budget_breakdown(report)[0]


def _words_to_first_imperative(text, report):
    """How far into the guide the first actionable instruction appears, in words.

    The instruction is located by the report's OWN fields — the top-ranked actionable
    finding's first prescription step, else the first fail/error row's first
    recommendation line — so this cannot be satisfied by adding a summary sentence that
    only looks like an instruction. Returns None when the report prescribes nothing.
    """
    needles = []
    ranked = rank_diagnoses(report.diagnoses)
    if ranked:
        steps = list(getattr(ranked[0], "prescription", None) or [])
        if steps:
            needles.append(_debullet(str(steps[0])))
    for _k, c in report_rows(report).items():
        if status_value(c) in ("fail", "error"):
            lines = _rec_lines(getattr(c, "recommendation", ""))
            # Skip a bare header line ("Fix peering:") — it is a label, not an
            # instruction, and counting it as the action is exactly the mistake that
            # made the truncated row look complete.
            content = [l for l in lines if len(l.split()) >= 6] or lines
            if content:
                needles.append(content[0])
    best = None
    for needle in needles:
        if not needle:
            continue
        idx = _norm_ws(text).find(needle)
        if idx < 0:
            continue
        n = _guide_word_count(_norm_ws(text)[:idx])
        best = n if best is None else min(best, n)
    return best


def _guide_audit(text, report, include_budget=True):
    """Problems in the composed guide. Empty list means it passed.

    Checks, in the order they matter:
      1. no rendered recommendation is a TRUNCATION of its source field — if the guide
         shows a recommendation's first line it must show all of them (the an earlier defect blocker);
      2. every fail/error row's recommendation appears IN FULL, because the red rows are
         where the customer's next action lives;
      3. every non-pass row is mentioned somewhere by its human name;
      4. the top-ranked actionable finding's first prescription step — the imperative —
         appears verbatim;
      5. the guide is within its word budget AND its first instruction is reachable
         inside the time-to-action budget;
      6. no false claim of cleanliness (delegates to `_false_clean_claims`);
      7. no unverifiable claim about the notebook / the customer's screen;
      8. no context card carries an action heading — a no-action card that prints a bold
         "Fix" is read as work to do (an earlier defect volume);
      9. two non-pass rows with the same check name and byte-identical message: an ENGINE
         defect the chat's row-dedupe would otherwise hide (an earlier defect #3);
     10. no row sends the customer to a resource this same report already cleared, while a
         blocking cause is established.
    """
    problems = []
    norm = _norm_ws(text)
    checks = report_rows(report)

    def _in_guide(line):
        return _debullet(line) in norm

    # (1) + (2)
    for key, c in checks.items():
        lines = _rec_lines(getattr(c, "recommendation", ""))
        if not lines:
            continue
        label = _check_label(key, c)
        rendered_any = any(_in_guide(l) for l in lines)
        missing = [l for l in lines if not _in_guide(l)]
        if status_value(c) in ("fail", "error") and missing:
            problems.append(
                f"row '{label}' is {status_value(c).upper()} but {len(missing)} of "
                f"{len(lines)} recommendation line(s) are absent from the guide, starting "
                f"{missing[0][:70]!r} — a red row's instruction must be complete")
        elif rendered_any and missing:
            problems.append(
                f"row '{label}': the guide renders part of the recommendation but drops "
                f"{len(missing)} line(s), starting {missing[0][:70]!r} — a partially "
                "rendered instruction looks complete and is not")

    # (3)
    for key, c in checks.items():
        if status_value(c) == "pass":
            continue
        label = _check_label(key, c)
        if label not in norm and str(key) not in norm:
            problems.append(f"non-pass row '{label}' ({status_value(c)}) is never mentioned")

    # (4)
    ranked = rank_diagnoses(report.diagnoses)
    if ranked:
        steps = list(getattr(ranked[0], "prescription", None) or [])
        if steps and not _in_guide(str(steps[0])):
            problems.append(
                "the top finding's imperative is not in the guide verbatim: "
                f"{_debullet(str(steps[0]))[:80]!r}")

    # (5)
    if include_budget:
        words = _guide_word_count(text)
        budget = guide_word_budget(report)
        if words > budget:
            problems.append(f"guide is {words} words, over its {budget}-word budget "
                            f"(+{words - budget})")
        first = _words_to_first_imperative(text, report)
        if first is None and (ranked or any(status_value(c) in ("fail", "error")
                                            for c in checks.values())):
            problems.append("no instruction from the report's own fields could be located in "
                            "the guide")
        elif first is not None and first > _GUIDE_WORDS_TO_ACTION:
            problems.append(f"the first instruction appears {first} words in, over the "
                            f"{_GUIDE_WORDS_TO_ACTION}-word time-to-action budget "
                            f"(~{first / 190 * 60:.0f}s of reading before anything actionable)")

    # (6)
    problems += [f"false claim of cleanliness: {h!r}" for h in _false_clean_claims(text, report)]

    # (7)
    problems += [f"unverifiable claim about the notebook/UI: {h!r}"
                 for h in _unverifiable_ui_claims(text)]

    # (8)
    for i, d in enumerate(report.diagnoses or [], start=1):
        if severity_value(d) not in ("info", ""):
            continue
        title = _norm_ws(getattr(d, "title", ""))
        if not title:
            continue
        # EVERY occurrence, not just the first: the offending heading is usually in a
        # second rendering of the same card, and stopping at the first hid it.
        for m in _re.finditer(_re.escape(title), norm):
            if "**Fix**" in norm[m.end():m.end() + 400]:
                problems.append(f"context card {title[:50]!r} prints a bold 'Fix' heading — a "
                                "no-action card must not look like work to do")
                break

    # (9) reported against the ROWS, not the text: the chat merges byte-identical rows, so
    # without this the duplication is invisible in the guide and still wrong in the JSON a
    # support ticket carries.
    by_name = {}
    for key, c in checks.items():
        if status_value(c) == "pass":
            continue
        by_name.setdefault((_check_label(key, c), _norm_ws(getattr(c, "message", ""))),
                           []).append(key)
    for (label, _msg), keys in by_name.items():
        if len(keys) > 1:
            problems.append(f"rows {', '.join(sorted(keys))} share the check name {label!r} AND a "
                            "byte-identical message, so nothing in the row distinguishes them — "
                            "the check should name the object it is about (see "
                            "check_subnet_egress_ip for the convention)")

    # (10) Deliberately keyed on the APPLIANCE ADDRESS appearing in the instruction,
    # NOT on the verb list that `_restate_redundant_appliance_recommendations` matches — a
    # rule that reused that list could only ever agree with the fix, which is false
    # confidence. Keying on the IP catches a future check that writes "open a support case
    # with the firewall team about 10.40.2.132" and never says the word "verify".
    if established_blocking_causes(report.diagnoses):
        cleared = cleared_appliances(checks)
        for key, c in checks.items():
            if status_value(c) == "pass":
                continue
            md = getattr(c, "metadata", None) or {}
            if md.get("appliance_audit_restated"):
                continue           # already restated by the engine; that is the fix working
            rec = _norm_ws(getattr(c, "recommendation", ""))
            for ip, by in cleared.items():
                if ip and ip in rec:
                    problems.append(
                        f"row {_check_label(key, c)!r} still directs the customer at {ip}, which "
                        f"'{by}' cleared in this same report, while a blocking cause is already "
                        "established — that points them at the one thing this run ruled out")
                    break
    return problems


# Human-readable network-layer labels for the chat prescription (M2 layer tag).
_LAYER_LABEL = {
    "classic-vnet": "classic — workspace VNet layer",
    "ncc-serverless": "serverless — Network policy egress layer",
    "storage": "storage account network/RBAC layer",
    # A firewall/UDR finding is about the EGRESS PATH, not the storage account's own
    # network ACLs or RBAC. Labelling it "storage account network/RBAC layer" sent the
    # customer to the wrong Azure blade : the storage account was
    # correctly configured; a Deny rule on the hub firewall was dropping the traffic.
    "forced-tunnel-egress": "classic — forced-tunnel egress path (hub firewall / UDR)",
}

# ---------------------------------------------------------------------------
# The closing line
# ---------------------------------------------------------------------------
# Field experience: the deliverable ended with "Dashboard rendered in the
# notebook cell (the displayHTML output, to the left of this chat in Genie Code)" while
# the notebook was COMPLETELY EMPTY — zero cells — and a step labelled "Render diagnostic
# dashboard in notebook cell" showed a green check. The saved .html did exist. So the last
# sentence the customer read was a confident claim about the UI that nothing had verified;
# it is the same class of defect we spent the round removing from the engine, in the most
# expensive position.
#
# Nothing in this process can observe whether a displayHTML actually painted, so the
# default text does not claim it. It asserts exactly one thing we DO know — the file was
# written, because save_dashboard_html returns "" on failure and a path on success — and
# states the inline render as a possibility with the fallback.
#
# There IS one cheap in-process signal, and it is used: `nd_render_dashboard()` is the
# function the driver tells the agent to call inside the displayHTML cell. If it ran, our
# HTML was handed to displayHTML in a notebook cell, which is precisely the fact the empty
# notebook disproves. It records that in the session and prints the upgraded line. If the
# agent renders some other way, no upgrade happens and the conservative wording stands —
# the failure mode is a weaker true sentence, never a stronger false one.

def _dashboard_pointer(html_path, handed_off=False):
    """The one line that closes the turn. Claims only what this process can verify."""
    if not html_path:
        # The save failed and we cannot see the notebook: there is nothing to point at.
        return ("I could not write the dashboard file to the workspace (the error is in the "
                "cell output above). The full findings are in the message above this line. "
                "Tell me if you want to re-verify after applying the fix.")
    line = ("The diagnosis above is the complete answer — you do not need the dashboard to "
            f"act on it. **For the per-check detail there is also a saved report** — `{html_path}`")
    if handed_off:
        # The recorded signal is narrow, so the sentence is too: our HTML reached a
        # displayHTML call in a notebook cell in this session. Whether it PAINTED, and
        # whether Genie later clobbered the cell, are still unobservable from here — hence
        # "should also appear", not "is displayed".
        line += (". The same dashboard was handed to a `displayHTML` cell in this session, so it "
                 "should also appear in that cell's output; open the saved file if it does not.")
    else:
        line += (" — open that file for the per-check detail and the evidence behind each "
                 "finding. It may also be displayed inline in a notebook cell; if you do not "
                 "see it there, the saved file is the same dashboard.")
    return line + " Tell me if you want to re-verify after applying the fix."


def _displayhtml():
    """The notebook's displayHTML, or None. It is a runtime builtin, not an import."""
    try:
        import IPython
        fn = (IPython.get_ipython().user_ns or {}).get("displayHTML")
        if callable(fn):
            return fn
    except Exception:
        pass
    try:
        from dbruntime.display import displayHTML as fn
        return fn if callable(fn) else None
    except Exception:
        return None


def nd_render_dashboard(session_path):
    """Return the saved dashboard HTML for `displayHTML(...)`, and record the hand-off.

    Called as `displayHTML(nd_render_dashboard(r'<session>'))`, which is what the driver
    prints as the render step. Returning the HTML (rather than displaying it here) keeps
    the notebook builtin in the cell where it belongs, and gives this process the one
    signal it can honestly act on: our HTML reached a displayHTML call in a notebook cell.
    """
    s = _load_session(session_path)
    html_path = (s or {}).get("report_html_path") or ""
    if not html_path:
        raise ValueError("no saved dashboard in this session — re-run the diagnosis")
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    s["dashboard_handed_off"] = True
    pointer = _dashboard_pointer(html_path, handed_off=True)
    s["dashboard_pointer"] = pointer
    if isinstance((s or {}).get("last_result"), dict):
        s["last_result"]["dashboard_pointer"] = pointer
    try:
        _save_session(s, session_path)
    except Exception:
        pass
    print("[Doctor] Dashboard HTML handed to displayHTML in this cell. CLOSE THE TURN with "
          "this exact line and nothing after it:")
    print(f"[Doctor]   {pointer}")
    return html


def _present(s, path, report):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    _rows = report_rows(report)

    # Do this BEFORE composing anything the customer reads. The
    # account-snapshot script goes to a FILE and the hand-off text quotes that file's
    # path, so the chat carries a pointer instead of 4,386 characters of Python. Both
    # surfaces are composed after the substitution, which is what stops the chat and the
    # dashboard quoting different locations for the same script.
    _acct_script, _acct_path = "", ""
    for _k, _c in _rows.items():
        if (getattr(_c, "metadata", None) or {}).get("account_dump_script"):
            _acct_script = (getattr(_c, "raw_output", "") or "").strip()
            _acct_path = save_account_snapshot_script(
                _acct_script, report, base_dir=s.get("base_dir") or None)
            _rec = getattr(_c, "recommendation", "") or ""
            if _ACCOUNT_SCRIPT_PATH_TOKEN in _rec:
                _c.recommendation = _rec.replace(
                    _ACCOUNT_SCRIPT_PATH_TOKEN,
                    f"`{_acct_path}`" if _acct_path
                    # The file write failed; say so rather than pointing at nothing.
                    else "(the file could not be written — ask me to paste the script)")
            _c.metadata = dict(_c.metadata or {}, account_script_path=_acct_path)
            break

    html = build_dashboard_v2([report], s["problem"], ts)
    html_path = save_dashboard_html(html, report, base_dir=s.get("base_dir") or None)
    pending = [d for d in (report.diagnoses or []) if getattr(d, "needs_confirmation", False)]
    res = {
        "status": "DONE",
        "session_path": path,
        "path": s["path"],
        # The CHAT gets the objective summary; the exhaustive detail (every row, each
        # finding's full Why, the Limits block, benign observations) lives in the dashboard
        # HTML built above by build_dashboard_v2 — a pure render of the report, so it cannot
        # be truncated by a relay. `_chat_prescription` remains the full-detail oracle the
        # offline guide test audits for completeness.
        "chat_prescription": _chat_summary(report),
        "dashboard_html_path": html_path,
        "dashboard_pointer": _dashboard_pointer(html_path),
        "confirmation_questions": [q for d in pending for q in (d.follow_up_questions or [])],
        "summary": report.summary,
    }
    # When the ARM layer could not be read FROM THIS RUNTIME because egress is blocked,
    # the deliverable is the "Azure ARM Reachability" row's recommendation (which egress
    # to enable + re-run) — carried in the prescription like any other row. There is no
    # offline script to hand over.
    # REUSE 2 — the account-layer hand-off. When the ACCOUNT layer could not be read,
    # the actionable deliverable is a read-only snapshot an EXISTING account admin
    # takes, not a request to make our Service Principal an account admin. The infra
    # phase generated it and parked it on the row; hoist it so the relay has something
    # to hand over. Separate key from cloud_shell_script: the two layers fail
    # independently and a run can need both.
    # Found by METADATA, not by row key (the hand-off travels on whichever account row
    # reported the refusal), and located above so the path substitution happens before
    # anything is composed.
    #
    # Deliberately the PATH and not the script text. There is no `account_snapshot_script`
    # key any more: while it existed, the relay did exactly what it was told and pasted
    # 4,386 characters into the message, and the customer skipped the two real sentences
    # that followed it. Removing the key removes the temptation — a relay cannot post a
    # payload it was never handed.
    if _acct_path:
        res["account_snapshot_script_path"] = _acct_path
    _decorate(res, s["path"])
    s["stage"] = "done"
    s["report_html_path"] = html_path
    s["last_result"] = res
    _save_session(s, path)
    print("[Doctor] DONE. PRESENT IT IN THIS ORDER:")
    if res["confirmation_questions"]:
        print("[Doctor]   0. FIRST ask the customer these confirmation question(s) and only "
              "present the matching option from the prescription:")
        for q in res["confirmation_questions"]:
            print(f"[Doctor]      - {q}")
    # the relay summarised this text and dropped the load-bearing sentences
    # (the overall status, the WARN rows, a whole diagnosis and its own "a real
    # misconfig could be invisible here" caveat). The content is now composed
    # deterministically in _chat_prescription; this instruction says plainly that it
    # is to be POSTED, not retold.
    print("[Doctor]   1. Post result['chat_prescription'] in chat VERBATIM and IN FULL — copy "
          "every section (Overall + counts, the named non-pass rows, 'Limits of this diagnosis', "
          "every Finding with its severity and fix order, Verification). Do NOT summarise it, do "
          "NOT drop a section, do NOT re-label a finding's severity, and do NOT add a sentence "
          "saying checks 'passed' or 'came back clean' — the text already states exactly which "
          "rows passed and which did not.")
    _ov = getattr(report.overall_status, "value", report.overall_status)
    _c = check_verdict_counts(report)
    print(f"[Doctor]      (overall_status={_ov}; rows: {_c['pass']} pass / {_c['warn']} warn / "
          f"{_c['fail'] + _c['error']} fail / {_c['skip']} skip / {_c['inconclusive']} inconclusive)")
    if _rows.get(_ARM_BLIND_ROW) is not None and getattr(_rows.get(_ARM_BLIND_ROW), "metadata", {}).get("arm_blind_kind") == "unreachable":
        print("[Doctor]   1b. The AZURE half of this diagnosis was NOT read (this runtime "
              "cannot reach management.azure.com — see the 'Azure ARM Reachability' row). "
              "That row's recommendation names the exact egress to enable "
              "(management.azure.com + login.microsoftonline.com) and to re-run for a LIVE "
              "diagnosis. There is NO offline snapshot. Do NOT present this run as a clean "
              "result, and if the customer's policy forbids that egress, say the Azure layer "
              "stays uninspected.")
    if _acct_path:
        # This instruction used to ask the relay to (a) paste the script and (b) restate
        # the hand-off. It obediently did both, and BOTH were defects: 4,386 characters of
        # Python that the customer scrolled past, and a second near-duplicate hand-off
        # block ~350 words after the first, whose only new content the reader had to cross
        # the wall of Python to reach. The prescription is already in
        # `chat_prescription`, VERBATIM and in the right place. So this now forbids both.
        print("[Doctor]   1c. The ACCOUNT half was NOT read. `chat_prescription` ALREADY "
              "contains the complete hand-off under 'Closing the gap' — do NOT restate it, "
              "do NOT summarise it, and do NOT write a second hand-off paragraph. Do NOT "
              "paste the script: it is a file, and its path is already quoted inside that "
              "section. Add ONE line and nothing more, so the customer can forward it: "
              f"\"The read-only account-snapshot script is saved at {_acct_path} — send that "
              "file to an existing Databricks account admin; it makes five read-only GETs, "
              "collects network configuration metadata only (no credentials, no data), and "
              "changes nothing.\" Never claim an NCC is or is not attached.")
    if html_path:
        print(f"[Doctor]   2. NEW cell: displayHTML(nd_render_dashboard(r'{path}'))")
    # do not let the closing line be improvised. It was improvising a claim that the
    # dashboard had rendered in a notebook cell, on a notebook with no cells at all.
    print("[Doctor]   3. Close the turn by posting result['dashboard_pointer'] VERBATIM, and "
          "write nothing after it. Do NOT add a sentence claiming the dashboard rendered, is "
          "visible, or is 'to the left' — this process cannot see the notebook, so that claim "
          "is not ours to make. If the cell in step 2 printed its own closing line, use that "
          "one instead: it ran later and knows more.")
    return res


def _maybe_scope_setup(s, path):
    """The customer answered the credential ask with `create` — hand over the walkthrough.

    Emitted from the driver (not left to the LLM) for the same reason every other question
    is: a NEED_INPUT question is relayed VERBATIM, so the customer gets the same three
    commands every time instead of whatever the presenter remembers of
    reference/DIAGNOSTIC_MACHINERY.md. Delivered at most once per session, and it does NOT
    answer the ask — `sp_scope` stays missing, so the normal intake question comes back if
    the customer returns without a name.
    """
    a = s["answers"]
    if not a.get(_SP_SETUP_FLAG) or a.get("sp_scope") or a.get(_SP_SETUP_DELIVERED):
        return None
    # WHICH layer asked decides which grant the walkthrough names. The account offer is
    # the only ask that wants an account admin; everything else wants Azure Reader.
    account_layer = bool(a.get(_ACCOUNT_OFFER_FLAG)) and not a.get("account_declined")
    question = _scope_setup_question(account_layer)
    a[_SP_SETUP_DELIVERED] = True
    _save_session(s, path)
    next_call = f"run_network_doctor(answers={{...}}, session_path=r'{path}')"
    res = _decorate({"status": "NEED_INPUT", "session_path": path, "path": s["path"],
                     "questions": [question], "next_step": _safe_cell(next_call)}, s["path"])
    print("[Doctor] The customer has no secret scope yet. RELAY this walkthrough VERBATIM "
          "(it is the answer to their question) and WAIT — do not summarize the commands, "
          "do not substitute a portal click-path, and do NOT treat this as a decline: the "
          "Azure inspection is still on the table.")
    print(f"[Doctor]   - {question['question']}")
    print(f"[Doctor] When they come back with the scope NAME, run this cell — LEAD IT WITH "
          f"THE SAFETY COMMENT exactly as shown:")
    print(f"[Doctor]   {_SAFETY_PREAMBLE}")
    print(f"[Doctor]   run_network_doctor(answers={{'sp_scope': '<their scope>'}}, "
          f"session_path=r'{path}')")
    return res


_CREDENTIAL_REFUSED = "_credential_refused"


def _credential_ask_is_closed(a):
    """Has the customer actually turned a credential DOWN, or just chosen a depth?

    `sp_declined` gets set two ways that mean different things, and the post-verdict
    serverless account offer is the one place that has to tell them apart. If the
    customer typed `none`, or ran out of patience with the ask, they declined: asking
    again is nagging. But if the flag came from answering `simple` at turn one, they
    declined nothing — they picked a depth BEFORE seeing any evidence, and that is a
    different question from "here is a measured finding; one credential turns it into
    the exact policy name and fix". The offer exists precisely because it is made
    informed and only once (see _serverless_account_offer), and it carries its own
    `none`, so a depth choice must not silently answer it in advance.
    """
    if not a.get("sp_declined"):
        return False
    if a.get(_CREDENTIAL_REFUSED):
        return True
    return "sp_declined" not in (a.get(_DEPTH_AUTO_DECLINED) or [])


def _count_unanswered_reply(s, replied):
    """Advance the bound for the PENDING question when a reply failed to answer it.

    See the _ASK_COUNTS comment for why this counts replies rather than turns or calls.
    Returns the count for whatever question is pending now (0 when nothing is).
    """
    a = s["answers"]
    pending = _missing_questions(s)
    now = (pending[0]["ids"][0] if pending else "")
    if replied and now and now == (a.get(_LAST_ASKED) or ""):
        counts = dict(a.get(_ASK_COUNTS) or {})
        counts[now] = int(counts.get(now) or 0) + 1
        a[_ASK_COUNTS] = counts
    a[_LAST_ASKED] = now
    return int((a.get(_ASK_COUNTS) or {}).get(now) or 0)


def _bound_intake_asks(s, path, replied):
    """Stop asking a question the customer has now failed to answer twice.

    The two bounds land differently, on purpose:

      analysis_depth -> assume `deep`, and SAY so. Every credential question below it
          still carries its own `none`, so the assumption takes nothing away — but it is
          a decision made FOR them, and making it silently had the customer answer "1",
          get no acknowledgement, and then be asked for the service principal they were
          trying to avoid.
      sp_scope       -> switch the run to `simple` and produce the credential-free
          diagnosis. There is a real answer left to give here, so an ERROR would be worse
          than a reduced result honestly labelled. The creation walkthrough is delivered
          once per session (_SP_SETUP_DELIVERED), so without this the sequence was: ask,
          walkthrough, then the same terse question every turn, with no end.

    Returns True when it changed the run, so the caller re-reads what is still missing.
    """
    a = s["answers"]
    asks = _count_unanswered_reply(s, replied)
    pending = _missing_questions(s)
    pid = (pending[0]["ids"][0] if pending else "")
    if not pid or asks < _MAX_UNANSWERED_ASKS:
        _save_session(s, path)
        return False
    if pid == "analysis_depth":
        a["analysis_depth"] = "deep"
        _normalize_answers(s)
        _save_session(s, path)
        print("[Doctor] The depth answer did not come back twice, so I am assuming `deep` "
              "(the fuller analysis). TELL THE CUSTOMER that in one line, and that "
              "answering `none` to any credential question is still open to them.")
        return True
    if pid == "compute_type":
        # There is no safe default here. Guessing the plane would decide WHICH network the
        # whole diagnosis is about, and the two are not interchangeable — so this is the one
        # bound that stops rather than proceeding. `both` is not a plane (see
        # _normalize_answers) and answering it repeatedly cannot make it one.
        _save_session(s, path)
        print("[Doctor] Asked twice which compute plane this is and did not get one of the "
              "two. Stopping rather than choosing for the customer.")
        return "STOP"
    if pid == "cluster_id":
        # This ask has to be bounded precisely BECAUSE the answer now comes from work the
        # customer goes off and does. Two replies that carry no id and we stop asking and
        # continue without the in-VNet probes — an honest reduced result, named as such,
        # rather than the same question forever. It is not a dead end: an id supplied later
        # (before the probes phase) overwrites this and the probes run.
        a["cluster_id"] = "none"
        _save_session(s, path)
        print("[Doctor] Asked twice for a cluster id and none came back, so I am continuing "
              "WITHOUT the in-VNet probes. TELL THE CUSTOMER plainly: the checks that need a "
              "machine inside the VNet are not running, the report names them as unverified, "
              "and sending the id (while this diagnosis is still going) picks them back up.")
        return True
    if pid == "sp_scope" and s["path"] in ("A", "B") and not a.get("sp_scope"):
        a["analysis_depth"] = "simple"
        a[_CREDENTIAL_REFUSED] = True  # asked and not produced: not the same as choosing
        _normalize_answers(s)
        _save_session(s, path)
        print("[Doctor] The Azure credential has been asked for twice without a scope name "
              "coming back, so I am NOT asking again — continuing with the SIMPLE "
              "analysis. TELL THE CUSTOMER plainly: the Azure configuration layer is not "
              "being inspected, the report names what that leaves unverified, and a fresh "
              "run with the scope name picks those checks back up.")
        return True
    _save_session(s, path)
    return False


def _emit_need_input(s, path):
    qs = _missing_questions(s)
    res = _decorate({"status": "NEED_INPUT", "session_path": path, "path": s["path"], "questions": qs}, s["path"])
    print(f"[Doctor] NEED_INPUT (path {s['path']}). RELAY this ONE question to the customer "
          "VERBATIM and WAIT — do not paraphrase, do not add other asks, no diagnosis yet "
          "(the driver asks one thing at a time on purpose):")
    for q in qs:
        print(f"[Doctor]   - {q['question']}")
    ids = sorted({i for q in qs for i in q["ids"]})
    # Surface-minimization: pass ONLY sp_scope (key names default), and build the
    # answers dict in a prior neutral cell rather than inlining credential-shaped
    # keys next to an external host:port (that combination over-triggers the gate).
    next_call = f"run_network_doctor(answers={{...}}, session_path=r'{path}')"
    res["next_step"] = _safe_cell(next_call)
    print(f"[Doctor] Then run this cell — LEAD IT WITH THE SAFETY COMMENT exactly as shown "
          f"(it materially reduces safety-gate denials):")
    print(f"[Doctor]   {_SAFETY_PREAMBLE}")
    print(f"[Doctor]   run_network_doctor(answers={{...}}, session_path=r'{path}')  "
          f"# fill these keys: {ids}")
    print("[Doctor] Keep the answers dict minimal: pass only sp_scope unless your key "
          "names are non-default. The SP needs Azure READER only (Account-Admin/SP with "
          "write roles over-triggers the 'privilege-escalating' classifier).")
    return res


def _emit_in_progress(s, path, next_call):
    safe_call = _safe_cell(next_call)
    res = _decorate({"status": "IN_PROGRESS", "session_path": path, "path": s["path"],
                     "next_step": safe_call}, s["path"])
    print("[Doctor] NEXT — run this in a NEW cell, LEADING with the safety comment exactly "
          "as shown (reduces safety-gate denials):")
    print(f"[Doctor]   {_SAFETY_PREAMBLE}")
    print(f"[Doctor]   {next_call}")
    print(f"[Doctor] (open {res.get('reference_doc', '')} for this path's procedure)")
    return res


# ---------------------------------------------------------------------------
# Stage handlers
# ---------------------------------------------------------------------------

def _probe_plane_from_checkpoint(s):
    """"classic" once a probe row RECORDS that it ran in the VNet, else "".

    The context is rebuilt every turn and the phases run on separate turns, so a
    measurement taken during the probes phase has to be read back from the checkpoint —
    otherwise the infra phase, which is what asks whether the probes ran inside the VNet,
    never sees it and the report calls the plane unproven immediately after proving it.

    Still a MEASUREMENT, not an intent: the flag is only stamped when the instance-metadata
    endpoint actually answered on the cluster that ran the probes.
    """
    path = (s or {}).get("checkpoint_path") or ""
    if not path:
        return ""
    try:
        rows = (load_checkpoint(path).get("checks") or {})
    except Exception:
        return ""
    for row in rows.values():
        if isinstance(row, dict) and (row.get("metadata") or {}).get("probe_plane_confirmed"):
            return "classic"
    return ""


def _arm_absent_reason(a):
    """Why the Azure layer was not read, when the reason is the customer's own choice.

    The report's skip rows fall back to "No Azure SP secret references provided", which is
    the right text when we asked and got nothing and the wrong text when the customer
    picked the analysis that does not use a credential — it reads as "you withheld this"
    for a choice we offered as legitimate. orchestrator._ARM_NOT_CONSULTED exists for
    exactly this reason ("never tell a customer they withheld a credential when the
    credential would have answered nothing"); the depth fork needs the same care.

    Returns "" whenever a credential exists, so a real ARM failure still names its own
    cause instead of being papered over by this.
    """
    if _sp_refs(a):
        return ""
    if a.get(_CREDENTIAL_REFUSED):
        return ("the Azure credential was asked for and was not available, so the Azure "
                "configuration was not read; re-running with the secret scope name settles "
                "these layers")
    if "sp_declined" in (a.get(_DEPTH_AUTO_DECLINED) or []):
        return ("you chose the simple analysis, which uses no Azure credential — these "
                "layers were not read, rather than read and found wanting")
    return ""


def _ctx_for_A(s):
    a = s["answers"]
    ctx = {
        "compute_type": a.get("compute_type", "serverless"),
        "azure_checker": None,
        "azure_sp": _sp_refs(a),
        "ncc_config": None,   # filled below when the customer provided an account_id
        "cluster_id": (a.get("cluster_id") or "") if str(a.get("cluster_id", "")).lower() != "none" else "",
        # Enables the classic topology-first egress trace in the infra phase. Only a
        # real /subscriptions/... value is surfaced; `none`/declined resolves to "".
        "workspace_arm_id": (a.get("workspace_arm_id") or "")
            if a.get("workspace_arm_id", "").startswith("/subscriptions/") else "",
        # Tells the infra phase this is a "validate my setup" audit rather than a real
        # failing target, so it also traces a representative EGRESS destination. Without
        # it the audit only checks the workspace control plane, which back-end Private
        # Link always satisfies — reporting healthy while egress is black-holed.
        "_target_is_workspace_audit": bool(a.get("_target_is_workspace_audit")),
        # Switch the ARM half of the infra phase off when nothing on this run has an
        # Azure resource to read: a serverless-only problem reaching a destination that
        # is not an Azure resource. Every classic-plane check would plane-skip anyway,
        # so the only effect of building the checker is a full subscription/RG/VNet
        # discovery sweep that answers nothing — and the SP here is still needed, for
        # the ACCOUNT API token, so it cannot simply be withheld from the context.
        "skip_arm_layer": (a.get("compute_type") == "serverless"
                           and not _serverless_target_is_azure_resource(a)),
        # WHERE THE PROBES RAN, measured — not the plane the problem is about. Only
        # `"classic"` is assertable (IMDS answered ⇒ a real VNet VM); IMDS silence proves
        # nothing, so we leave it unset and the consumer treats that as unknown. See
        # models.probes_measured_data_plane_vnet for why this is separate from compute_type.
        # MEASURED, never inferred. On serverless this stays "" and the remote probe run
        # below is what sets it to "classic" — measured on the cluster that actually ran
        # the probes, not on the runtime that dispatched them. Reading IMDS here alone was
        # the bug: the driver runs on serverless, so it answered False even when the
        # customer had supplied a running classic cluster for exactly this purpose.
        "probe_runtime": ("classic" if a.get("_imds_classic")
                          else _probe_plane_from_checkpoint(s)),
        # Consumed by the NCC rows' destination gate. The NCC is a PRIVATE-ENDPOINT
        # mechanism (its rules name an Azure resource id + group id), so on a public
        # destination it is the wrong layer and its rows must not appear at all — what
        # governs that case is the network policy's egress allow-list.
        "target_is_azure_resource": _serverless_target_is_azure_resource(a),
    }
    # Only when there is something better to say than the default, and never over
    # `skip_arm_layer`, whose own reason (an Azure SP would answer nothing here) is more
    # specific. The key is added rather than set to "" because the infra phase seeds it
    # with setdefault — an empty value would still count as present and win.
    # WHERE THE PROBES MUST RUN. A classic problem's probes belong on the customer's
    # classic cluster: a probe measures the network of the machine that executes it, so a
    # result taken in this serverless notebook is evidence about a different VNet, a
    # different DNS and a different egress path. The intake already collects the cluster
    # (and provisions one on `create`); until now nothing consumed it.
    #
    # Serverless deliberately gets NO plan. Serverless egress does not traverse the
    # customer VNet at all, so there is nothing in there to measure — that answer lives in
    # the account layer (the NCC and the serverless network policy), which is where the
    # serverless path already looks.
    _cid = str(a.get("cluster_id") or "").strip()
    if a.get("compute_type") == "classic" and _cid and _cid.lower() != "none":
        try:
            _ws = get_workspace_context()
        except Exception:
            _ws = {}
        if _ws.get("workspace_url") and _ws.get("token"):
            ctx["probe_on_cluster"] = {
                "workspace_url": _ws["workspace_url"], "token": _ws["token"],
                "cluster_id": _cid}
        else:
            print("[Doctor] A classic cluster was supplied but this session has no "
                  "workspace URL/token, so the probes cannot be dispatched to it. They "
                  "will run here and the report will say the plane is unproven.")

    if not ctx["skip_arm_layer"]:
        _absent = _arm_absent_reason(a)
        if _absent:
            ctx["azure_infra_error"] = _absent
    try:
        ctx["ws_ctx"] = get_workspace_context()
    except Exception:
        ctx["ws_ctx"] = {}
    if a.get("account_id"):
        # Token is minted INSIDE the infra phase from the same SP (account-admin
        # required); customer supplies only the account id — never a token value.
        ctx["ncc_config"] = {
            "account_host": a.get("account_host") or "https://accounts.azuredatabricks.net",
            "account_id": a["account_id"],
            "workspace_id": (ctx["ws_ctx"] or {}).get("workspace_id", ""),
            "token": "",
        }
    return ctx

_ACCOUNT_OFFER_FLAG = "_account_offer_made"
_ACCOUNT_REOPENED_FLAG = "_account_layer_reopened"


def _serverless_account_offer(s, path):
    """PROBES FIRST, credential second — the serverless account-layer offer.

    The in-session probes cost the customer nothing and, on serverless, already carry
    the verdict: if the name resolves and the TCP connect to the port times out, egress
    from the serverless plane is being blocked, and the blocking layer can only be the
    account layer (the workspace VNet is not on this path at all). Reading the NCC and
    the serverless network policy does not establish THAT — it names WHICH policy and
    yields the exact fix.

    So the credential is asked for here, once the evidence exists, instead of during
    intake: the customer sees a real finding before being asked for anything, and a run
    that turns out healthy is never asked at all. (Before this, a serverless
    `%pip install` run was met with two credential questions — an Azure Reader SP and an
    account UUID — before it had shown a single measurement, as a live smoke test
    showed.)

    Returns a NEED_INPUT result to relay, or None to finalize normally.
    """
    a = s["answers"]
    if s["path"] != "A" or a.get("compute_type") != "serverless":
        return None
    # Already answered, already declined, or already asked once: never ask twice — a
    # second ask would read as the loop the intake version was.
    if (a.get("account_id") or a.get("account_declined")
            or _credential_ask_is_closed(a) or a.get(_ACCOUNT_OFFER_FLAG)):
        return None
    if not s.get("checkpoint_path"):
        return None
    try:
        rows = (load_checkpoint(s["checkpoint_path"]).get("checks") or {})
    except Exception:
        return None

    def _st(name):
        return str((rows.get(name) or {}).get("status", "")).lower()

    # Only offer when the probes FOUND something to prescribe against. A clean run has
    # no fix to name, so the account read would add nothing worth a credential ask.
    failing = [n for n in ("dns", "tcp", "tls") if _st(n) in ("fail", "error")]
    if not failing:
        return None
    def _label(name):
        # Checkpoint rows are DICTS, so check_label's attribute lookup would miss the
        # human name it already carries and fall back to the internal key ("Tcp").
        return (rows.get(name) or {}).get("check_name") or _check_label(name, None)

    evidence = ", ".join(
        f"{_label(n)}: {(rows.get(n) or {}).get('message', '') or _st(n)}"
        for n in ("dns", "tcp", "tls") if _st(n))

    # API-FIRST, and here it is FREE: the credential-less discovery avenues (session
    # spark confs, an already-loaded account snapshot) need no SP at all, so try them
    # before putting a UUID in front of the customer. When one hits, the ask shrinks to
    # the secret scope alone.
    question = dict(_ACCOUNT_CRED_QUESTION)
    if not a.get("account_id"):
        acc, src = discover_account_id(None)
        if acc:
            a["account_id"] = acc
            a["_account_discovery_log"] = f"self-discovered via {src}"
            print(f"[Doctor] Databricks account id SELF-DISCOVERED via {src} — not asking for it.")
            question = dict(
                _ACCOUNT_CRED_QUESTION,
                ids=["sp_scope", "sp_declined", "sp_tenant_key", "sp_client_key",
                     "sp_secret_key"],
                question=(
                    "To name the exact policy and give you the exact fix I need to read your "
                    "Databricks ACCOUNT configuration — the serverless network policy attached "
                    "to this workspace, whose egress allow-list decides whether serverless "
                    "compute may reach this destination. I already have your account id. What is the NAME "
                    "of the Databricks Secrets scope holding a service principal that is an "
                    "**account admin on your Databricks account**? (this is a Databricks "
                    "account grant — Azure Reader is NOT what it needs, and no Azure "
                    "permission helps here). If you don't have such a scope yet, answer "
                    "`create` and I'll walk you through making it. Or answer `none` and "
                    "I'll stand on the probe evidence I already have."))
        else:
            a["_account_discovery_log"] = src

    a[_ACCOUNT_OFFER_FLAG] = True
    _save_session(s, path)
    host = a.get("target_host", "")
    next_call = f"run_network_doctor(answers={{...}}, session_path=r'{path}')"
    res = _decorate({
        "status": "NEED_INPUT", "session_path": path, "path": "A",
        "interim_finding": (
            f"Measured from this serverless session: {evidence}. Serverless compute does "
            f"not egress through your workspace VNet, so reaching `{host}` is governed by "
            f"the Databricks account layer — {_governing_layer_phrase(a)}. "
            "That is where this is being blocked."),
        "questions": [question],
        "next_step": _safe_cell(next_call),
    }, "A")
    print(f"[Doctor] Serverless probes are in and they already establish the LAYER: {evidence}")
    print("[Doctor] NEED_INPUT — RELAY the finding FIRST (it is already an answer), then this "
          "ONE question VERBATIM:")
    print(f"[Doctor]   - {question['question']}")
    print("[Doctor] Do NOT ask for an Azure credential here: on serverless the governing "
          "layer is the Databricks ACCOUNT layer (accounts.azuredatabricks.net), which "
          "requires ACCOUNT ADMIN — an Azure Reader SP cannot read it, and no ARM read is "
          "involved in this answer.")
    print(f"[Doctor] Name the layer as {_governing_layer_phrase(a)} — do NOT call it the NCC "
          "unless the target is an Azure resource reached over a private endpoint.")
    print(f"[Doctor] Then run this cell, LEADING with the safety comment exactly as shown:")
    print(f"[Doctor]   {_SAFETY_PREAMBLE}")
    print(f"[Doctor]   {next_call}  # fill these keys: {sorted(question['ids'])}")
    return res


def _maybe_reopen_for_account_layer(s, path):
    """The account credential arrived AFTER the infra phase already ran, so the three
    account-layer rows are sitting in the checkpoint as skips. `_run_phase` resumes by
    running only checks with no outcome yet, so without clearing them the credential the
    customer just supplied would change nothing. Clear those rows and put the session
    back on the infra stage; `_ctx_for_A` now builds `ncc_config`, so they run for real.

    Returns a NEED_INPUT result when the scope arrived without the account id and the id
    could not be discovered — otherwise a scope-only answer finalized in silence."""
    a = s["answers"]
    if (s.get("stage") != "finalize" or not a.get(_ACCOUNT_OFFER_FLAG)
            or a.get(_ACCOUNT_REOPENED_FLAG) or not s.get("checkpoint_path")):
        return None

    # A SCOPE-ONLY answer. The offer asks for two values in one turn, so a relay can
    # easily return just the secret scope. The account id is unavoidable for the account
    # API (it is in the URL path), and the intake-time discovery block cannot help here —
    # this session is long past intake, so it never runs again. The result was the worst
    # possible shape: the customer supplied a credential, the account layer was never
    # read, and NOTHING said why. Try the SP-backed discovery avenue now (it needs a token,
    # which only exists once the scope arrives), and if that fails ask for the ONE missing
    # value rather than finalizing quietly.
    if not a.get("account_id") and not a.get("account_declined"):
        if not a.get("sp_scope"):
            return None                    # nothing supplied at all -> finalize as offered
        if not a.get("_account_discovery_log_sp"):
            try:
                sp_vals = load_azure_sp_from_secrets(_get_dbutils(), _sp_refs(a))
            except Exception as e:
                a["_account_discovery_log_sp"] = f"the secret scope could not be read: {e}"
                print(f"[Doctor] Account-id discovery could not read the scope '{a.get('sp_scope')}' ({e}).")
            else:
                acc, src = discover_account_id(sp_vals)
                a["_account_discovery_log_sp"] = f"self-discovered via {src}" if acc else src
                if acc:
                    a["account_id"] = acc
                    print(f"[Doctor] Databricks account id SELF-DISCOVERED via {src} — the scope "
                          "was enough after all; not asking the customer.")
                else:
                    print(f"[Doctor] Account-id self-discovery with the SP did not succeed ({src}).")
            _save_session(s, path)
        if not a.get("account_id"):
            # BOUND IT. This emit site is outside _missing_questions, so _bound_intake_asks
            # never reaches it, and the ask re-fires every turn while the id is missing.
            # Same counter, same key space as every other ask: a reply that leaves this
            # question pending advances it, and at the bound the run finalizes with the
            # account layer honestly marked as not inspected.
            _counts = dict(a.get(_ASK_COUNTS) or {})
            if (a.get(_LAST_ASKED) or "") == "account_id":
                _counts["account_id"] = int(_counts.get("account_id") or 0) + 1
                a[_ASK_COUNTS] = _counts
            a[_LAST_ASKED] = "account_id"
            if int(_counts.get("account_id") or 0) >= _MAX_UNANSWERED_ASKS:
                a["account_declined"] = True
                a.pop("_account_id_unparsed", None)
                _save_session(s, path)
                print("[Doctor] Asked twice for the Databricks account id without getting one, "
                      "so I am NOT asking again — finalizing with the NCC layer NOT inspected. "
                      "TELL THE CUSTOMER that plainly: the report names it as unverified, and a "
                      "fresh run with the account id picks those checks back up.")
                return None
            a["_account_discovery_log"] = a.get("_account_discovery_log") or a["_account_discovery_log_sp"]
            q = _account_id_question(a)
            next_call = f"run_network_doctor(answers={{...}}, session_path=r'{path}')"
            print("[Doctor] The secret scope arrived but the ACCOUNT ID did not, and I could not "
                  "discover it. Asking for that ONE value — finalizing here would drop the account "
                  "read the customer just supplied a credential for, without saying so.")
            print(f"[Doctor]   - {q['question']}")
            print(f"[Doctor]   {next_call}  # fill these keys: {sorted(q['ids'])}")
            return _decorate({"status": "NEED_INPUT", "session_path": path, "path": "A",
                              "questions": [q], "next_step": _safe_cell(next_call)}, "A")

    if not a.get("account_id"):
        return None
    try:
        cleared = reopen_checks(s["checkpoint_path"], sorted(_SERVERLESS_PLANE_CHECKS))
    except Exception as e:
        print(f"[Doctor] Could not reopen the account-layer checks ({e}) — finalizing on the "
              "probe evidence instead of silently claiming the account layer was read.")
        return None
    a[_ACCOUNT_REOPENED_FLAG] = True
    s["stage"] = "infra"
    _save_session(s, path)
    print(f"[Doctor] Account credential received — re-running the account-layer checks "
          f"({', '.join(cleared) or 'none were recorded'}) to name the exact policy.")
    return None


def _stage_A(s, path):
    a = s["answers"]
    host, port = a["target_host"], int(a.get("target_port") or 443)
    pending = _maybe_reopen_for_account_layer(s, path)
    if pending is not None:
        return pending
    ctx = _ctx_for_A(s)
    nxt = f"run_network_doctor(session_path=r'{path}')"
    if s["stage"] == "ready":
        ckpt_path = s.get("checkpoint_path") or os.path.join(
            _session_dir(s.get("base_dir") or None),
            _re.sub(r"[^A-Za-z0-9._-]", "_", f"{host}_{port}") + ".ckpt.json")
        ck = start_diagnosis(host, port, ctx, checkpoint_path=ckpt_path)
        s["checkpoint_path"], s["stage"] = str(ck), "infra"
        _save_session(s, path)
        return _emit_in_progress(s, path, nxt)
    if s["stage"] == "infra":
        continue_diagnosis(s["checkpoint_path"], ctx)
        pending = [p for p in ("probes", "infra")
                   if p not in load_checkpoint(s["checkpoint_path"])["phases_done"]]
        if not pending:
            s["stage"] = "finalize"
        _save_session(s, path)
        return _emit_in_progress(s, path, nxt)
    # finalize
    offer = _serverless_account_offer(s, path)
    if offer is not None:
        return offer
    report = finalize_diagnosis(s["checkpoint_path"], _ctx_for_A(s))
    return _present(s, path, report)

def _emit_path_c_egress_blocked(s, path, reason):
    """ARM is unreachable from this runtime. There is NO offline snapshot: tell the
    customer exactly which egress to enable, then re-run for a LIVE diagnosis."""
    a = s["answers"]
    a["_egress_block_offered"] = True
    _save_session(s, path)
    question = (
        "I can't reach Azure ARM (management.azure.com) from the compute I'm running on, "
        f"so I have NOT inspected your Azure network config yet ({reason}). This is an "
        "EGRESS block, not a permissions problem — and I don't work from an offline "
        "snapshot, because a cluster-start problem has to be read from your live config.\n\n"
        "Enable outbound HTTPS to `management.azure.com` and `login.microsoftonline.com` "
        "from this compute, then reply `ready` (or just re-run me) and I'll do the live "
        "diagnosis:\n"
        "- **Serverless**: Account Console > Settings > Network — add those two endpoints "
        "to the account network policy / NCC egress allow-list (account-admin; a narrow, "
        "reversible allow-list entry, not opening the internet).\n"
        "- **Classic**: the data-plane subnet's route table / NSG / hub firewall must "
        "permit outbound HTTPS to those two endpoints.\n\n"
        "If your security policy forbids that egress, I can't inspect the Azure layer from "
        "here — that's a deliberate limitation of your environment, and I'll say the Azure "
        "layer was not inspected rather than guess a cause from the error text."
    )
    print(f"[Doctor] NEED_INPUT (path C) — Azure ARM is UNREACHABLE from this runtime "
          f"({reason}). There is NO offline fallback. RELAY the egress guidance VERBATIM: "
          "enable outbound HTTPS to management.azure.com + login.microsoftonline.com "
          "(serverless: Account Console > Settings > Network / NCC; classic: the data-plane "
          "subnet route table / NSG / firewall), then re-run for the LIVE diagnosis. If "
          "their policy forbids that egress, say the Azure layer stays uninspected — do NOT "
          "present this as a finished or clean result.")
    return _decorate({"status": "NEED_INPUT", "session_path": path, "path": "C",
                      "questions": [{"ids": ["egress_enabled"],
                                     "question": question}],
                      "reason": reason,
                      "next_step": _safe_cell(
                          f"run_network_doctor(answers={{...}}, session_path=r'{path}')")},
                     "C")


def _stage_C(s, path):
    a = s["answers"]
    arm_id = a.get("workspace_arm_id", "")
    if not str(arm_id).startswith("/subscriptions/"):
        msg = ("Path C cannot run without the workspace ARM resource id "
               "(`/subscriptions/.../providers/Microsoft.Databricks/workspaces/<name>`). "
               "I will not guess a root cause from the error text. Paste the ARM id to continue.")
        print(f"[Doctor] ERROR: {msg}")
        return {"status": "ERROR", "session_path": path, "path": "C", "error": msg}

    # No offline path any more. Before asking anyone for a credential, probe whether
    # THIS runtime can reach management.azure.com AT ALL — that probe needs no token
    # (a bare 401 proves the network path is open). If it can't, the deliverable is
    # the egress to enable, not a snapshot and not a credential we can't use yet.
    reach = probe_arm_reachability()
    if not reach.get("ok") and not reach.get("reachable"):
        return _emit_path_c_egress_blocked(
            s, path, reason=reach.get("reason", "no route to management.azure.com"))

    refs = _sp_refs(a)
    if not refs or a.get("sp_declined"):
        # ARM is reachable but Path C reads the Azure config through a Reader SP and has
        # no credential-free version. Say so — the intake SP ask (with its `create`
        # walkthrough) is where they get one; a decline finalizes with the Azure layer
        # honestly marked not inspected.
        print("[Doctor] Path C needs a read-only Service Principal to inspect the Azure "
              "config; none was provided. The Azure layer will be reported as NOT inspected.")
        report = diagnose_cluster_start(s["problem"], arm_id, arm_token="")
        return _present(s, path, report)

    try:
        sp = load_azure_sp_from_secrets(_get_dbutils(), refs)
    except Exception as e:
        print(f"[Doctor] ERROR: could not read the SP from secret scope '{refs['scope']}': {e}")
        print("[Doctor] Fix the scope/key names and call run_network_doctor(answers={...}, "
              f"session_path=r'{path}') again with the corrected names.")
        return {"status": "ERROR", "session_path": path, "error": str(e)}
    tok = get_arm_token(sp["tenant_id"], sp["client_id"], sp["client_secret"])
    if tok["error"]:
        print(f"[Doctor] ERROR: ARM token mint failed: {tok['error']}")
        return {"status": "ERROR", "session_path": path, "error": tok["error"]}

    # LIVE ONLY. Re-probe with the real token: a genuine egress block (no HTTP response)
    # means guide-to-egress; a reachable-but-401/403 is an RBAC issue that
    # diagnose_cluster_start surfaces per-check, so let it run and report that honestly.
    probe = probe_arm_reachability(tok["token"])
    if not probe.get("ok") and not probe.get("reachable"):
        return _emit_path_c_egress_blocked(
            s, path, reason=probe.get("reason", "no route to management.azure.com"))
    report = diagnose_cluster_start(s["problem"], arm_id, arm_token=tok["token"])
    return _present(s, path, report)


# ---------------------------------------------------------------------------
# Path B — storage / UC access. Network BEFORE RBAC; the Diagnosis is SELECTED
# in code (the "pick ONE diagnosis" step the agent used to free-lance).
# ---------------------------------------------------------------------------

def _nsp_grants_access(nsp):
    return bool(
        nsp and nsp.metadata.get("has_nsp") and nsp.metadata.get("has_databricks_rule")
        and any(m.lower() == "enforced" for m in (nsp.metadata.get("access_modes") or []))
    )

def _compose_storage_diagnosis(fqdn, fw, nsp, ac_in_rules, roles, ac_id, egress_trace=None):
    """Pick EXACTLY ONE Diagnosis from the check outcomes, network before RBAC.

    Returns list[Diagnosis] (0 or 1). This replaces the hand-authored
    'pick ONE diagnosis' step in the old prose Path B.

    egress_trace (CLASSIC consumers only): a topology.trace() result. If a forced-
    tunnel HUB FIREWALL drops the storage egress, that is the root cause and OUTRANKS
    every storage-account-ACL tier below — the account's own firewall/NSP/RBAC are
    moot when the packet never leaves the hub. (Serverless never reaches here: _stage_B
    only builds egress_trace for classic consumers; serverless storage egress is an
    NCC/storage-perimeter concern.)
    """
    # 0) Hub firewall in the forced-tunnel path drops storage egress (classic).
    if (egress_trace and egress_trace.get("status") == "fail"
            and (egress_trace.get("blocking_gate") or {}).get("kind") == "firewall"):
        # Path B builds the trace directly (no topology_egress_path CHECK exists here),
        # so attribute the evidence to the trace itself rather than to a check that
        # never ran.
        d = make_egress_firewall_diagnosis(egress_trace, source="topology_trace")
        if d is not None:
            return [d]

    network_blocked = bool(fw and fw.status == Status.FAIL) and not _nsp_grants_access(nsp)
    nsp_learning = bool(nsp and nsp.metadata.get("has_nsp")) and not _nsp_grants_access(nsp)

    # publicNetworkAccess=Disabled with NO approved Private Endpoint is an ABSOLUTE
    # block: Disabled shuts down the public endpoint entirely, so NSP/service tags
    # (incl. an NSP in Learning) have NO effect — enforcing the NSP would not fix
    # access. So this hard block must OUTRANK storage_nsp_not_enforced as the PRIMARY
    # root cause (M2 / ROUND #1 storage fix-order). Detect it from the firewall
    # check's metadata rather than re-reading ARM.
    _fw_md = (fw.metadata if fw else {}) or {}
    pubnet_disabled_no_pe = (
        bool(fw and fw.status == Status.FAIL)
        and str(_fw_md.get("public_network_access", "")).lower() == "disabled"
        and int(_fw_md.get("approved_pe_count", 0) or 0) == 0
    )

    # 0) Hard network block first: publicNetworkAccess Disabled + no PE. Ranked
    #    ABOVE NSP-Learning because flipping the NSP to Enforced cannot restore
    #    access while the public endpoint is Disabled.
    if pubnet_disabled_no_pe:
        return [Diagnosis(
            pattern_id="storage_no_network_path",
            title="No Network Path to Storage (publicNetworkAccess Disabled, no PE)",
            severity=Severity.CRITICAL, confidence="high",
            root_cause=(
                f"Storage account `{fqdn}` has publicNetworkAccess=Disabled with no approved Private "
                "Endpoint. The public endpoint is shut down entirely, so service tags and any NSP "
                "(including one in Learning/Enforced) have NO effect — there is simply no network path "
                "for serverless to reach it. This OUTRANKS the NSP state: enforcing the NSP would not "
                "restore access while publicNetworkAccess stays Disabled. RBAC is irrelevant until a "
                "path exists."),
            evidence=[(c.check_name, c.message) for c in (fw, nsp) if c],
            prescription=[
                "Give serverless a private path — EITHER create an NCC Private Endpoint rule to the "
                "storage account (sub-resource dfs/blob), approve the PE on the storage account, wait "
                "for ESTABLISHED; OR change publicNetworkAccess to 'Enabled from selected virtual "
                "networks and IP addresses' and configure + ENFORCE an NSP with the "
                "AzureDatabricksServerless inbound rule.",
                "Re-test the serverless query after the path is established (~2-5 min propagation)."],
            fix_order=1)]

    # 1) NSP exists but not Enforced (Learning / missing Databricks rule) — the
    #    actionable fix is to enforce it. Covers the network-blocked case where
    #    an NSP is present, AND the Enabled+Deny case where NSP is the gate.
    if nsp_learning and (network_blocked or ac_in_rules is False):
        modes = ", ".join(nsp.metadata.get("access_modes") or []) or "unknown"
        return [Diagnosis(
            pattern_id="storage_nsp_not_enforced",
            title="NSP Present but NOT Enforced (Serverless Blocked at the Network Perimeter)",
            severity=Severity.HIGH, confidence="high",
            root_cause=(
                f"Storage account `{fqdn}` has a Network Security Perimeter but it is not granting "
                f"access (accessMode: {modes}; Databricks rule present: "
                f"{nsp.metadata.get('has_databricks_rule')}). Learning mode is audit-only — it does "
                "NOT enforce the inbound rule, so serverless traffic is dropped at the perimeter even "
                "though classic compute (on the customer VNet) still works. This is a NETWORK block, "
                "not an RBAC problem."),
            evidence=[(c.check_name, c.message) for c in (fw, nsp) if c],
            prescription=[
                "Flip the NSP resource association from Learning to ENFORCED: Azure Portal > Network "
                "Security Perimeters > <perimeter> > Resources > the storage account's association > "
                "set accessMode = Enforced (or `az network perimeter ... association update "
                "--access-mode Enforced`).",
                "Confirm the perimeter has an inbound rule for the `AzureDatabricksServerless.<region>` "
                "service tag; add it if missing.",
                "Re-test the serverless query after ~2-5 min for propagation."],
            fix_order=1)]

    # 2) No path to storage at all (publicNetworkAccess Disabled, no PE, no Enforced NSP).
    if network_blocked:
        return [Diagnosis(
            pattern_id="storage_no_network_path",
            title="No Network Path to Storage (publicNetworkAccess Disabled, no PE, no Enforced NSP)",
            severity=Severity.CRITICAL, confidence="high",
            root_cause=(
                f"Storage account `{fqdn}` has publicNetworkAccess=Disabled with no approved Private "
                "Endpoint and no Enforced NSP granting serverless. Serverless compute has no network "
                "path to reach it — RBAC is irrelevant until a path exists."),
            evidence=[(c.check_name, c.message) for c in (fw, nsp) if c],
            prescription=[
                "Give serverless a private path — create an NCC Private Endpoint rule to the storage "
                "account (sub-resource dfs/blob), approve the PE on the storage account, wait for "
                "ESTABLISHED; OR provision an NSP and ENFORCE it with the AzureDatabricksServerless "
                "inbound rule.",
                "Re-test the serverless query after the path is established."],
            fix_order=1)]

    # 3) Enabled+Deny but the Access Connector is not in resourceAccessRules.
    if ac_in_rules is False:
        return [Diagnosis(
            pattern_id="storage_ac_missing_from_firewall",
            title="Access Connector Missing from the Storage Firewall Allow-List",
            severity=Severity.HIGH, confidence="high",
            root_cause=(
                f"Storage account `{fqdn}` has publicNetworkAccess=Enabled + defaultAction=Deny, and the "
                "workspace's Access Connector is NOT in the storage's resourceAccessRules. Serverless "
                "is admitted only via a Resource Instance Rule (or NSP), so it is blocked at the "
                "firewall — classic compute may still work via virtualNetworkRules, which is not a "
                "substitute for serverless."),
            evidence=[(c.check_name, c.message) for c in (fw, nsp) if c],
            prescription=[
                "Storage account > Networking > Resource instances > Add: Resource type "
                "`Microsoft.Databricks/accessConnectors`, Instance name "
                f"`{ac_id or '<access connector id>'}`.",
                "Re-test the serverless query after ~2-5 min."],
            fix_order=1)]

    # 4) Network OK but RBAC missing (Storage Blob Delegator / data role).
    if roles is not None and roles.status == Status.FAIL:
        missing = ", ".join(roles.metadata.get("missing_roles") or []) or "required storage role(s)"
        return [Diagnosis(
            pattern_id="storage_rbac_missing",
            title="Access Connector Identity Missing Storage Role(s)",
            severity=Severity.HIGH, confidence="high",
            root_cause=(
                f"The network path to `{fqdn}` is open, but the Access Connector's managed identity is "
                f"missing required role(s): {missing}. Serverless uses a User Delegation SAS, which "
                "needs Storage Blob Delegator on the account plus a data-plane role."),
            evidence=[(roles.check_name, roles.message)],
            prescription=[
                f"Storage account > Access Control (IAM) > Add role assignment: grant {missing} to the "
                "Access Connector's managed identity.",
                "Re-test after ~5 min for role propagation."],
            fix_order=1)]

    return []  # network + RBAC both clean — no blocking storage issue


def _resolve_storage_target(s, path, ws):
    """Decide WHAT this Path B run diagnoses, and say why. Never fatal.

    Order of preference:
      1. the Unity Catalog table, when the customer named one AND UC resolves it —
         that also gives us the catalog, hence the Access Connector, hence RBAC;
      2. the storage ACCOUNT / HOST the customer gave us — enough for every network
         check (firewall, NSP, resource instance rules, forced-tunnel egress);
      3. nothing usable -> ask ONE more question (NEED_INPUT), never ERROR-and-stop.

    Returns (target, need_input_result). Exactly one is non-None. `target` is a dict:
      fqdn, account, table_info, ac_id, degraded (str reason or ""), note (str).
    """
    a = s["answers"]
    full_table = str(a.get("full_table") or "").strip()
    table_info = {"catalog_name": "", "storage_location": "", "storage_account": "",
                  "container": "", "error": ""}
    degraded = ""

    if full_table:
        table_info = get_table_storage_info(ws["workspace_url"], ws["token"], full_table)
        if table_info.get("error") or not table_info.get("storage_account"):
            degraded = (table_info.get("error")
                        or f"Unity Catalog returned no storage location for `{full_table}`")
            # this used to `return {"status": "ERROR"}` — zero checks, no report, no
            # diagnoses, while the account and host were already in the answers. A table
            # lookup is one INPUT to the diagnosis, never a precondition for running it.
            print(f"[Doctor] Could not resolve table `{full_table}`: {degraded}. NOT fatal — "
                  "falling back to diagnosing the storage account/host directly.")
            a["_table_unresolved"] = degraded
            _save_session(s, path)

    hint_account, hint_host = _storage_target_from_answers(a)

    if table_info.get("storage_account"):
        account = table_info["storage_account"]
        fqdn = f"{account}.dfs.core.windows.net"
        note = (f"Unity Catalog table `{full_table}` resolves to storage account `{account}` "
                f"(container {table_info.get('container') or '?'}).")
    elif hint_account or hint_host:
        account = hint_account
        fqdn = hint_host or f"{account}.dfs.core.windows.net"
        if degraded:
            note = (f"Diagnosing storage account `{account or fqdn}` DIRECTLY, because the table "
                    f"lookup failed: {degraded}. The credential chain (catalog -> storage "
                    "credential -> Access Connector) and anything that depends on it (RBAC) could "
                    "not be traced, so those layers are unverified in this report.")
        elif full_table:
            note = f"Diagnosing storage account `{account or fqdn}` (table `{full_table}`)."
        else:
            note = (f"Diagnosing storage account `{account or fqdn}` directly — no Unity Catalog "
                    "table was supplied, so the credential chain and RBAC are not traced.")
    else:
        # Nothing to point at. Ask once more instead of aborting.
        s["stage"] = "intake"
        _save_session(s, path)
        print("[Doctor] No usable storage target yet (no resolvable table, no storage account, no "
              "host) — asking for one rather than stopping.")
        return None, _emit_need_input(s, path)

    ac_id = ""
    if table_info.get("catalog_name"):
        ac_info = get_access_connector_for_table(ws["workspace_url"], ws["token"],
                                                 table_info["catalog_name"])
        ac_id = (ac_info or {}).get("access_connector_id", "")
    return {"fqdn": fqdn, "account": account, "table_info": table_info, "ac_id": ac_id,
            "degraded": degraded, "note": note}, None


def _target_check(target):
    """A first report row that states WHICH target was diagnosed and WHY.

    WARN when the run degraded off the customer's stated table: the report is still
    useful, but it did not answer the exact question that was asked and must say so.
    """
    degraded = bool(target["degraded"]) or not target["table_info"].get("storage_account")
    return CheckResult(
        check_name="Diagnostic Target",
        target=target["fqdn"],
        status=Status.WARN if degraded else Status.PASS,
        message=target["note"],
        recommendation=("Re-run with the failing `catalog.schema.table` when you have it, and I will "
                        "also trace the credential chain (catalog -> storage credential -> Access "
                        "Connector) and its RBAC." if degraded else ""),
        metadata={"degraded_target": degraded, "storage_account": target["account"]})


def _degraded_target_diagnosis(target):
    """Carry the scope limitation into the diagnosis list, not just a check row, so the
    chat text states it even when no storage rule fired. INFO + low confidence is the
    engine's existing way of saying "I could not fully conclude" (see
    models.cannot_conclude), which also keeps the headline off a clean PASS."""
    if target["table_info"].get("storage_account"):
        return []            # the table resolved: full credential chain + RBAC were traced
    why = (f"I could not resolve the Unity Catalog table ({target['degraded']})"
           if target["degraded"] else "No Unity Catalog table was supplied")
    return [Diagnosis(
        pattern_id="storage_target_degraded",
        title="Diagnosed the Storage Account, Not a Unity Catalog Table",
        severity=Severity.INFO, confidence="low",
        root_cause=(f"{why}, so I diagnosed `{target['fqdn']}` directly. Every storage NETWORK "
                    "layer in this report was checked against the real account; the credential "
                    "chain (catalog -> storage credential -> Access Connector) and the "
                    "Access-Connector RBAC were NOT traced, so a permission-side cause could be "
                    "invisible in this report."),
        prescription=["Re-run with the failing `catalog.schema.table` (or grant the caller USE "
                      "CATALOG / SELECT on it) and I will add the credential chain + RBAC layers."],
        fix_order=98)]


def _stage_B(s, path):
    a = s["answers"]
    try:
        ws = get_workspace_context()
    except Exception as e:
        print(f"[Doctor] ERROR: could not read workspace context: {e}")
        return {"status": "ERROR", "session_path": path, "error": str(e)}

    # S3 — pick the target: the table when it resolves, else the account/host.
    target, need_input = _resolve_storage_target(s, path, ws)
    if need_input is not None:
        return need_input
    fqdn, table_info, ac_id = target["fqdn"], target["table_info"], target["ac_id"]

    # Without an SP we can only report the credential chain — be honest, do not guess RBAC/network.
    if a.get("sp_declined") or not _sp_refs(a):
        chain_traced = bool(table_info.get("storage_account"))
        checks = [
            _target_check(target),
            CheckResult("Table / Credential Chain", fqdn,
                        Status.PASS if chain_traced else Status.SKIP,
                        (f"catalog={table_info['catalog_name']}, storage={table_info['storage_account']}, "
                         f"access_connector={ac_id or '(unresolved)'}") if chain_traced else
                        ("Not traced — no Unity Catalog table resolved, so catalog / storage "
                         "credential / Access Connector are unknown for this target.")),
            CheckResult("Storage Firewall", fqdn, Status.SKIP, "Skipped — no Azure SP provided (network not checked)."),
            CheckResult("Network Security Perimeter", fqdn, Status.SKIP, "Skipped — no Azure SP provided."),
            CheckResult("Storage Role Assignments", fqdn, Status.SKIP, "Skipped — no Azure SP provided (RBAC not checked)."),
        ]
        diag = [Diagnosis(
            pattern_id="storage_needs_sp", title="Cannot Determine Root Cause Without an Azure Reader SP",
            severity=Severity.INFO, confidence="low",
            root_cause=(("Traced the credential chain, but a" if chain_traced else "A")
                        + " storage PERMISSION_DENIED can be RBAC OR a "
                        "network block (firewall / NSP Learning / missing Resource Instance Rule). "
                        "Without a Reader SP I can't read the storage network config or role assignments "
                        "to tell which — so I won't guess."),
            prescription=["Provide a Databricks-backed Reader SP (scope + key names) and re-run; I'll "
                          "check firewall/NSP/Resource-Instance-Rule (network first) then RBAC."],
            needs_confirmation=False, fix_order=1)] + _degraded_target_diagnosis(target)
        return _present(s, path, build_storage_report(fqdn, checks, diag,
                        ("Credential chain traced; network/RBAC pending an Azure SP." if chain_traced
                         else f"Target {fqdn}; network/RBAC pending an Azure SP.")))

    # S5 — Azure ARM checks. Network BEFORE RBAC.
    sp = load_azure_sp_from_secrets(_get_dbutils(), _sp_refs(a))
    tok = get_arm_token(sp["tenant_id"], sp["client_id"], sp["client_secret"])
    if tok["error"]:
        print(f"[Doctor] ERROR: ARM token mint failed: {tok['error']}")
        return {"status": "ERROR", "session_path": path, "error": tok["error"]}
    # The ARM lookup keys on the ACCOUNT NAME, which we now have from the table OR
    # straight from the customer — the two are interchangeable here.
    sa = find_storage_account_scope(tok, target["account"])
    if sa["error"]:
        print(f"[Doctor] ERROR locating storage account `{target['account']}` in ARM: {sa['error']}")
        return {"status": "ERROR", "session_path": path, "error": sa["error"]}

    fw = check_storage_firewall(tok, sa["scope"])
    # Pass the firewall result: the "no NSP" verdict depends on the account's topology
    # (public endpoint state + approved private endpoints), and without it the check used to
    # contradict the firewall row printed directly above it.
    nsp = check_storage_nsp(tok, sa["scope"], firewall=fw)

    # Slice 3 — CLASSIC consumer egress to storage through a forced-tunnel hub firewall.
    # Only when the consumer is classic (VNet-injected) AND the workspace ARM id is
    # known: trace whether a hub firewall in the 0.0.0.0/0 path drops the storage FQDN.
    # The storage account's own ACLs can be perfectly clean while the egress firewall
    # silently drops it — and that firewall, not the storage perimeter, is the cause.
    # Serverless never builds this (its egress is account-level NCC, handled elsewhere).
    egress_trace = None
    _ws_arm = a.get("workspace_arm_id", "")
    if _ws_arm.startswith("/subscriptions/") and a.get("compute_type", "").lower() == "classic":
        try:
            from topology import build_topology, trace as _topo_trace
            _topo = build_topology(tok, _ws_arm, compute_type="classic")
            _subnets = (_topo.roots or {}).get("subnet_ids") or []
            if _subnets:
                egress_trace = _topo_trace(_topo, _subnets[0], fqdn, 443, category="storage")
        except Exception:
            egress_trace = None

    # Resource Instance Rule (Enabled+Deny only): is the AC in resourceAccessRules?
    ac_in_rules = None
    if fw.metadata.get("public_network_access") == "Enabled" and fw.metadata.get("default_action") == "Deny":
        rules = fw.metadata.get("resource_rules") or []
        ac_in_rules = bool(ac_id) and any(
            (r.get("resourceId", "") or "").lower() == ac_id.lower() for r in rules)

    # RBAC only when the network is not blocked (network before RBAC).
    roles = None
    if not (fw.status == Status.FAIL and not _nsp_grants_access(nsp)) and ac_id:
        princ = resolve_access_connector_principal(tok, ac_id)
        if princ["error"]:
            print(f"[Doctor] Could not resolve AC principal ({princ['error']}); skipping RBAC, "
                  "reporting network findings.")
        else:
            roles = check_storage_roles(tok, sa["scope"], princ["principal_id"])

    checks = [_target_check(target), fw, nsp]
    if ac_in_rules is None:
        checks.append(CheckResult("Resource Instance Rule (AC)", fqdn, Status.SKIP,
                                  "Not applicable — firewall topology does not require resourceAccessRules."))
    elif ac_in_rules:
        checks.append(CheckResult("Resource Instance Rule (AC)", fqdn, Status.PASS,
                                  "Access Connector present in resourceAccessRules."))
    else:
        checks.append(CheckResult("Resource Instance Rule (AC)", fqdn, Status.FAIL,
                                  "Access Connector NOT in resourceAccessRules — serverless blocked at firewall."))
    # Say WHY RBAC was not evaluated. "network blocked before RBAC" was printed even
    # when the real reason was that no Access Connector could be resolved (which is the
    # normal case for an account/host target) — a wrong reason sends the customer to the
    # wrong blade.
    if roles is not None:
        checks.append(roles)
    elif not ac_id:
        checks.append(CheckResult(
            "Storage Role Assignments", fqdn, Status.SKIP,
            "Not evaluated — no Access Connector could be resolved for this target (no Unity "
            "Catalog table was resolved), so there is no identity whose role assignments to read.",
            recommendation="Re-run with the failing catalog.schema.table to include the RBAC layer."))
    else:
        checks.append(CheckResult(
            "Storage Role Assignments", fqdn, Status.SKIP,
            "Skipped — network blocked before RBAC could be evaluated."))
    if egress_trace and egress_trace.get("status") in ("fail", "warn"):
        _gate = egress_trace.get("blocking_gate") or {}
        checks.append(CheckResult(
            "Forced-Tunnel Firewall Egress", fqdn,
            Status.FAIL if egress_trace["status"] == "fail" else Status.WARN,
            egress_trace.get("reason", ""),
            recommendation=egress_trace.get("recommendation", ""),
            metadata={"egress_trace": True, **_gate}))

    diagnoses = (_compose_storage_diagnosis(fqdn, fw, nsp, ac_in_rules, roles, ac_id,
                                            egress_trace=egress_trace)
                 + _degraded_target_diagnosis(target))
    for _d in diagnoses:  # M2 layer tag — storage diagnoses are storage-plane
        if not getattr(_d, "layer", ""):
            _d.layer = "storage"
    return _present(s, path, build_storage_report(fqdn, checks, diagnoses))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _drive_network_doctor(problem_text="", answers=None, session_path="", base_dir=None, fresh=False):
    """The diagnosis itself. Call `run_network_doctor` instead: it is the public
    entry point and adds the crash guarantees (no raw traceback reaches the
    customer, and a cluster we provisioned is torn down).
    """
    if session_path:
        path = session_path
        s = _load_session(path)
    else:
        if not (problem_text or "").strip():
            raise ValueError("First call needs problem_text (the customer's message / error paste).")
        path = _session_path_for(problem_text, base_dir)
        if os.path.exists(path) and fresh:
            try:
                old = _load_session(path)
                if old.get("checkpoint_path") and os.path.exists(old["checkpoint_path"]):
                    os.remove(old["checkpoint_path"])
            except Exception:
                pass
            os.remove(path)
            print("[Doctor] fresh=True — previous session discarded; starting a new diagnosis.")
        if os.path.exists(path):
            s = _load_session(path)
            if s.get("stage") == "done":
                # A FINISHED diagnosis from an earlier conversation must never be
                # served silently as if it were current (observed in the field).
                # the offer itself has to carry the two facts that decide it: HOW
                # OLD the previous run is in wall-clock terms, and whether the diagnostic
                # code has changed since. Presented without those, "view the previous
                # diagnosis" is a staleness trap in the one situation where it matters
                # most: the customer is re-running because they changed something.
                age = _session_age(s)
                changed = _build_changed(s)
                res = {"status": "STALE_SESSION", "session_path": path,
                       "previous_updated": s.get("updated", ""),
                       "previous_age": age,
                       "build_changed": changed,
                       "fresh_call": "run_network_doctor(problem_text, fresh=True)"}
                if changed:
                    print(f"[Doctor] STALE_SESSION — a previous diagnosis for this exact problem "
                          f"exists, from {age}, but the DIAGNOSTIC CODE HAS CHANGED since it ran "
                          f"(build {s.get('build', '?')} -> {_build_fingerprint()}). Its findings "
                          "are superseded, so I will not present them as current.")
                    print("[Doctor]   - Re-run now: run_network_doctor(problem_text, fresh=True)")
                    print("[Doctor] Tell the customer the earlier result predates a change to the "
                          "diagnostic and is being re-run, rather than offering it to them.")
                    return res
                print(f"[Doctor] STALE_SESSION — a previous diagnosis for this exact problem "
                      f"already exists, from {age}. It reflects your environment AS IT WAS THEN: "
                      "if anything has changed since (including a fix you just applied), re-run.")
                print(f"[Doctor]   - View that earlier result ({age}): "
                      f"run_network_doctor(session_path=r'{path}')")
                print("[Doctor]   - Start a NEW diagnosis: run_network_doctor(problem_text, fresh=True)")
                print("[Doctor] Ask the customer which they want if unclear, and quote the age when "
                      "you ask.")
                res["view_call"] = f"run_network_doctor(session_path=r'{path}')"
                return res
            print("[Doctor] Resuming existing session (this is normal after a reset; do not delete it).")
        else:
            s = {"schema": _SESSION_SCHEMA, "problem": problem_text.strip(),
                 "path": _classify(problem_text), "stage": "intake", "answers": {},
                 "checkpoint_path": "", "base_dir": base_dir or "",
                 # which build of the diagnostic produced this session, so a later
                 # resume can refuse to present findings from superseded code.
                 "build": _build_fingerprint(),
                 "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            host, port = _extract_target(problem_text)
            if s["path"] == "A" and host:
                s["answers"]["target_host"] = host
                if port:
                    s["answers"]["target_port"] = port
            if s["path"] == "C":
                s["answers"]["nhc_error_text"] = "present"
            if s["path"] == "B":
                m = _UC_TABLE_RE.search(problem_text or "")
                if m:
                    s["answers"]["full_table"] = ".".join(m.groups())
                # the failing storage host is very often already in the customer's
                # first message ("...cannot read abfss://...@<acct>.dfs.core.windows.net/...").
                # Reading it here means one fewer question, and it is the fallback target
                # if the table cannot be resolved.
                _acct, _host = _storage_ref_from_text(problem_text or "")
                if _acct:
                    s["answers"].setdefault("storage_account", _acct)
                if _host:
                    s["answers"].setdefault("storage_host", _host)

    if answers:
        s["answers"].update({k: v for k, v in answers.items() if v not in (None, "")})
    # Normalize on EVERY call, not just when the caller passed answers. The runtime
    # autofill lives in here, and gating it on `answers` meant it could never run on the
    # first turn — so the customer was asked for a compute type the driver could already
    # read from its own Spark conf (observed in the field).
    _normalize_answers(s)

    if (s.get("path") == "C"
            and s["answers"].get("workspace_arm_declined")
            and not str(s["answers"].get("workspace_arm_id") or "").startswith("/subscriptions/")):
        msg = ("Path C cannot run without the workspace ARM resource id "
               "(`/subscriptions/.../providers/Microsoft.Databricks/workspaces/<name>`). "
               "I will not guess a root cause from the error text. Paste the ARM id to continue.")
        print(f"[Doctor] ERROR: {msg}")
        return {"status": "ERROR", "session_path": path, "path": "C", "error": msg}

    if s["stage"] == "done":
        # refuse to re-serve findings produced by a build that no longer exists.
        # Nothing about the cached result would tell the reader it predates a change to
        # the diagnostic itself, and a fresh notebook / fresh kernel does not help.
        if _build_changed(s):
            print(f"[Doctor] STALE_SESSION — this stored result is from {_session_age(s)} and was "
                  f"produced by a DIFFERENT build of the diagnostic (build {s.get('build', '?')} "
                  f"-> {_build_fingerprint()}). I will not present superseded findings as current.")
            print("[Doctor]   - Re-run now: run_network_doctor(problem_text, fresh=True)")
            return {"status": "STALE_SESSION", "session_path": path,
                    "previous_updated": s.get("updated", ""),
                    "previous_age": _session_age(s), "build_changed": True,
                    "fresh_call": "run_network_doctor(problem_text, fresh=True)"}
        res = s.get("last_result") or _decorate(
            {"status": "DONE", "session_path": path, "path": s["path"],
             "dashboard_html_path": s.get("report_html_path", "")}, s["path"])
        print(f"[Doctor] This session is already DONE — presenting the SAME result again from "
              f"{_session_age(s)} (nothing re-ran; it describes your environment as it was then). "
              "For a re-verification after a fix, start a fresh call with the problem text plus "
              "'re-verify'.")
        return res

    # Before any stage dispatch: a pending `create` is a question the customer asked US,
    # and it can arrive at ANY point — at intake, or in reply to the post-verdict account
    # offer (stage `finalize`). Answering it here covers every ask site at once.
    setup = _maybe_scope_setup(s, path)
    if setup is not None:
        return setup

    if s["stage"] in ("intake", "ready") or _missing_questions(s):
        # API-FIRST account-id discovery (a user requirement): before
        # asking the customer for the account id, the doctor tries to find it
        # itself (session spark confs + account-API redirect probe via the SP).
        a = s["answers"]
        if (s["path"] == "A" and a.get("compute_type") == "serverless"
                and a.get("sp_scope") and "account_id" not in a
                and not a.get("account_declined") and "_account_discovery_log" not in a):
            sp_vals = {}
            try:
                sp_vals = load_azure_sp_from_secrets(_get_dbutils(), _sp_refs(a))
            except Exception:
                pass
            acc, src = discover_account_id(sp_vals)
            if acc:
                a["account_id"] = acc
                a["_account_discovery_log"] = f"self-discovered via {src}"
                print(f"[Doctor] Databricks account id SELF-DISCOVERED via {src} — "
                      "no need to ask the customer.")
            else:
                a["_account_discovery_log"] = src
                print(f"[Doctor] Account-id self-discovery attempted without success ({src}) — "
                      "falling back to asking the customer.")
            _save_session(s, path)

        if _missing_questions(s):
            # Terminate instead of asking a third time. A workspace audit that cannot
            # resolve the workspace's own hostname has nothing to diagnose, and asking
            # again cannot change that — so say what is blocked and what would unblock
            # it, rather than looping (which is what this did before: the same intake
            # question, turn after turn, with no report and no explanation).
            _aud = s["answers"]
            if _aud.get("_workspace_audit_unresolved") and not _aud.get("target_host"):
                _aud["_workspace_audit_asks"] = int(_aud.get("_workspace_audit_asks") or 0) + 1
                _save_session(s, path)
            if (int(_aud.get("_workspace_audit_asks") or 0) >= 3
                    and not _aud.get("target_host")):
                print("[Doctor] Giving up on the workspace audit after 3 attempts — the "
                      "workspace hostname was never resolved or supplied.")
                return _decorate({
                    "status": "ERROR", "session_path": path, "path": s["path"],
                    "error": "workspace audit could not resolve a target",
                    "next_step": "No cell to run. Relay the message below and stop.",
                    "message": (
                        "I can't run a general validation of this workspace: I could not "
                        "detect its hostname from this session, and I wasn't given one. To "
                        "continue, either tell me a specific destination that is failing "
                        "(host and port), or paste the workspace URL — it looks like "
                        "`adb-<digits>.<n>.azuredatabricks.net` and is in your browser's "
                        "address bar. Nothing was changed and no diagnosis was produced."),
                }, s["path"])
            # Bound whatever is pending, for the same reason the audit above is
            # bounded. `bool(answers)` is what makes this count the CUSTOMER's replies:
            # a bare re-invocation of the same cell is not a second refusal.
            _stop = _bound_intake_asks(s, path, bool(answers))
            if _stop == "STOP":
                return _decorate({
                    "status": "ERROR", "session_path": path, "path": s["path"],
                    "error": "compute plane not established",
                    "next_step": "No cell to run. Relay the message below and stop.",
                    "message": (
                        "I need to know whether this is failing on SERVERLESS or on CLASSIC "
                        "compute before I can diagnose anything, and I cannot pick for you: "
                        "they are two different networks, so the checks and the fixes differ "
                        "entirely. Classic egresses through your own VNet; serverless does "
                        "not touch that VNet and is governed by your Databricks account's "
                        "network policy.\n\nStart again and answer `serverless` or "
                        "`classic`. If it is failing on both, run one diagnosis for each — "
                        "that gives you two correct answers instead of one mixed-up "
                        "report."),
                }, s["path"])
        if _missing_questions(s):
            s["stage"] = "intake"
            _save_session(s, path)
            return _emit_need_input(s, path)
        s["stage"] = "ready"
        _save_session(s, path)

    if s["path"] == "C":
        return _stage_C(s, path)
    if s["path"] == "B":
        return _stage_B(s, path)
    return _stage_A(s, path)


# ---------------------------------------------------------------------------
# Public entry point: the crash guarantees
# ---------------------------------------------------------------------------
# One thing must never happen in a customer's notebook, and before this wrapper it
# could: a raw Python traceback as the answer. Any bug below this line (in the
# orchestrator, the correlation engine, the report builder) propagated out of the
# cell. The customer's takeaway is "the tool is broken", with no indication of what
# to do, and the relaying model has nothing to present.
#
# There used to be a second guarantee here — tearing down a diagnostic cluster this
# engine had provisioned, because nothing else ever deleted it. The doctor no longer
# creates compute in a customer workspace at all (see _CLUSTER_QUESTION), so there is
# no cluster of ours to leak and nothing to clean up: any cluster in play is one the
# customer made and owns.

def _decorate_result(res):
    """Guarantee the routing fields on a result, whatever produced it.

    `_decorate` needs a path label; a result may carry it in `res["path"]`, or only
    reach us with a `session_path` whose session knows it. Falls back to leaving the
    result untouched rather than guessing a path — a wrong reference_doc would send
    the model to the wrong procedure, which is worse than none.
    """
    if isinstance(res, dict) and res.get("status") == "DONE" and not res.get("next_step"):
        # SKILL.md: "Every result also carries ... a one-line inline summary inside
        # result["next_step"]". DONE shipped without one — and DONE is the turn with the
        # MOST for the relay to get right: post the prescription, THEN render, THEN the
        # pointer. In the field the model went straight to rendering and the customer
        # saw no diagnosis at all. The [Doctor] prints said the order; the result dict, which
        # is what the model reads back, said nothing. An earlier fix added reference_doc at
        # this same boundary and did not check DONE, because the test only covered the
        # error paths.
        _sp = res.get("session_path") or ""
        res["next_step"] = (
            "Finalize in THIS order. 1) Post result['chat_prescription'] in chat VERBATIM "
            "and IN FULL — before anything else, and never a summary of it. "
            f"2) In a NEW cell: displayHTML(nd_render_dashboard(r'{_sp}')). "
            "3) Post result['dashboard_pointer'] verbatim and write nothing after it.")
    if not isinstance(res, dict) or res.get("reference_doc"):
        return res
    label = res.get("path") or ""
    if not label:
        sp = res.get("session_path") or ""
        if sp and os.path.exists(sp):
            try:
                label = (_load_session(sp) or {}).get("path") or ""
            except Exception:
                label = ""
    return _decorate(res, label) if label else res


def run_network_doctor(problem_text="", answers=None, session_path="", base_dir=None, fresh=False):
    """Drive the whole diagnosis. See module docstring for the call protocol.

    fresh=True discards a finished session for the same problem text and starts
    over (use when the customer asks for a NEW diagnosis of a recurring issue).

    Never raises: an unexpected failure comes back as status ERROR so the caller
    has something to relay, and any cluster this diagnosis provisioned is torn
    down first.
    """
    # A missing problem_text is the CALLER's protocol mistake, not a fault in the
    # tool — keep it a precise instruction instead of dressing it up as an
    # internal error below.
    if not session_path and not (problem_text or "").strip():
        print("[Doctor] The first call needs problem_text — pass the customer's own message "
              "VERBATIM: run_network_doctor(problem_text=\"<their message>\").")
        return {"status": "ERROR", "session_path": "",
                "error": "missing problem_text on the first call",
                "message": ("The first call needs the customer's message. Pass their own "
                            "words verbatim as problem_text — it is what classifies the "
                            "diagnostic path."),
                # SKILL.md promises next_step on every result. There is no path yet,
                # so there is no reference_doc to name — but the caller still needs to
                # be told what to do, and it must not look like a cell to execute.
                "next_step": ("No cell to run. Call run_network_doctor(problem_text=...) "
                              "again with the customer's own words.")}
    try:
        res = _drive_network_doctor(problem_text=problem_text, answers=answers,
                                    session_path=session_path, base_dir=base_dir,
                                    fresh=fresh)
        # SKILL.md:218 promises reference_doc on EVERY result. Individual return
        # sites drifted from that — 12 of them (every early ERROR, and both
        # STALE_SESSION paths) returned bare dicts, so the model lost its routing
        # exactly when a run went wrong or served a stale verdict. Decorating each
        # site invites the same drift again with the next one added, so it happens
        # once here, at the only door the caller comes through.
        return _decorate_result(res)
    except Exception as exc:
        path = session_path or ""
        if not path and (problem_text or "").strip():
            try:
                path = _session_path_for(problem_text, base_dir)
            except Exception:
                path = ""
        # SKILL.md: "Every result also carries result["reference_doc"] ... and a
        # one-line inline summary inside result["next_step"]". A crash result is
        # still a result the model has to route on, so recover the path from the
        # session when there is one and decorate it like any other return.
        path_label = ""
        if path and os.path.exists(path):
            try:
                path_label = (_load_session(path) or {}).get("path") or ""
            except Exception:
                path_label = ""
        detail = f"{exc.__class__.__name__}: {exc}"
        print(f"[Doctor] The diagnostic hit an unexpected error and stopped: {detail}")
        print("[Doctor] RELAY to the customer: the diagnostic could not finish, this is a "
              "fault in the tool and not in their environment, and nothing in their "
              "infrastructure was changed. Do NOT present a diagnosis — there isn't one.")
        return _decorate({
            "status": "ERROR",
            "session_path": path,
            "path": path_label,
            "error": detail,
            "next_step": ("No cell to run. Relay the message below to the customer and "
                          "stop — there is no diagnosis to present."),
            "message": ("The network diagnostic stopped on an unexpected internal error. "
                        "Nothing in your environment was changed, and no diagnosis was "
                        "produced. Re-running may succeed; if it does not, send the detail "
                        "below to whoever provided this tool."),
            "traceback": _traceback.format_exc(),
        }, path_label)
