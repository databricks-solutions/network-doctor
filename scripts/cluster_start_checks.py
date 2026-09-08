"""Cluster-start failure diagnostics for the Network Connectivity Doctor.

Diagnoses why a classic VNet-injected cluster cannot enter RUNNING state
(typical signal: X_NHC_CONTROL_PLANE_HTTP_ERROR / "Network configuration failure").

The broken cluster cannot run probes, so every check here is ARM-only and
runs from serverless. The customer pastes the NHC error block; we parse it
to find the failed entities and HTTP error codes, then validate the workspace's
data-plane network configuration against the VNet-inject requirements.

Importable module: sibling scripts resolve via sys.path (the skill dir is
inserted by SKILL.md Step 1). Also works exec-loaded for back-compat.
"""

import ipaddress as _ipaddress
import re as _re
import time as _time

from models import CheckResult, Status


# ---------------------------------------------------------------------------
# NHC error parser (pure text, fully unit-testable)
# ---------------------------------------------------------------------------

_NHC_ENTITY_RE = _re.compile(
    r'entity:\s*"(?P<entity>[^"]+)"\s*'
    r'outcome:\s*"(?P<outcome>[^"]+)"\s*'
    r'duration_sec:\s*(?P<duration>[\d.]+)\s*'
    r'message:\s*"(?P<message>(?:[^"\\]|\\.)*)"\s*'
    r'last_error_code:\s*(?P<code>\d+)',
    _re.DOTALL,
)

_NHC_FAILED_COMPONENTS_RE = _re.compile(
    r'X_NHC_(?P<bucket>[A-Z_]+)_HTTP_ERROR\s+(?P<count>\d+)\s+failed component\(s\):\s*(?P<components>[^\n]+?)(?=\s+Retryable:)',
)

# Fallback for the failed-component line when the X_NHC_*_HTTP_ERROR prefix is
# absent (e.g. X_NHC_STORAGE_SSL_ERROR, or text the agent reworded). Matches the
# bare "N failed component(s): internet storage" form.
_NHC_FAILED_COMPONENTS_SIMPLE_RE = _re.compile(
    r'(?P<count>\d+)\s+failed component\(s\)\s*:\s*(?P<components>[^\n]+?)(?=\s+Retryable:|\n|$)',
    _re.IGNORECASE,
)

# Fallback entity matcher for FLATTENED / reworded NHC text where the strict
# quoted form (entity: "x" outcome: "y" duration_sec: N message: "..."
# last_error_code: N) is gone. Real-world cause: the agent rewords the raw
# termination_reason before pasting, dropping quotes/duration/last_error_code,
# which left the strict regex with 0 entities (observed in the field on a
# hub-spoke workspace). This catches `entity: host outcome: ssl_error` with optional
# quotes and trailing message/last_error_code.
_NHC_ENTITY_SIMPLE_RE = _re.compile(
    r'entity:\s*"?(?P<entity>[A-Za-z0-9][A-Za-z0-9._-]*)"?\s+'
    r'outcome:\s*"?(?P<outcome>[A-Za-z_]+)"?'
    r'(?:[^\n]*?last_error_code:\s*(?P<code>\d+))?',
    _re.IGNORECASE,
)

_NHC_RETRYABLE_RE = _re.compile(r'Retryable:\s*(true|false)')


def parse_nhc_error(error_text):
    """Parse an NHC error block from a Databricks compute event.

    Args:
        error_text: Raw text the customer pasted from the "Terminating" or
            "Add nodes failed" event. Expected to contain the X_NHC_*
            error code, failed component list, and one or more entity:
            outcome: lines.

    Returns:
        dict with keys:
          - is_nhc: bool — True if this looks like an NHC failure
          - error_code: e.g. "X_NHC_CONTROL_PLANE_HTTP_ERROR" or ""
          - failed_components: list[str] (e.g. ["control_plane internet"])
          - retryable: bool or None
          - entities: list of dicts with entity, outcome, duration_sec,
                      message, last_error_code (int)
          - signals: dict of derived hints for correlation rules:
              - workspace_url: str (first *.azuredatabricks.net entity)
              - workspace_401: bool (workspace front door returned 401)
              - workspace_403: bool
              - databricks_com_403: bool (www.databricks.com returned 403)
              - any_dns_failure: bool
    """
    text = error_text or ""

    error_code = ""
    m = _re.search(r'(X_NHC_[A-Z_]+)', text)
    if m:
        error_code = m.group(1)

    # Non-NHC classic cluster launch-failure signatures. These are NOT the
    # canonical X_NHC_* control-plane health-check codes, but they are still
    # classic VNet-injected clusters that never reached RUNNING — and the root
    # cause is frequently a customer-side Azure misconfiguration (broken subnet
    # delegation, missing required NSG rules, forced-tunnel UDR, DNS, private
    # link) that the same ARM checks surface. A SERVICE_FAULT / launch-failure
    # classification is a SYMPTOM, not proof of a Databricks-side bug, so we
    # still route these into the cluster-start ARM diagnostic.
    _LAUNCH_FAILURE_PATTERNS = [
        ("X_UnexpectedLaunchFailure", r'X_UnexpectedLaunchFailure'),
        ("UNEXPECTED_LAUNCH_FAILURE", r'UNEXPECTED_LAUNCH_FAILURE'),
        ("UNEXPECTED_LAUNCH_FAILURE", r'Unexpected failure during launch'),
        ("WORKER_ENVIRONMENT_MISSING", r'No such workerEnvironment'),
        ("SERVICE_FAULT", r'\bSERVICE_FAULT\b'),
        # Azure cluster-start termination codes that ARE network-configuration
        # failures. These arrive as a bare Reason: code with no "won't start"
        # prose, and used to fall through to Path A (which then asked for a
        # host:port the customer does not have). They are Path C by definition:
        # the fault is between the data-plane VM and the control plane / egress,
        # which is exactly what the ARM-level Path C diagnosis reads.
        ("NPIP_TUNNEL_SETUP_FAILURE", r'NPIP_TUNNEL_SETUP_FAILURE'),
        ("NPIP_TUNNEL_SETUP_FAILURE", r'Ngrok\s+setup\s+timeout'),
        ("NETWORK_CONFIGURATION_FAILURE", r'NETWORK_CONFIGURATION_FAILURE'),
        ("SUBNET_EXHAUSTED_FAILURE", r'SUBNET_EXHAUSTED_FAILURE'),
        ("CONTROL_PLANE_REQUEST_FAILURE", r'CONTROL_PLANE_REQUEST_FAILURE'),
        ("DRIVER_UNREACHABLE", r'\bDRIVER_UNREACHABLE\b'),
        ("SECURITY_DAEMON_REGISTRATION_EXCEPTION", r'SECURITY_DAEMON_REGISTRATION_EXCEPTION'),
    ]
    launch_failure_signatures = []
    for label, pat in _LAUNCH_FAILURE_PATTERNS:
        if _re.search(pat, text):
            launch_failure_signatures.append(label)
    # PLAIN-LANGUAGE LAUNCH STATE. A customer whose cluster will not start
    # usually does not paste an error code; they describe the state: "stuck at
    # Finding instances", "never comes up", "won't start". In the field that
    # exact wording classified to Path A three separate times, and Path A then asks
    # for a failing host:port which such a customer does not have — so the
    # misclassification also demands information that cannot exist. The agent
    # correctly flagged it as a classifier bug each time instead of rewording the
    # customer's text, which is why it stayed visible.
    #
    # Guarded by a compute noun in the same text so a sentence about something else
    # not coming up (a VPN, a dashboard, a job) cannot hijack Path C.
    _COMPUTE_NOUN_RE = r'(cluster|compute|warehouse|worker\s+node|inst[\u00e2a]ncia)'
    _LAUNCH_STATE_PATTERNS = [
        ("CLUSTER_STUCK_PENDING", r'finding\s+instances'),
        ("CLUSTER_STUCK_PENDING", r'stuck\s+(?:at|in|on)?\s*(?:pending|starting|launching|acquiring)'),
        ("CLUSTER_STUCK_PENDING", r'travad[oa]\s+(?:em|no|na)?\s*(?:pending|inicializa)'),
        ("CLUSTER_NEVER_STARTED", r'never\s+(?:comes?|came|gets?|got)\s+up'),
        ("CLUSTER_NEVER_STARTED", r'(?:wo|do|does|did|would)n\u2019?\'?t\s+(?:start|come\s+up|launch|spin\s+up)'),
        ("CLUSTER_NEVER_STARTED", r'will\s+not\s+(?:start|come\s+up|launch)'),
        ("CLUSTER_NEVER_STARTED", r'fail(?:s|ed|ing)?\s+to\s+(?:start|launch|spin\s+up)'),
        ("CLUSTER_NEVER_STARTED", r'n[\u00e3a]o\s+sob(?:e|em)'),
        ("CLUSTER_NEVER_STARTED", r'n[\u00e3a]o\s+inicia'),
    ]
    if _re.search(_COMPUTE_NOUN_RE, text, _re.IGNORECASE):
        for label, pat in _LAUNCH_STATE_PATTERNS:
            if _re.search(pat, text, _re.IGNORECASE):
                launch_failure_signatures.append(label)

    # Dedupe preserving order.
    launch_failure_signatures = list(dict.fromkeys(launch_failure_signatures))
    is_launch_failure = bool(launch_failure_signatures)

    # Human-language NHC signatures. A real customer rarely pastes the raw
    # `X_NHC_*` code or the structured entity lines — they describe the symptom
    # in prose ("Network configuration failure", "Add nodes failed", "Instance
    # failed network health check"), often in Portuguese ("não sobe", "falha no
    # NHC"). These are exactly the Path C triggers the skill frontmatter lists,
    # but classification keyed only on the machine codes — so a prose NHC prompt
    # misclassified to Path A (seen on a clean-baseline run: the
    # driver returned path=A for "cluster ... não sobe — falha no NHC ...";
    # only the agent's self-escalation recovered Path C). Match them here,
    # case-insensitively, so is_nhc is True and _classify routes to C.
    _NHC_PHRASE_PATTERNS = [
        r'X_NHC_',
        r'network\s+configuration\s+failure',
        r'add\s+nodes\s+failed',
        r'instance\s+failed\s+network\s+health\s+check',
        r'failed\s+network\s+health\s+check',
        r'network\s+health\s+check',
        r'\bNHC\b',                      # "falha no NHC", "NHC failure"
        r'failed\s+component\(s\)\s*:\s*control_plane',
    ]
    has_nhc_phrase = any(_re.search(p, text, _re.IGNORECASE) for p in _NHC_PHRASE_PATTERNS)
    # If there's no canonical X_NHC_ code but we matched a launch-failure
    # signature, surface the most specific one as the error_code so the report
    # and the agent name the real symptom instead of "(unknown)".
    if not error_code and launch_failure_signatures:
        error_code = launch_failure_signatures[0]

    failed_components = []
    cm = _NHC_FAILED_COMPONENTS_RE.search(text)
    if not cm:
        cm = _NHC_FAILED_COMPONENTS_SIMPLE_RE.search(text)
    if cm:
        # The component list can be comma- OR space-separated ("internet storage").
        raw = cm.group("components").strip()
        failed_components = [c.strip() for c in _re.split(r'[,\s]+', raw)
                             if c.strip() and any(ch.isalpha() for ch in c)]

    retryable = None
    rm = _NHC_RETRYABLE_RE.search(text)
    if rm:
        retryable = rm.group(1) == "true"

    entities = []
    for em in _NHC_ENTITY_RE.finditer(text):
        try:
            code = int(em.group("code"))
        except ValueError:
            code = 0
        entities.append({
            "entity": em.group("entity"),
            "outcome": em.group("outcome"),
            "duration_sec": float(em.group("duration")),
            "message": em.group("message"),
            "last_error_code": code,
        })
    # Fallback: strict (quoted) form found nothing — the text was flattened or
    # reworded. Recover entity/outcome (and last_error_code if present) loosely so
    # the storage/SSL signal survives for the correlation engine.
    if not entities:
        for em in _NHC_ENTITY_SIMPLE_RE.finditer(text):
            try:
                code = int(em.group("code")) if em.group("code") else 0
            except (ValueError, IndexError):
                code = 0
            entities.append({
                "entity": em.group("entity"),
                "outcome": em.group("outcome"),
                "duration_sec": 0.0,
                "message": "",
                "last_error_code": code,
            })

    signals = {
        "workspace_url": "",
        "workspace_401": False,
        "workspace_403": False,
        "databricks_com_403": False,
        "any_dns_failure": False,
        "storage_ssl_error": False,
        "databricks_com_failure": False,
        "failed_hosts": [],
        "is_launch_failure": is_launch_failure,
        "launch_failure_signatures": launch_failure_signatures,
    }
    # X_NHC_STORAGE_SSL_ERROR is the canonical code for the bootstrap artifact
    # pull failing — keep it as a signal even if entity parsing came up short.
    if _re.search(r'X_NHC_STORAGE_SSL_ERROR', text, _re.IGNORECASE):
        signals["storage_ssl_error"] = True
    for e in entities:
        ent = e["entity"]
        code = e["last_error_code"]
        outcome = (e["outcome"] or "").lower()
        signals["failed_hosts"].append(ent)
        if "azuredatabricks.net" in ent:
            if not signals["workspace_url"]:
                signals["workspace_url"] = ent
            if code == 401:
                signals["workspace_401"] = True
            elif code == 403:
                signals["workspace_403"] = True
        if ent == "www.databricks.com":
            signals["databricks_com_failure"] = True
            if code == 403:
                signals["databricks_com_403"] = True
        # Storage/artifact bootstrap endpoints failing TLS = the X_NHC_STORAGE_SSL
        # signature, whether or not the canonical code string survived rewording.
        if "blob.core.windows.net" in ent and outcome in ("ssl_error", "tls_error"):
            signals["storage_ssl_error"] = True
        if outcome in ("dns_error", "dns_failure"):
            signals["any_dns_failure"] = True

    # `is_nhc` means "recognised as a classic cluster-start failure worth running
    # the ARM diagnostic for" — this now includes the non-NHC launch-failure
    # signatures, not just the canonical X_NHC_* codes/entities.
    is_nhc = (
        bool(_re.search(r'X_NHC_', text))
        or bool(failed_components)
        or bool(entities)
        or is_launch_failure
        or has_nhc_phrase
    )

    return {
        "is_nhc": is_nhc,
        "is_launch_failure": is_launch_failure,
        "launch_failure_signatures": launch_failure_signatures,
        "error_code": error_code,
        "failed_components": failed_components,
        "retryable": retryable,
        "entities": entities,
        "signals": signals,
    }


# ---------------------------------------------------------------------------
# ARM helpers
# ---------------------------------------------------------------------------
#
# LIVE ONLY. The caller passes an ARM bearer token and _arm_get reads Azure
# directly, from the runtime the problem lives on. This works when that runtime
# has outbound to login.microsoftonline.com and management.azure.com (classic
# compute, or serverless with the NCC / account network policy allow-listing
# those endpoints).
#
# There is deliberately NO offline/snapshot mode. A pre-fetched dump is a
# point-in-time copy taken from a different identity at a different moment; the
# product's whole thesis is to read the configuration as it is right now. When
# this runtime cannot reach ARM, the caller tells the customer exactly which
# egress to enable and to re-run — it never diagnoses from a file.

def _arm_get(arm_token, url, params=None, timeout=15):
    """GET an ARM URL LIVE against management.azure.com.

    There is no offline/snapshot mode: the whole point is to read the customer's
    Azure configuration as it is RIGHT NOW, from the runtime the problem lives on.
    If this runtime cannot reach ARM (serverless egress blocked / NCC default-deny),
    the caller does NOT fall back to a pre-fetched file — it tells the customer to
    enable egress to management.azure.com and re-run, so the diagnosis stays live.
    """
    import requests as _req
    headers = {"Authorization": f"Bearer {arm_token}"}
    try:
        r = _req.get(url, headers=headers, params=params or {}, timeout=timeout)
        if r.status_code != 200:
            return {"_error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return r.json()
    except Exception as e:
        return {"_error": f"request failed: {e}"}


def probe_arm_reachability(arm_token="", timeout=5):
    """Cheap gate: can this runtime reach management.azure.com AT ALL?

    This is the decision point that replaced the old LIVE-vs-OFFLINE fork. There
    is no offline path any more: either ARM is reachable and we read it live, or
    it is not and we tell the customer which egress to open, then re-run.

    Crucially this needs NO credential. A bare GET to the subscriptions endpoint
    with no (or a junk) token returns HTTP 401 — and ANY HTTP response proves the
    network path is open. So the caller can gate on reachability BEFORE asking the
    customer for a Service Principal, and never asks for a credential it cannot use.

    - With no token: a 401 means "reachable" and returns immediately (that is the
      expected, healthy answer for an unauthenticated probe — no retry).
    - With a real token: 200 is the clean green light; a 401 is retried once
      (AAD/role-assignment propagation) before being reported as a token/RBAC
      issue that is still "reachable" (do NOT tell the customer to change the
      network for that).
    A genuine egress block shows up as a connection error/timeout, handled below.

    Returns:
        dict with "ok" (bool), "reason" (str), and "reachable" (bool) when an HTTP
        response was seen.
    """
    import requests as _req

    def _hit():
        return _req.get(
            "https://management.azure.com/subscriptions",
            params={"api-version": "2022-12-01"},
            headers={"Authorization": f"Bearer {arm_token}"},
            timeout=timeout,
        )

    try:
        r = _hit()
        # Credential-free reachability probe: a 401 is exactly what an
        # unauthenticated GET should return, and it already proves the path is
        # open. Report reachable-but-unauthenticated without the RBAC retry.
        if not arm_token and r.status_code in (401, 403):
            return {"ok": False, "reachable": True,
                    "reason": f"ARM reachable (HTTP {r.status_code} to an unauthenticated probe)",
                    "status_code": r.status_code}
        # A 401 immediately after minting a fresh token is often AAD token /
        # role-assignment propagation, not a real network-deny — the same token
        # then works on a retry (seen in real deployments). The network path is clearly
        # open (we got an HTTP response), so retry ONCE after a short pause
        # before treating it as a failure. A genuine NCC default-deny shows up as
        # a connection error/timeout (handled below), not a 401.
        if r.status_code == 401:
            _time.sleep(2)
            r = _hit()
        # Any HTTP response (200/401/403) proves the network path to ARM is open.
        # 200 is the clean green light; 403/401-after-retry mean reachable-but-
        # token/RBAC issue — surface that distinctly so the caller doesn't
        # needlessly fall back to Cloud Shell for a credential problem.
        if r.status_code == 200:
            return {"ok": True, "reason": "ARM reachable"}
        if r.status_code in (401, 403):
            return {
                "ok": False,
                "reason": (
                    f"ARM reachable but returned HTTP {r.status_code} — token/RBAC issue, not a "
                    "network block. Re-mint the ARM token (get_arm_token) and verify the SP has "
                    "Reader on the relevant scope; do NOT fall back to Cloud Shell for this."
                ),
                "reachable": True,
                "status_code": r.status_code,
            }
        return {"ok": False, "reason": f"ARM returned HTTP {r.status_code}", "status_code": r.status_code}
    except Exception as e:
        return {"ok": False, "reason": f"ARM unreachable: {e.__class__.__name__}"}




def _parse_resource_id(resource_id):
    """Parse an ARM resource id into its components."""
    parts = (resource_id or "").strip().lstrip("/").split("/")
    out = {}
    if "subscriptions" in parts:
        i = parts.index("subscriptions")
        if i + 1 < len(parts):
            out["subscription_id"] = parts[i + 1]
    if "resourceGroups" in parts:
        i = parts.index("resourceGroups")
        if i + 1 < len(parts):
            out["resource_group"] = parts[i + 1]
    if "providers" in parts:
        i = parts.index("providers")
        if i + 2 < len(parts):
            out["provider"] = parts[i + 1]
            out["resource_type"] = parts[i + 2]
        if i + 3 < len(parts):
            out["resource_name"] = parts[i + 3]
    return out


# ---------------------------------------------------------------------------
# Workspace-level checks
# ---------------------------------------------------------------------------

def get_workspace_network_config(arm_token, workspace_resource_id):
    """Fetch the Databricks workspace ARM resource and return network config.

    Returns:
        dict with keys:
          - ok: bool
          - error: str (if not ok)
          - workspace_url: str
          - public_network_access: "Enabled" | "Disabled" | ""
          - required_nsg_rules: str (e.g. "AllRules" | "NoAzureDatabricksRules")
          - vnet_id: str (full ARM id of the customer VNet, if VNet-injected)
          - public_subnet: str (subnet name)
          - private_subnet: str (subnet name)
          - private_endpoint_connections: list[dict]
          - managed_resource_group_id: str
          - location: str
          - raw: full ARM JSON (for debugging / metadata)
    """
    out = {
        "ok": False, "error": "", "workspace_url": "",
        "public_network_access": "", "required_nsg_rules": "",
        "vnet_id": "", "public_subnet": "", "private_subnet": "",
        "private_endpoint_connections": [],
        "managed_resource_group_id": "", "location": "",
        "raw": {},
    }
    rid = (workspace_resource_id or "").strip()
    if not rid.startswith("/subscriptions/"):
        out["error"] = "workspace_resource_id must be a full ARM id starting with /subscriptions/"
        return out
    url = f"https://management.azure.com{rid}?api-version=2023-02-01"
    data = _arm_get(arm_token, url)
    if "_error" in data:
        out["error"] = data["_error"]
        return out
    props = data.get("properties", {}) or {}
    params = props.get("parameters", {}) or {}
    out["raw"] = data
    out["location"] = data.get("location", "")
    out["workspace_url"] = props.get("workspaceUrl", "")
    out["public_network_access"] = props.get("publicNetworkAccess", "")
    out["required_nsg_rules"] = props.get("requiredNsgRules", "")
    out["managed_resource_group_id"] = props.get("managedResourceGroupId", "")
    out["vnet_id"] = (params.get("customVirtualNetworkId", {}) or {}).get("value", "")
    out["public_subnet"] = (params.get("customPublicSubnetName", {}) or {}).get("value", "")
    out["private_subnet"] = (params.get("customPrivateSubnetName", {}) or {}).get("value", "")
    out["private_endpoint_connections"] = props.get("privateEndpointConnections", []) or []
    out["ok"] = True
    return out


def check_subnet_delegation(arm_token, vnet_id, subnet_name):
    """Verify a subnet is delegated to Microsoft.Databricks/workspaces."""
    start = _time.time()
    target = f"{vnet_id.split('/')[-1]}/{subnet_name}" if vnet_id else subnet_name
    if not vnet_id or not subnet_name:
        return CheckResult("Subnet Delegation", target, Status.SKIP,
            "VNet id or subnet name missing — cannot check delegation.",
            duration_ms=(_time.time() - start) * 1000)
    url = f"https://management.azure.com{vnet_id}/subnets/{subnet_name}?api-version=2023-02-01"
    data = _arm_get(arm_token, url)
    if "_error" in data:
        return CheckResult("Subnet Delegation", target, Status.ERROR,
            f"Could not read subnet: {data['_error']}",
            duration_ms=(_time.time() - start) * 1000)
    delegations = (data.get("properties", {}) or {}).get("delegations", []) or []
    db_delegations = [
        d for d in delegations
        if (d.get("properties", {}) or {}).get("serviceName", "") == "Microsoft.Databricks/workspaces"
    ]
    if not db_delegations:
        return CheckResult("Subnet Delegation", target, Status.FAIL,
            f"Subnet '{subnet_name}' is NOT delegated to Microsoft.Databricks/workspaces",
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Both the public (host) and private (container) subnets must be delegated to "
                "Microsoft.Databricks/workspaces. Without this delegation, the data plane cannot "
                "place NICs in the subnet and NHC fails before bootstrap.\n"
                f"Fix: Azure Portal > VNet > Subnets > {subnet_name} > Delegate subnet to a service "
                "> Microsoft.Databricks/workspaces."
            ),
            metadata={"vnet_id": vnet_id, "subnet": subnet_name})
    return CheckResult("Subnet Delegation", target, Status.PASS,
        f"Subnet '{subnet_name}' is delegated to Microsoft.Databricks/workspaces",
        duration_ms=(_time.time() - start) * 1000,
        metadata={"vnet_id": vnet_id, "subnet": subnet_name})


# Required outbound rules per
# https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/vnet-inject
# Each entry: (service tag, list of required ports). A rule passes if there is
# any Allow rule from VirtualNetwork (or *) to that destination service tag,
# covering at least one of the listed ports.
_REQUIRED_OUTBOUND_RULES = [
    ("AzureDatabricks", ["443", "3306", "8443", "8444", "8445", "8446", "8447", "8448", "8449", "8450", "8451"]),
    ("Storage", ["443"]),
    ("EventHub", ["9093"]),
    ("Sql", ["3306"]),
]


def _ports_match_any(rule_ports, required_ports):
    """Return True if rule_ports (a list of port strings/ranges) covers any of the required ports."""
    for rp in rule_ports:
        if not rp:
            continue
        if rp == "*":
            return True
        for req in required_ports:
            if rp == req:
                return True
            if "-" in rp and _port_in_range(req, rp):
                return True
            if "," in rp:
                if any(part.strip() == req for part in rp.split(",")):
                    return True
    return False


def check_subnet_required_nsg_rules(arm_token, vnet_id, subnet_name, required_nsg_rules_setting="",
                                    backend_pl_check=None):
    """Validate the NSG attached to a subnet has the full Databricks-required rule set.

    `backend_pl_check`: the CheckResult from check_backend_private_link (reused, never
    re-derived here). When the workspace is set to requiredNsgRules=NoAzureDatabricksRules
    AND that check confirmed an Approved back-end databricks_ui_api private endpoint in the
    data-plane VNet, the ABSENCE of the public AzureDatabricks service-tag rules is the
    documented-correct posture — not a failure — and the "flip to AllRules" advice must not
    be emitted. Passing None keeps the strict VNet-inject expectation.

    an earlier defect exists because this awareness previously lived ONLY in the downstream correlation
    rule (nhc_subnet_nsg_backend_pl_expected). The check row went hard red with AllRules
    advice while the diagnosis underneath said "do NOT flip to AllRules" — and a customer
    scans red rows before prose, so the report pushed them toward the forbidden action.
    A guard on one layer only is the same defect shape: fix it where the status is
    produced, so the status surface and the conclusion cannot diverge.

    Per the VNet-inject doc, an NSG attached to a Databricks data-plane subnet
    must have outbound Allow rules from VirtualNetwork to:
      - AzureDatabricks service tag on TCP 443, 3306, 8443-8451
      - Storage service tag on TCP 443
      - EventHub service tag on TCP 9093
      - Sql service tag on TCP 3306
    plus the default Allow inbound/outbound for VirtualNetwork->VirtualNetwork.

    We pattern-match by service tag so renamed rules still pass.
    """
    start = _time.time()
    target = f"{vnet_id.split('/')[-1]}/{subnet_name}" if vnet_id else subnet_name
    if not vnet_id or not subnet_name:
        return CheckResult("Subnet NSG (Databricks rules)", target, Status.SKIP,
            "VNet id or subnet name missing.",
            duration_ms=(_time.time() - start) * 1000)

    # Back-end Private Link posture, taken from the existing detector's verdict.
    _bpl_md = (getattr(backend_pl_check, "metadata", None) or {})
    _backend_pe_names = _bpl_md.get("backend_pe_names") or []
    backend_pl_expected = (required_nsg_rules_setting == "NoAzureDatabricksRules"
                           and bool(_bpl_md.get("has_backend_pe")))
    _pe_label = ", ".join(_backend_pe_names) if _backend_pe_names else "databricks_ui_api"
    _EXPECTED_ABSENT_TAG = "AzureDatabricks"
    _allrules_sentence = (
        "" if backend_pl_expected else
        "Alternatively, set the workspace requiredNsgRules to AllRules so Azure Databricks "
        "deploys these rules for you."
    )

    subnet_url = f"https://management.azure.com{vnet_id}/subnets/{subnet_name}?api-version=2023-02-01"
    subnet_data = _arm_get(arm_token, subnet_url)
    if "_error" in subnet_data:
        return CheckResult("Subnet NSG (Databricks rules)", target, Status.ERROR,
            f"Could not read subnet: {subnet_data['_error']}",
            duration_ms=(_time.time() - start) * 1000)
    nsg_ref = (subnet_data.get("properties", {}) or {}).get("networkSecurityGroup", {}) or {}
    nsg_id = nsg_ref.get("id", "")
    if not nsg_id:
        return CheckResult("Subnet NSG (Databricks rules)", target, Status.FAIL,
            f"Subnet '{subnet_name}' has NO NSG attached. Databricks data-plane subnets require an NSG "
            "with the AzureDatabricks/Storage/EventHub/Sql service-tag rules.",
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Attach an NSG carrying the Storage / EventHub / Sql service-tag outbound Allow rules "
                "(and the AzureDatabricks rules unless back-end Private Link carries the control plane). "
                + ("Do NOT flip requiredNsgRules to AllRules: this workspace uses back-end Private Link "
                   f"({_pe_label}), for which NoAzureDatabricksRules is the documented-correct setting."
                   if backend_pl_expected else
                   "If you don't manage them yourself, set the workspace requiredNsgRules to AllRules so "
                   "the service deploys them for you.")
            ),
            metadata={"subnet": subnet_name, "nsg_id": "",
                      "backend_pl_expected": backend_pl_expected,
                      "required_nsg_rules_setting": required_nsg_rules_setting})
    nsg_url = f"https://management.azure.com{nsg_id}?api-version=2023-02-01"
    nsg_data = _arm_get(arm_token, nsg_url)
    if "_error" in nsg_data:
        return CheckResult("Subnet NSG (Databricks rules)", target, Status.ERROR,
            f"Could not read NSG: {nsg_data['_error']}",
            duration_ms=(_time.time() - start) * 1000)

    nsg_props = nsg_data.get("properties", {}) or {}
    rules = (nsg_props.get("securityRules") or []) + (nsg_props.get("defaultSecurityRules") or [])

    # Track which required outbound service tags are covered.
    covered = {tag: False for tag, _ports in _REQUIRED_OUTBOUND_RULES}
    blocking_outbound = []  # high-priority Deny rules that catch any required service tag
    has_inbound_databricks = False  # required only if SCC is DISABLED (legacy)
    # Field finding: NHC bootstrap requires the canonically-named
    # rule "Microsoft.Databricks-workspaces_UseOnly_databricks-worker-to-databricks-webapp"
    # (or similar). A custom-named rule with identical service tag + ports does NOT
    # satisfy NHC even though it's network-equivalent. Track whether the canonical
    # name is present so we can flag this exact failure mode.
    canonical_databricks_rule_present = False

    for r in rules:
        rp = r.get("properties", {}) or {}
        direction = rp.get("direction", "")
        access = rp.get("access", "")
        dest = rp.get("destinationAddressPrefix", "") or ""
        dest_list = rp.get("destinationAddressPrefixes", []) or []
        src = rp.get("sourceAddressPrefix", "") or ""
        port_single = rp.get("destinationPortRange", "") or ""
        port_list = rp.get("destinationPortRanges", []) or []
        all_dest = [d for d in [dest] + dest_list if d]
        all_ports = [p for p in [port_single] + port_list if p]

        priority = rp.get("priority", 0) or 0
        is_default_rule = priority >= 65000  # Azure default rules; cannot be deleted.
        if direction == "Outbound" and access == "Allow":
            # Only EXPLICIT service-tag matches count as coverage. The default
            # AllowInternetOutBound rule (priority 65001) covers AzureDatabricks
            # IPs at the IP level, but the VNet-inject doc explicitly requires
            # the service-tag rule, so we don't credit Internet/* allows.
            for tag, required_ports in _REQUIRED_OUTBOUND_RULES:
                if tag in all_dest and _ports_match_any(all_ports, required_ports):
                    covered[tag] = True
            # Canonical name detection for the AzureDatabricks rule.
            rule_name = (r.get("name") or "").lower()
            if "AzureDatabricks" in all_dest and (
                "microsoft.databricks-workspaces_useonly" in rule_name
                or "databricks-worker-to-databricks" in rule_name
            ):
                canonical_databricks_rule_present = True
        if direction == "Outbound" and access == "Deny" and not is_default_rule:
            # Only flag CUSTOM Deny rules (not the default DenyAllOutBound at 65500).
            for tag, required_ports in _REQUIRED_OUTBOUND_RULES:
                if (tag in all_dest or any(d in ("*", "Internet") for d in all_dest)) \
                        and _ports_match_any(all_ports, required_ports):
                    blocking_outbound.append(
                        f"{r.get('name', '?')} priority={priority} blocks {tag}")
                    break
        if direction == "Inbound" and access == "Allow" and src == "AzureDatabricks":
            has_inbound_databricks = True

    all_missing = [tag for tag, ok in covered.items() if not ok]
    # Under back-end Private Link with NoAzureDatabricksRules, the AzureDatabricks
    # service-tag rules are EXPECTED to be absent: the data plane reaches the control
    # plane over the databricks_ui_api private endpoint at a VirtualNetwork address, so
    # Databricks deliberately does not deploy them. Storage / EventHub / Sql still
    # traverse the normal path and remain genuinely required, so only the one tag is
    # reclassified — the check does not go blind.
    expected_absent = ([_EXPECTED_ABSENT_TAG] if (backend_pl_expected
                                                  and _EXPECTED_ABSENT_TAG in all_missing) else [])
    missing = [t for t in all_missing if t not in expected_absent]
    issues = []
    if missing:
        for tag in missing:
            ports = next(p for t, p in _REQUIRED_OUTBOUND_RULES if t == tag)
            ports_str = ports[0] if len(ports) == 1 else f"{ports[0]} (+{len(ports)-1} more)"
            issues.append(f"missing outbound Allow to service tag '{tag}' (e.g. TCP {ports_str})")
    if blocking_outbound:
        issues.append(f"{len(blocking_outbound)} explicit Deny rule(s): {'; '.join(blocking_outbound)}")
    # Canonical-name check: if AzureDatabricks tag is "covered" but only by a
    # non-canonical (custom-named) rule, NHC won't accept it. This produces a
    # FAIL even though the service tag/ports look correct. The fix is the
    # AllRules flip — Databricks redeploys the canonically-named rule.
    # Suppressed under back-end Private Link: NHC does not need that rule at all there,
    # so demanding the canonical NAME would prescribe the AllRules flip the topology
    # forbids.
    canonical_name_gap = (covered.get("AzureDatabricks") and not canonical_databricks_rule_present
                          and not backend_pl_expected)
    if canonical_name_gap:
        issues.append(
            "AzureDatabricks rule present but NOT named 'Microsoft.Databricks-workspaces_UseOnly_*' "
            "— NHC keys on the canonical name and rejects custom-named rules "
            "even when service tag and ports match"
        )

    raw = (
        f"NSG: {nsg_id.split('/')[-1]} ; required_nsg_rules_setting={required_nsg_rules_setting or '(unset)'} ; "
        f"backend_pl_expected={'yes' if backend_pl_expected else 'no'}"
        + (f" (PE: {_pe_label})" if backend_pl_expected else "") + " ; "
        f"covered={covered} ; canonical_databricks_rule={'yes' if canonical_databricks_rule_present else 'no'} ; "
        f"in_databricks_present={has_inbound_databricks} (legacy SCC-disabled requirement) ; "
        f"deny={blocking_outbound or 'none'}"
    )

    md = {"nsg_id": nsg_id, "subnet": subnet_name, "missing_tags": missing,
          "expected_absent_tags": expected_absent, "backend_pl_expected": backend_pl_expected,
          "backend_pe_names": _backend_pe_names,
          "covered": covered, "deny_rules": blocking_outbound,
          "canonical_databricks_rule_present": canonical_databricks_rule_present,
          "required_nsg_rules_setting": required_nsg_rules_setting}

    # The one sentence that must never appear alongside a back-end-Private-Link topology.
    _expected_note = (
        f"Note: '{_EXPECTED_ABSENT_TAG}' service-tag rules are absent, which is EXPECTED here — "
        f"requiredNsgRules='NoAzureDatabricksRules' and an Approved back-end Private Link endpoint "
        f"({_pe_label}) carries the control plane. Do NOT flip requiredNsgRules to AllRules."
        if expected_absent else "")

    if issues:
        _rule_lines = [
            f"  - Outbound Allow VirtualNetwork -> {tag:<16}: TCP "
            + ", ".join(next(p for t, p in _REQUIRED_OUTBOUND_RULES if t == tag))
            for tag in missing
        ]
        return CheckResult("Subnet NSG (Databricks rules)", target, Status.FAIL,
            f"NSG attached to '{subnet_name}' is missing required Databricks rules: " + "; ".join(issues)
            + (" " + _expected_note if _expected_note else ""),
            raw_output=raw,
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Add the missing Databricks-required NSG rule(s) (per "
                "https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/vnet-inject) "
                "to BOTH the host (public) and container (private) subnets:\n"
                + ("\n".join(_rule_lines) + "\n" if _rule_lines else "")
                + "  - Outbound Allow VirtualNetwork -> VirtualNetwork  : Any (default, intra-VNet)\n"
                + (_expected_note if _expected_note else _allrules_sentence)
            ),
            metadata=md)

    if expected_absent:
        # GREEN, and the row itself says why — so the status surface agrees with the
        # diagnosis instead of contradicting it.
        return CheckResult("Subnet NSG (Databricks rules)", target, Status.PASS,
            f"NSG attached to '{subnet_name}' carries the required Storage / EventHub / Sql "
            f"service-tag rules. The public '{_EXPECTED_ABSENT_TAG}' service-tag rules are absent, "
            f"which is the DOCUMENTED-CORRECT posture for this workspace: "
            f"requiredNsgRules='NoAzureDatabricksRules' with an Approved back-end (compute-plane) "
            f"Private Link endpoint ({_pe_label}) carrying control-plane traffic over the private "
            f"endpoint. This is NOT a misconfiguration and NOT a cause of a launch failure — do NOT "
            f"flip requiredNsgRules to AllRules.",
            raw_output=raw,
            duration_ms=(_time.time() - start) * 1000,
            metadata=md)

    return CheckResult("Subnet NSG (Databricks rules)", target, Status.PASS,
        f"NSG attached to '{subnet_name}' has canonical Databricks-managed rules for required service tags",
        raw_output=raw,
        duration_ms=(_time.time() - start) * 1000,
        metadata=md)


def _port_in_range(port_str, range_str):
    try:
        port = int(port_str)
        a, b = range_str.split("-")
        return int(a) <= port <= int(b)
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# UDR blackhole analysis — EVERY route in the table, not just 0.0.0.0/0
# ---------------------------------------------------------------------------
#
# Field experience: check_subnet_route_table used to scan the route list for
# the 0.0.0.0/0 entry, `break`, and evaluate ONLY that one route. A UDR added on the
# `Storage` SERVICE TAG with next hop `None` — a blackhole sitting on the exact
# destination the bootstrap NHC timed out on — was read from ARM and thrown away:
# the report contained no blackhole and no `None` next hop anywhere, the routing row
# said only "0.0.0.0/0 -> VirtualAppliance", and the run ended on
# `launch_failure_arm_clean` ("no customer-side network misconfiguration"), which
# steered the customer at DNS / Private Link.
#
# Azure applies longest-prefix match over the WHOLE table, so ANY route can be the
# one that drops a required destination — and a more specific route WINS over
# 0.0.0.0/0, which is why a perfectly correct hub-firewall allow-list could not save
# this workspace: the packets never reached the firewall.
#
# Severity is decided by WHAT THE PREFIX COVERS, never by the mere existence of a
# blackhole: null-routing RFC1918 to stop on-prem leakage is a normal, deliberate
# pattern and must not turn a healthy workspace CRITICAL.

_DEFAULT_PREFIXES = ("0.0.0.0/0", "::/0")

# Service tags that stand for "everything" when used as a UDR address prefix.
_CATCH_ALL_TAGS = ("internet", "azurecloud")


def _canonical_tag(tag):
    """Azure's own spelling of a service tag, so a tag read out of a UDR can be
    looked up in ARM. Regional suffixes (`Storage.Southcentralus`) are stripped by
    the caller."""
    canon = {str(t).lower(): t for t, _ports in _REQUIRED_OUTBOUND_RULES}
    canon.update({
        "azureactivedirectory": "AzureActiveDirectory",
        "azureresourcemanager": "AzureResourceManager",
        "virtualnetwork": "VirtualNetwork",
        "azurecloud": "AzureCloud",
        "internet": "Internet",
    })
    return canon.get(str(tag or "").lower(), str(tag or ""))


def _bootstrap_tag_labels():
    """{lowercased service tag -> human label} for every destination a classic
    cluster's bootstrap must reach.

    REUSES the two lists that already encode this instead of hardcoding a third:
    `_REQUIRED_EGRESS[*]["service_tags"]` (the firewall-egress categories) and
    `_REQUIRED_OUTBOUND_RULES` (the documented NSG service-tag rules). Only the
    destinations neither list models — AAD token issuance, ARM, and the VNet's own
    intra-subnet traffic — are added here.
    """
    labels = {}
    for spec in _REQUIRED_EGRESS.values():
        for t in spec.get("service_tags", ()):
            labels[str(t).lower()] = spec["label"]
    for tag, ports in _REQUIRED_OUTBOUND_RULES:
        labels.setdefault(str(tag).lower(),
                          "%s service tag on TCP %s" % (tag, ", ".join(ports[:4])))
    labels.setdefault("azureactivedirectory",
                      "Azure AD / Entra ID token endpoints (AzureActiveDirectory tag :443)")
    labels.setdefault("azureresourcemanager",
                      "Azure Resource Manager (AzureResourceManager tag :443)")
    labels.setdefault("virtualnetwork",
                      "intra-VNet traffic (VirtualNetwork tag) — driver/executor and "
                      "in-VNet private endpoints")
    return labels


def _route_prefix_net(prefix):
    """Parse a route addressPrefix as an IP network, or None when it is a SERVICE
    TAG. Azure accepts `Storage`, `Storage.Southcentralus`, `AzureCloud`, `Internet`,
    `VirtualNetwork`, ... as UDR prefixes, and `ip_network` raises on all of them —
    which is how they came to be silently skipped."""
    try:
        return _ipaddress.ip_network(str(prefix or ""), strict=False)
    except ValueError:
        return None


def _nets_overlap(net, other):
    try:
        o = _ipaddress.ip_network(str(other), strict=False)
    except ValueError:
        return False
    if o.version != net.version:
        return False
    return net.overlaps(o)


def _is_public_net(net):
    """True when the prefix contains globally-routable address space (where every
    Databricks bootstrap endpoint lives)."""
    if net.prefixlen == 0:
        return True
    try:
        if (net.is_private or net.is_link_local or net.is_loopback
                or net.is_multicast or net.is_reserved):
            return False
    except Exception:
        pass
    return True


_SERVICE_TAG_PREFIX_CACHE = {}


def service_tag_prefixes(arm_token, subscription_id, location, tag):
    """Published address prefixes behind an Azure service tag, or None when the tag
    could not be expanded.

    Best-effort ARM read (`serviceTagDetails`), memoised per (subscription, location,
    tag) so a route table full of tag routes costs one call per distinct tag. None
    means "unknown coverage" — callers must SAY so rather than concluding the tag is
    irrelevant (that confident-negative-from-partial-input is the bug class this
    whole change is about).
    """
    canon = _canonical_tag(tag).split(".")[0]
    if not subscription_id or not location or not canon:
        return None
    key = (str(subscription_id), str(location).lower(), canon.lower())
    if key in _SERVICE_TAG_PREFIX_CACHE:
        return _SERVICE_TAG_PREFIX_CACHE[key]
    url = ("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/"
           "locations/%s/serviceTagDetails?api-version=2023-09-01&tagName=%s"
           % (subscription_id, location, canon))
    data = _arm_get(arm_token, url)
    prefixes = []
    if isinstance(data, dict) and "_error" not in data:
        for entry in (data.get("value") or []):
            nm = str(entry.get("name") or "").lower()
            if nm == canon.lower() or nm.startswith(canon.lower() + "."):
                prefixes.extend((entry.get("properties") or {}).get("addressPrefixes") or [])
    _SERVICE_TAG_PREFIX_CACHE[key] = prefixes or None
    return prefixes or None


def service_tag_prefix_containing(arm_token, subscription_id, location, tag, ip):
    """Most specific published prefix of `tag` that contains `ip`.

    Returns "" when the tag expanded but does not contain the address, and None when
    the tag could not be expanded (coverage UNKNOWN — never treat that as "no match").
    """
    prefixes = service_tag_prefixes(arm_token, subscription_id, location, tag)
    if prefixes is None:
        return None
    try:
        addr = _ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    best, best_len = "", -1
    for p in prefixes:
        try:
            net = _ipaddress.ip_network(str(p), strict=False)
        except ValueError:
            continue
        if net.version != addr.version:
            continue
        if addr in net and net.prefixlen > best_len:
            best, best_len = str(net), net.prefixlen
    return best


def _route_fields(route):
    """Normalise the three route shapes in this codebase into one dict.

    ARM (`{"name", "properties": {"addressPrefix", "nextHopType", ...}}`), the
    flattened shape used by check_subnet_route_table, and the topology-graph shape
    (`address_prefix`). One detector, every caller — a second implementation is how
    the last routing guard silently regressed.
    """
    rp = (route.get("properties") or {}) if isinstance(route, dict) else {}
    return {
        "name": route.get("name"),
        "prefix": (rp.get("addressPrefix") or route.get("prefix")
                   or route.get("address_prefix") or ""),
        "next_hop_type": rp.get("nextHopType") or route.get("next_hop_type") or "",
        "next_hop_ip": rp.get("nextHopIpAddress") or route.get("next_hop_ip") or "",
    }


def classify_blackhole_route(route, arm_token="", subscription_id="", location="",
                             local_prefixes=()):
    """Decide what a next-hop-'None' route actually breaks.

    `local_prefixes`: the subnet's own address prefix(es) — blackholing them drops
    driver/executor traffic and in-VNet private endpoints.

    Returns the normalised route fields plus:
      is_default_route  it is the 0.0.0.0/0 (or ::/0) entry
      verdict           "required"   — provably covers a destination the bootstrap needs
                        "unverified" — covers PUBLIC space we could not expand to
                                       service-tag prefixes; coverage is UNKNOWN
                        "unrelated"  — private/non-routable space, or provably
                                       overlaps no required service tag
      covers            human labels of what it drops
      why               one sentence of provenance for the verdict
    """
    out = _route_fields(route)
    prefix = str(out.get("prefix") or "")
    labels = _bootstrap_tag_labels()
    out["is_default_route"] = prefix in _DEFAULT_PREFIXES

    if out["is_default_route"]:
        out["verdict"] = "required"
        out["covers"] = sorted(set(labels.values()))
        out["why"] = ("%s covers every destination outside the VNet, so nothing the "
                      "bootstrap needs is reachable." % prefix)
        return out

    net = _route_prefix_net(prefix)
    if net is None:
        tag = prefix.split(".")[0].lower()
        if tag in _CATCH_ALL_TAGS:
            out["verdict"] = "required"
            out["covers"] = sorted(set(labels.values()))
            out["why"] = ("the service tag '%s' covers every %s destination, including all "
                          "of the Databricks bootstrap endpoints."
                          % (prefix, "Azure" if tag == "azurecloud" else "off-VNet"))
            return out
        if tag in labels:
            out["verdict"] = "required"
            out["covers"] = [labels[tag]]
            out["why"] = ("the route's address prefix IS the '%s' service tag, which is exactly "
                          "a destination set the Databricks bootstrap must reach." % prefix)
            return out
        out["verdict"] = "unrelated"
        out["covers"] = []
        out["why"] = ("the service tag '%s' is not one of the destination sets the Databricks "
                      "bootstrap is documented to require." % prefix)
        return out

    overlaps_local = [str(p) for p in (local_prefixes or []) if _nets_overlap(net, p)]
    if overlaps_local:
        out["verdict"] = "required"
        out["covers"] = [labels.get("virtualnetwork", "intra-VNet traffic")]
        out["why"] = ("%s overlaps the data-plane subnet's own address space (%s), so "
                      "driver/executor traffic and in-VNet private endpoints are dropped."
                      % (prefix, ", ".join(overlaps_local)))
        return out

    if not _is_public_net(net):
        out["verdict"] = "unrelated"
        out["covers"] = []
        out["why"] = ("%s is private / non-routable address space and holds none of the "
                      "(public) Databricks bootstrap endpoints; null-routing such a range is "
                      "a common deliberate pattern." % prefix)
        return out

    # PUBLIC CIDR: prove or disprove coverage by expanding the required service tags
    # to their published prefixes. A CIDR blackhole that overlaps the Storage or
    # AzureDatabricks ranges is the same defect as a tag blackhole.
    hits, expanded = [], False
    for tag in sorted(set(labels) - set(_CATCH_ALL_TAGS) - {"virtualnetwork"}):
        tag_prefixes = service_tag_prefixes(arm_token, subscription_id, location, tag)
        if tag_prefixes is None:
            continue
        expanded = True
        matched = [p for p in tag_prefixes if _nets_overlap(net, p)]
        if matched:
            hits.append((tag, labels[tag], matched))
    if hits:
        out["verdict"] = "required"
        out["covers"] = [lbl for _t, lbl, _m in hits]
        out["why"] = ("%s overlaps the published address prefixes of the %s service tag(s)."
                      % (prefix, ", ".join("%s (%d prefix(es), e.g. %s)"
                                           % (_canonical_tag(t), len(m), m[0])
                                           for t, _l, m in hits)))
        return out
    if expanded:
        out["verdict"] = "unrelated"
        out["covers"] = []
        out["why"] = ("%s was compared against the published address prefixes of every "
                      "Databricks-required service tag and overlaps none of them." % prefix)
        return out
    out["verdict"] = "unverified"
    out["covers"] = []
    out["why"] = ("%s is PUBLIC address space and the Azure service-tag prefix lists could not "
                  "be read (no ARM access to serviceTagDetails), so whether it covers a "
                  "Databricks bootstrap endpoint is UNKNOWN — that is not evidence that it "
                  "does not." % prefix)
    return out


def blackhole_routes_covering(routes, category=""):
    """Next-hop-'None' routes in `routes` whose SERVICE-TAG prefix covers `category`
    (a `_REQUIRED_EGRESS` key), plus any 0.0.0.0/0 and Internet/AzureCloud blackhole.

    The service-tag-only, ARM-free half of classify_blackhole_route, for callers that
    hold a route list and one destination category (topology.trace). CIDR coverage
    needs the ARM tag expansion and lives in classify_blackhole_route.
    """
    want = set()
    spec = _REQUIRED_EGRESS.get(category) or {}
    for t in spec.get("service_tags", ()):
        want.add(str(t).lower())
    hits = []
    for r in (routes or []):
        f = _route_fields(r)
        if str(f.get("next_hop_type")) != "None":
            continue
        prefix = str(f.get("prefix") or "")
        tag = prefix.split(".")[0].lower()
        if prefix in _DEFAULT_PREFIXES:
            f["covers_category"] = "0.0.0.0/0 (every off-VNet destination)"
        elif tag in _CATCH_ALL_TAGS:
            f["covers_category"] = "the '%s' service tag (every off-VNet destination)" % prefix
        elif want and tag in want:
            f["covers_category"] = "the '%s' service tag" % prefix
        else:
            continue
        hits.append(f)
    return hits


def check_subnet_route_table(arm_token, vnet_id, subnet_name):
    """Check the UDR attached to a subnet for forced-tunneling / blackhole patterns."""
    start = _time.time()
    target = f"{vnet_id.split('/')[-1]}/{subnet_name}" if vnet_id else subnet_name
    if not vnet_id or not subnet_name:
        return CheckResult("Subnet Route Table", target, Status.SKIP,
            "VNet id or subnet name missing.",
            duration_ms=(_time.time() - start) * 1000)
    subnet_url = f"https://management.azure.com{vnet_id}/subnets/{subnet_name}?api-version=2023-02-01"
    sd = _arm_get(arm_token, subnet_url)
    if "_error" in sd:
        return CheckResult("Subnet Route Table", target, Status.ERROR,
            f"Could not read subnet: {sd['_error']}",
            duration_ms=(_time.time() - start) * 1000)
    # Field experience: the public and private data-plane subnets produced
    # BYTE-IDENTICAL `message` and `recommendation`, neither naming its own subnet — only
    # the separate `target` field distinguished them. In the chat they read as one
    # instruction printed twice; in the report JSON that a support ticket carries, the two
    # rows are indistinguishable without cross-referencing `target`. check_subnet_egress_ip
    # already names its subnet ("No NAT gateway attached to 'snet-...'"), so this is the
    # existing convention, applied here. Prefixed rather than reworded so that every
    # existing substring of these messages stays intact.
    _sn = f"Subnet '{subnet_name}': "
    rt_ref = (sd.get("properties", {}) or {}).get("routeTable", {}) or {}
    rt_id = rt_ref.get("id", "")
    if not rt_id:
        # INCONCLUSIVE, not a pass. "No route table associated" is not the same fact as
        # "traffic is not forced-tunnelled": the EFFECTIVE routes of a subnet also include
        # BGP routes learned from an ExpressRoute/VPN gateway or an Azure Route Server, and
        # a hub advertising 0.0.0.0/0 over BGP forced-tunnels this subnet with no UDR
        # anywhere in ARM. Returning PASS here turned an absence of evidence into
        # reassurance — the customer was told default Azure routing
        # applied while the real routing was invisible to us.
        return CheckResult("Subnet Route Table", target, Status.WARN,
            f"No UDR (route table) is associated with '{subnet_name}', so ARM shows no user-defined "
            "route for this subnet. That is INCONCLUSIVE, not a clean bill of health: effective "
            "routes can still be overridden by BGP advertisements from an ExpressRoute/VPN gateway "
            "or an Azure Route Server, which route tables do not reveal.",
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Read the EFFECTIVE routes rather than the UDR to settle this: Azure Portal > "
                "Network Watcher > Effective routes > pick a NIC in this subnet (or "
                "`az network nic show-effective-route-table -g <managed-rg> -n <nic>`). Look for a "
                "0.0.0.0/0 entry whose source is 'VirtualNetworkGateway' — that is a forced tunnel "
                "with no route table attached."
            ),
            metadata={"route_table_id": "", "route_table_name": "",
                      "subnet_name": subnet_name, "default_route": None,
                      "udr_attached": False, "inconclusive": True})
    rt_data = _arm_get(arm_token, f"https://management.azure.com{rt_id}?api-version=2023-02-01")
    if "_error" in rt_data:
        return CheckResult("Subnet Route Table", target, Status.ERROR,
            _sn + f"Could not read route table: {rt_data['_error']}",
            duration_ms=(_time.time() - start) * 1000)
    routes = (rt_data.get("properties", {}) or {}).get("routes", []) or []
    rt_name = rt_id.split("/")[-1]
    rt_location = rt_data.get("location", "") or ""
    _sub_id = _parse_resource_id(vnet_id).get("subscription_id", "")
    _sn_props = sd.get("properties", {}) or {}
    _local_prefixes = [p for p in ([_sn_props.get("addressPrefix")]
                                   + list(_sn_props.get("addressPrefixes") or [])) if p]

    # EVERY route, not just 0.0.0.0/0. Azure longest-prefix-matches the whole
    # table, so a more specific route wins over the default one; evaluating only the
    # default route made a blackhole on a required destination invisible.
    all_routes = [_route_fields(r) for r in routes]
    default_route = None
    for e in all_routes:
        if e["prefix"] in _DEFAULT_PREFIXES and default_route is None:
            default_route = {"name": e["name"], "next_hop_type": e["next_hop_type"],
                             "next_hop_ip": e["next_hop_ip"]}

    blackholes = [classify_blackhole_route(e, arm_token=arm_token, subscription_id=_sub_id,
                                           location=rt_location,
                                           local_prefixes=_local_prefixes)
                  for e in all_routes if str(e["next_hop_type"]) == "None"]
    breaking = [b for b in blackholes if b["verdict"] == "required"]
    unproven = [b for b in blackholes if b["verdict"] == "unverified"]
    benign = [b for b in blackholes if b["verdict"] == "unrelated"]

    _inv_items = []
    for e in all_routes:
        hop_txt = e["next_hop_type"] + ((" " + e["next_hop_ip"]) if e["next_hop_ip"] else "")
        _inv_items.append("'%s' %s -> %s" % (e["name"], e["prefix"], hop_txt))
    _inventory = ("Evaluated all %d route(s) in UDR '%s': %s."
                  % (len(all_routes), rt_name, "; ".join(_inv_items) or "(table is empty)"))

    md = {"route_table_id": rt_id, "route_table_name": rt_name,
          "default_route": default_route, "udr_attached": True,
          "subnet_name": subnet_name, "routes_evaluated": len(all_routes),
          "all_routes": all_routes, "blackholes": blackholes,
          "blackholes_required": [b["prefix"] for b in (breaking + unproven)]}

    _benign_note = ""
    if benign:
        _b_items = ["blackhole route '%s' %s — %s" % (b["name"], b["prefix"], b["why"])
                    for b in benign]
        _benign_note = (" Also present, reported but NOT a cause of a bootstrap failure: "
                        + "; ".join(_b_items))

    # --- blackholes that DO cover something this workspace must reach ---------
    if breaking or unproven:
        flagged = breaking + unproven
        parts = []
        if default_route is not None and default_route["next_hop_type"] == "None":
            parts.append(
                f"UDR '{rt_name}' BLACKHOLES 0.0.0.0/0 (route '{default_route['name']}' next-hop=None). "
                "EVERY internet-bound packet from this subnet is silently dropped — control plane / SCC "
                "relay, artifact storage, PyPI/Maven and any customer endpoint outside the VNet. "
                "Destinations served inside the VNet (private endpoints, back-end Private Link) still "
                "work, which is why the symptom can look partial.")
        specific = [b for b in flagged if not b["is_default_route"]]
        if specific:
            _s_items = []
            for b in specific:
                item = "route '%s' prefix %s (next-hop None) — %s" % (b["name"], b["prefix"], b["why"])
                if b["covers"]:
                    item += " Drops: " + "; ".join(b["covers"]) + "."
                _s_items.append(item)
            # Only claim the firewall is bypassed when a forced tunnel actually exists —
            # the same "don't narrate an observation you did not make" rule as before.
            if default_route is not None and default_route["next_hop_type"] == "VirtualAppliance":
                _wins = ("Because Azure applies LONGEST-PREFIX MATCH, each of these WINS over the "
                         "subnet's 0.0.0.0/0 route, so the traffic never reaches the NVA/firewall at "
                         "%s at all and a correct firewall allow-list cannot compensate."
                         % default_route["next_hop_ip"])
            elif default_route is not None:
                _wins = ("Because Azure applies LONGEST-PREFIX MATCH, each of these WINS over the "
                         "subnet's 0.0.0.0/0 route (-> %s)." % default_route["next_hop_type"])
            else:
                _wins = ("This table has no 0.0.0.0/0 entry, but a UDR still overrides Azure's own "
                         "system route for the prefixes it names, so these prefixes are black-holed.")
            parts.append(
                "UDR '%s' BLACKHOLES %d specific destination prefix(es) with next-hop 'None': %s %s "
                "Blackholed packets are discarded with no ICMP, which surfaces as a connection "
                "TIMEOUT (curl 28) rather than a TLS or HTTP error."
                % (rt_name, len(specific), " ".join(_s_items), _wins))
        if not breaking:
            parts.append("Coverage of a Databricks-required destination could NOT be verified for the "
                         "route(s) above, so this is flagged as UNRESOLVED rather than confirmed.")
        parts.append(_inventory)
        _rec_routes = "; ".join("'%s' (%s)" % (b["name"], b["prefix"]) for b in flagged)
        return CheckResult("Subnet Route Table", target, Status.FAIL,
            _sn + " ".join(parts) + _benign_note,
            raw_output="routes=%s" % (_inv_items,),
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                f"Azure Portal > Route tables > {rt_name} > Routes > {_rec_routes}: delete the "
                "route, or change its next hop to the path the traffic should actually take — "
                "'Internet' for direct Azure egress, or 'Virtual appliance' + the hub firewall's "
                "private IP if this egress must be inspected. A next hop of 'None' is a blackhole: "
                "packets are discarded silently. Wait 1-2 minutes for propagation, then retry the "
                "cluster."
            ),
            metadata=md)

    # --- no blackhole on a required destination: judge the default route -------
    if default_route is None:
        return CheckResult("Subnet Route Table", target,
            Status.WARN if benign else Status.PASS,
            _sn + f"UDR '{rt_name}' has no 0.0.0.0/0 override — default Azure Internet routing for "
            "control-plane traffic (note: a BGP-advertised default route from an "
            "ExpressRoute/VPN gateway or Route Server would not appear in a route table). "
            + _inventory + _benign_note,
            raw_output=f"routes={[r.get('name') for r in routes]}",
            duration_ms=(_time.time() - start) * 1000,
            metadata=md)
    hop = default_route["next_hop_type"]
    if hop == "VirtualAppliance":
        return CheckResult("Subnet Route Table", target, Status.WARN,
            _sn + f"UDR '{rt_name}' forces 0.0.0.0/0 through NVA at {default_route['next_hop_ip']}. "
            "ALL internet-bound egress from this subnet (control plane, artifact storage, "
            "PyPI/Maven, customer endpoints outside the VNet) depends on that appliance's rules. "
            + _inventory + _benign_note,
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                f"Verify the NVA at {default_route['next_hop_ip']} allows outbound HTTPS (443) to: "
                "the regional Databricks control-plane CIDRs (see Microsoft service-tag CIDR list "
                "for 'AzureDatabricks' in this region), *.azuredatabricks.net, www.databricks.com, "
                "*.databricks.com, and the SCC relay — plus whatever else this workspace egresses to. "
                "(This check reads ROUTING only; it has no cluster error text as input, so it "
                "attributes nothing to the appliance.)"
            ),
            metadata=md)
    return CheckResult("Subnet Route Table", target,
        Status.WARN if benign else Status.PASS,
        _sn + f"UDR '{rt_name}' default route 0.0.0.0/0 -> {hop}, and no route in the table blackholes a "
        f"destination the cluster bootstrap needs. " + _inventory + _benign_note,
        duration_ms=(_time.time() - start) * 1000,
        metadata=md)


def check_subnet_egress_ip(arm_token, vnet_id, subnet_name):
    """Resolve the subnet's egress public IP via NAT gateway (if any)."""
    start = _time.time()
    target = f"{vnet_id.split('/')[-1]}/{subnet_name}" if vnet_id else subnet_name
    if not vnet_id or not subnet_name:
        return CheckResult("Subnet Egress IP", target, Status.SKIP,
            "VNet id or subnet name missing.",
            duration_ms=(_time.time() - start) * 1000)
    subnet_url = f"https://management.azure.com{vnet_id}/subnets/{subnet_name}?api-version=2023-02-01"
    sd = _arm_get(arm_token, subnet_url)
    if "_error" in sd:
        return CheckResult("Subnet Egress IP", target, Status.ERROR,
            f"Could not read subnet: {sd['_error']}",
            duration_ms=(_time.time() - start) * 1000)
    nat_ref = (sd.get("properties", {}) or {}).get("natGateway", {}) or {}
    nat_id = nat_ref.get("id", "")
    if not nat_id:
        return CheckResult("Subnet Egress IP", target, Status.WARN,
            f"No NAT gateway attached to '{subnet_name}'. Egress uses default Azure outbound or an "
            "NVA via UDR; egress IP is not stable. Workspace IP access lists keyed on a single IP "
            "will not reliably allow this subnet.",
            duration_ms=(_time.time() - start) * 1000,
            metadata={"egress_ips": []})
    nat_data = _arm_get(arm_token, f"https://management.azure.com{nat_id}?api-version=2023-02-01")
    if "_error" in nat_data:
        return CheckResult("Subnet Egress IP", target, Status.ERROR,
            f"Could not read NAT gateway: {nat_data['_error']}",
            duration_ms=(_time.time() - start) * 1000)
    pip_refs = (nat_data.get("properties", {}) or {}).get("publicIpAddresses", []) or []
    egress_ips = []
    for pr in pip_refs:
        pip_id = pr.get("id", "")
        if not pip_id:
            continue
        pip_data = _arm_get(arm_token, f"https://management.azure.com{pip_id}?api-version=2023-02-01")
        ip = (pip_data.get("properties", {}) or {}).get("ipAddress", "")
        if ip:
            egress_ips.append(ip)
    if not egress_ips:
        return CheckResult("Subnet Egress IP", target, Status.WARN,
            f"NAT gateway '{nat_id.split('/')[-1]}' has no resolved public IPs.",
            duration_ms=(_time.time() - start) * 1000,
            metadata={"egress_ips": []})
    return CheckResult("Subnet Egress IP", target, Status.PASS,
        f"Subnet '{subnet_name}' egresses via NAT gateway with public IP(s): {', '.join(egress_ips)}",
        duration_ms=(_time.time() - start) * 1000,
        metadata={"egress_ips": egress_ips, "nat_id": nat_id})


def check_workspace_ip_access_list(workspace_url, databricks_pat, egress_ips=None):
    """Read the workspace's IP access list and check whether egress IPs are allowed.

    Uses the workspace REST API (not ARM). `databricks_pat` is a token with
    workspace admin permissions — typically the SP's Databricks PAT issued
    via the SP's account-admin or workspace-admin role.

    If `egress_ips` is None or empty, this returns INFO with the list state
    only; the correlation rule will use it together with subnet egress IP.
    """
    import requests as _req
    start = _time.time()
    target = workspace_url
    if not workspace_url:
        return CheckResult("Workspace IP Access List", "(no workspace url)", Status.SKIP,
            "workspace_url missing — cannot query IP access list.",
            duration_ms=(_time.time() - start) * 1000)
    if not databricks_pat:
        return CheckResult("Workspace IP Access List", target, Status.SKIP,
            "No Databricks workspace PAT provided — cannot query /api/2.0/ip-access-lists. "
            "(Customer admin can fetch this from Workspace settings > Security > IP access list.)",
            duration_ms=(_time.time() - start) * 1000)
    base = workspace_url.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    headers = {"Authorization": f"Bearer {databricks_pat}"}
    try:
        cfg = _req.get(f"{base}/api/2.0/workspace-conf?keys=enableIpAccessLists",
                       headers=headers, timeout=10)
        enabled = False
        if cfg.status_code == 200:
            enabled = (cfg.json().get("enableIpAccessLists", "false") in (True, "true"))
        lists_resp = _req.get(f"{base}/api/2.0/ip-access-lists", headers=headers, timeout=10)
        if lists_resp.status_code != 200:
            return CheckResult("Workspace IP Access List", target, Status.ERROR,
                f"HTTP {lists_resp.status_code} reading IP access lists: {lists_resp.text[:200]}",
                duration_ms=(_time.time() - start) * 1000)
        lists = lists_resp.json().get("ip_access_lists", [])
    except Exception as e:
        return CheckResult("Workspace IP Access List", target, Status.ERROR,
            f"Could not read IP access list: {e}",
            duration_ms=(_time.time() - start) * 1000)

    allow_cidrs = []
    block_cidrs = []
    for l in lists:
        if not l.get("enabled", True):
            continue
        if l.get("list_type") == "ALLOW":
            allow_cidrs.extend(l.get("ip_addresses", []) or [])
        elif l.get("list_type") == "BLOCK":
            block_cidrs.extend(l.get("ip_addresses", []) or [])

    if not enabled:
        return CheckResult("Workspace IP Access List", target, Status.PASS,
            "Workspace IP access list is disabled — not the cause of the 401.",
            duration_ms=(_time.time() - start) * 1000,
            metadata={"enabled": False, "allow": allow_cidrs, "block": block_cidrs})

    if egress_ips:
        unmatched = []
        for ip in egress_ips:
            try:
                ip_obj = _ipaddress.ip_address(ip)
            except ValueError:
                continue
            in_allow = any(_ip_in_cidr(ip_obj, c) for c in allow_cidrs) if allow_cidrs else False
            in_block = any(_ip_in_cidr(ip_obj, c) for c in block_cidrs)
            if in_block or (allow_cidrs and not in_allow):
                unmatched.append(ip)
        if unmatched:
            return CheckResult("Workspace IP Access List", target, Status.FAIL,
                f"IP access list ENABLED. Subnet egress IP(s) {unmatched} are NOT in the ALLOW list "
                "(or are in the BLOCK list). The workspace front door returns 401 'privacy settings "
                "disallow access' to bootstrap traffic from this subnet.",
                duration_ms=(_time.time() - start) * 1000,
                recommendation=(
                    "Add the subnet's egress public IP(s) to the workspace ALLOW list:\n"
                    "Databricks Workspace > Settings > Security > IP access list > ALLOW > "
                    f"add {', '.join(unmatched)}/32. Wait ~1 minute, then retry the cluster start."
                ),
                metadata={"enabled": True, "allow": allow_cidrs, "block": block_cidrs,
                          "unmatched_egress_ips": unmatched})
        return CheckResult("Workspace IP Access List", target, Status.PASS,
            f"IP access list ENABLED but subnet egress IP(s) {egress_ips} match the ALLOW list.",
            duration_ms=(_time.time() - start) * 1000,
            metadata={"enabled": True, "allow": allow_cidrs, "block": block_cidrs})

    return CheckResult("Workspace IP Access List", target, Status.WARN,
        f"IP access list is ENABLED ({len(allow_cidrs)} allow, {len(block_cidrs)} block CIDRs) but "
        "the subnet's egress IP could not be resolved — cannot confirm whether the data plane is "
        "allowed. If the cluster's NAT/firewall public IP is not in the ALLOW list, the front door "
        "will return 401.",
        duration_ms=(_time.time() - start) * 1000,
        metadata={"enabled": True, "allow": allow_cidrs, "block": block_cidrs})


def _ip_in_cidr(ip_obj, cidr_str):
    try:
        return ip_obj in _ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False


def check_workspace_private_link(workspace_network_cfg, vnet_id):
    """Validate workspace publicNetworkAccess vs private endpoint topology."""
    start = _time.time()
    target = workspace_network_cfg.get("workspace_url", "")
    pna = workspace_network_cfg.get("public_network_access", "")
    pe_conns = workspace_network_cfg.get("private_endpoint_connections", []) or []

    if pna != "Disabled":
        return CheckResult("Workspace Private Link", target, Status.PASS,
            f"publicNetworkAccess={pna or 'Enabled'} — workspace front door is reachable over public DNS.",
            duration_ms=(_time.time() - start) * 1000,
            metadata={"public_network_access": pna, "pe_count": len(pe_conns)})

    approved_in_vnet = []
    for pe in pe_conns:
        pe_props = pe.get("properties", {}) or {}
        state = ((pe_props.get("privateLinkServiceConnectionState", {}) or {}).get("status", ""))
        pe_id = (pe_props.get("privateEndpoint", {}) or {}).get("id", "")
        # Heuristic: PE is "in-VNet" if its resource id lives under the same VNet's resource group.
        if state == "Approved" and vnet_id and pe_id and \
                _parse_resource_id(pe_id).get("resource_group") == _parse_resource_id(vnet_id).get("resource_group"):
            approved_in_vnet.append(pe_id.split("/")[-1])

    if not pe_conns:
        return CheckResult("Workspace Private Link", target, Status.FAIL,
            "publicNetworkAccess=Disabled and the workspace has NO private endpoint connections. "
            "Bootstrap traffic to the front door cannot succeed (401 'privacy settings disallow access').",
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Either re-enable publicNetworkAccess, OR create a front-end Private Endpoint for "
                "the workspace and link a privatelink.azuredatabricks.net Private DNS zone to the "
                "data-plane VNet."
            ),
            metadata={"public_network_access": pna, "pe_count": 0})

    if not approved_in_vnet:
        return CheckResult("Workspace Private Link", target, Status.FAIL,
            f"publicNetworkAccess=Disabled. Workspace has {len(pe_conns)} PE connection(s) but none "
            "are in (or sharable with) the data-plane VNet's resource group. Bootstrap traffic 401s.",
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Add a front-end Private Endpoint in (or peered to) the data-plane VNet, approve it, "
                "and link the privatelink.azuredatabricks.net Private DNS zone to that VNet."
            ),
            metadata={"public_network_access": pna, "pe_count": len(pe_conns)})

    return CheckResult("Workspace Private Link", target, Status.PASS,
        f"publicNetworkAccess=Disabled but {len(approved_in_vnet)} approved PE(s) reach the "
        f"data-plane VNet ({', '.join(approved_in_vnet)}).",
        duration_ms=(_time.time() - start) * 1000,
        metadata={"public_network_access": pna, "approved_pes_in_vnet": approved_in_vnet})


def _vnet_id_from_subnet_id(subnet_id):
    """Derive the parent VNet ARM id from a subnet ARM id (.../virtualNetworks/<v>/subnets/<s>)."""
    s = subnet_id or ""
    idx = s.lower().find("/subnets/")
    return s[:idx] if idx != -1 else ""


def _resolve_pe_vnet(arm_token, pe_id):
    """ARM GET a private endpoint resource and return (vnet_id_of_its_subnet, error).

    Reads Azure live via the ARM token — no offline snapshot path."""
    if not pe_id:
        return "", "no private endpoint resource id on the connection"
    url = f"https://management.azure.com{pe_id}?api-version=2023-05-01"
    data = _arm_get(arm_token, url)
    if "_error" in data:
        return "", data["_error"]
    subnet_id = ((data.get("properties", {}) or {}).get("subnet", {}) or {}).get("id", "")
    if not subnet_id:
        return "", "private endpoint has no properties.subnet.id"
    vnet = _vnet_id_from_subnet_id(subnet_id)
    if not vnet:
        return "", f"could not derive VNet id from subnet id '{subnet_id}'"
    return vnet, ""


def check_backend_private_link(workspace_network_cfg, vnet_id, arm_token=""):
    """Detect a back-end (classic compute plane) Private Link connection.

    FRONT-END (inbound) Private Link uses the SAME `databricks_ui_api` sub-resource —
    only the PE's location distinguishes them (back-end = subnet of the workspace
    data-plane VNet; front-end = transit/hub VNet). `has_backend_pe` is True ONLY for
    an Approved databricks_ui_api PE whose subnet is VERIFIED in the data-plane VNet.
    Doc: https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/private-link-standard

    metadata: has_backend_pe, backend_pe_names, frontend_pe_names, unverified_pe_names,
    verification_errors, ui_api_pe_states, vnet_verified, in_vnet (legacy RG heuristic).
    """
    start = _time.time()
    target = workspace_network_cfg.get("workspace_url", "")
    pe_conns = workspace_network_cfg.get("private_endpoint_connections", []) or []

    def _group_ids(pe_props):
        gids = pe_props.get("groupIds") or []
        if not gids:
            plsc = pe_props.get("privateLinkServiceConnectionState", {}) or {}
            for v in (pe_props.get("groupId"), plsc.get("groupId")):
                if v:
                    gids = [v]
                    break
        return [str(g) for g in gids]

    ui_api_pes = []  # (name, state, pe_id, rg_heuristic_in_vnet)
    for pe in pe_conns:
        pe_props = pe.get("properties", {}) or {}
        gids = _group_ids(pe_props)
        if not any("databricks_ui_api" in g for g in gids):
            continue
        state = ((pe_props.get("privateLinkServiceConnectionState", {}) or {}).get("status", ""))
        pe_id = (pe_props.get("privateEndpoint", {}) or {}).get("id", "")
        name = pe_id.split("/")[-1] if pe_id else (pe.get("name", "") or "ui_api_pe")
        rg_match = bool(
            vnet_id and pe_id
            and _parse_resource_id(pe_id).get("resource_group") == _parse_resource_id(vnet_id).get("resource_group")
        )
        ui_api_pes.append((name, state, pe_id, rg_match))

    approved = [p for p in ui_api_pes if p[1] == "Approved"]
    can_verify = bool(arm_token)

    backend_pe_names, frontend_pe_names, unverified_pe_names, verification_errors = [], [], [], []
    if can_verify and vnet_id:
        for name, _state, pe_id, _rg in approved:
            pe_vnet, err = _resolve_pe_vnet(arm_token, pe_id)
            if err:
                unverified_pe_names.append(name)
                verification_errors.append(f"{name}: {err}")
            elif pe_vnet.lower() == vnet_id.lower():
                backend_pe_names.append(name)
            else:
                frontend_pe_names.append(name)

    vnet_verified = bool(can_verify and vnet_id and approved and not unverified_pe_names)

    if can_verify and vnet_id:
        has_backend_pe = bool(backend_pe_names)
    else:
        has_backend_pe = bool(approved)  # legacy fallback, marked unverified

    md = {
        "has_backend_pe": has_backend_pe,
        "backend_pe_names": backend_pe_names if (can_verify and vnet_id) else [p[0] for p in approved],
        "frontend_pe_names": frontend_pe_names,
        "unverified_pe_names": unverified_pe_names,
        "verification_errors": verification_errors,
        "ui_api_pe_states": [p[1] for p in ui_api_pes],
        "vnet_verified": vnet_verified,
        "in_vnet": any(p[3] for p in approved),
    }

    if not ui_api_pes:
        return CheckResult("Backend Private Link", target, Status.SKIP,
            "No back-end (databricks_ui_api) Private Link private endpoint found on the workspace.",
            duration_ms=(_time.time() - start) * 1000, metadata=md)

    if not approved:
        return CheckResult("Backend Private Link", target, Status.WARN,
            f"A databricks_ui_api private endpoint exists but is not Approved "
            f"(states: {', '.join(md['ui_api_pe_states'])}). Back-end Private Link appears intended but "
            "the connection is not active.",
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Approve the databricks_ui_api private endpoint connection (Azure Portal > workspace > "
                "Networking / Private endpoint connections), and ensure the privatelink.azuredatabricks.net "
                "Private DNS zone is linked to the workspace VNet so compute resolves the workspace URL to "
                "the PE private IP. Doc: https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/private-link-standard"
            ),
            metadata=md)

    if can_verify and vnet_id:
        if backend_pe_names:
            return CheckResult("Backend Private Link", target, Status.PASS,
                f"Back-end (classic compute plane) Private Link CONFIRMED: {len(backend_pe_names)} Approved "
                f"databricks_ui_api private endpoint(s) verified IN the data-plane VNet "
                f"({', '.join(backend_pe_names)}). With back-end Private Link, "
                "requiredNsgRules=NoAzureDatabricksRules is the documented-correct setting — the public "
                "AzureDatabricks NSG egress rules are intentionally not used."
                + (f" Note: {len(frontend_pe_names)} additional Approved databricks_ui_api PE(s) sit outside "
                   f"the data-plane VNet (likely front-end): {', '.join(frontend_pe_names)}."
                   if frontend_pe_names else ""),
                duration_ms=(_time.time() - start) * 1000, metadata=md)
        if frontend_pe_names and not unverified_pe_names:
            return CheckResult("Backend Private Link", target, Status.WARN,
                f"Found {len(frontend_pe_names)} Approved databricks_ui_api private endpoint(s) "
                f"({', '.join(frontend_pe_names)}) OUTSIDE the data-plane VNet — this is likely FRONT-END "
                "(inbound) Private Link for user/API access. It does NOT provide the back-end compute-plane "
                "path, so it does not justify requiredNsgRules=NoAzureDatabricksRules for the data plane.",
                duration_ms=(_time.time() - start) * 1000,
                recommendation=(
                    "The data plane still needs a path to the control plane: either flip requiredNsgRules to "
                    "AllRules, configure true back-end Private Link (databricks_ui_api PE in a dedicated subnet "
                    "of the WORKSPACE data-plane VNet + privatelink.azuredatabricks.net DNS integration), or add "
                    "the NSG rules manually. Doc: https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/private-link-standard"
                ),
                metadata=md)
        return CheckResult("Backend Private Link", target, Status.WARN,
            f"Approved databricks_ui_api private endpoint(s) exist ({', '.join(unverified_pe_names)}) but the "
            "PE resource could not be read via ARM to verify its subnet/VNet "
            f"({'; '.join(verification_errors)}). Cannot confirm back-end Private Link — treating it as NOT "
            "confirmed (conservative): the SP may lack Reader on the PE's resource group.",
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Grant the Reader SP access to the resource group holding the private endpoint (or re-run with "
                "subscription-level Reader) and re-run the diagnostic. If back-end Private Link IS configured "
                "for this workspace, verify the PE's subnet is in the workspace data-plane VNet and the "
                "privatelink.azuredatabricks.net Private DNS zone integration — do NOT flip requiredNsgRules "
                "to AllRules based on this incomplete scan alone."
            ),
            metadata=md)

    return CheckResult("Backend Private Link", target, Status.WARN,
        f"{len(approved)} Approved databricks_ui_api private endpoint(s) found "
        f"({', '.join(md['backend_pe_names'])}), but no ARM token/cache was available to verify the PE's "
        "subnet, so back-end vs front-end Private Link cannot be distinguished (vnet_verified=False).",
        duration_ms=(_time.time() - start) * 1000, metadata=md)


def check_dns_resolution_for_workspace(arm_token, vnet_id, workspace_url, public_network_access):
    """If publicNetworkAccess=Disabled, verify privatelink DNS zone is linked and has a record."""
    start = _time.time()
    target = workspace_url
    if not workspace_url:
        return CheckResult("Workspace Private DNS", "(no workspace url)", Status.SKIP,
            "workspace_url missing.",
            duration_ms=(_time.time() - start) * 1000)
    if public_network_access != "Disabled":
        return CheckResult("Workspace Private DNS", target, Status.SKIP,
            "publicNetworkAccess is not Disabled — Private DNS zone for workspace not required.",
            duration_ms=(_time.time() - start) * 1000)
    if not vnet_id:
        return CheckResult("Workspace Private DNS", target, Status.SKIP,
            "VNet id missing.",
            duration_ms=(_time.time() - start) * 1000)

    # Find privatelink.azuredatabricks.net zones the SP can see, then check VNet links.
    parsed = _parse_resource_id(vnet_id)
    sub_id = parsed.get("subscription_id", "")
    if not sub_id:
        return CheckResult("Workspace Private DNS", target, Status.ERROR,
            "Could not parse subscription id from VNet id.",
            duration_ms=(_time.time() - start) * 1000)
    zones_url = (f"https://management.azure.com/subscriptions/{sub_id}"
                 "/providers/Microsoft.Network/privateDnsZones?api-version=2020-06-01")
    zones_data = _arm_get(arm_token, zones_url)
    if "_error" in zones_data:
        return CheckResult("Workspace Private DNS", target, Status.ERROR,
            f"Could not list private DNS zones: {zones_data['_error']}",
            duration_ms=(_time.time() - start) * 1000)
    zones = zones_data.get("value", []) or []
    pl_zones = [z for z in zones if z.get("name", "") == "privatelink.azuredatabricks.net"]
    if not pl_zones:
        return CheckResult("Workspace Private DNS", target, Status.FAIL,
            "publicNetworkAccess=Disabled but no 'privatelink.azuredatabricks.net' Private DNS zone "
            "exists in the subscription. Workspace URL cannot resolve to the PE — bootstrap fails.",
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Create a Private DNS zone 'privatelink.azuredatabricks.net', link it to the "
                "data-plane VNet, and add an A record for the workspace pointing to the front-end "
                "PE's private IP."
            ))
    issues = []
    matched_zone = None
    for z in pl_zones:
        z_id = z.get("id", "")
        z_rg = _parse_resource_id(z_id).get("resource_group", "")
        links_url = (f"https://management.azure.com{z_id}/virtualNetworkLinks?api-version=2020-06-01")
        links_data = _arm_get(arm_token, links_url)
        links = links_data.get("value", []) if "_error" not in links_data else []
        linked = any((((l.get("properties", {}) or {}).get("virtualNetwork", {}) or {}).get("id", "").lower()
                      == vnet_id.lower()) for l in links)
        if not linked:
            issues.append(f"zone in RG '{z_rg}' is NOT linked to data-plane VNet")
            continue
        # Look up workspace A record
        host_label = workspace_url.split(".")[0] if workspace_url else ""
        recs_url = (f"https://management.azure.com{z_id}/A/{host_label}?api-version=2020-06-01")
        recs_data = _arm_get(arm_token, recs_url)
        if "_error" in recs_data:
            issues.append(f"zone in RG '{z_rg}' linked but A record for '{host_label}' missing")
            continue
        a_records = (recs_data.get("properties", {}) or {}).get("aRecords", []) or []
        if not a_records:
            issues.append(f"zone in RG '{z_rg}' has no A record for '{host_label}'")
        else:
            ips = [a.get("ipv4Address") for a in a_records if a.get("ipv4Address")]
            matched_zone = {"zone_id": z_id, "ips": ips}
            break

    if matched_zone:
        return CheckResult("Workspace Private DNS", target, Status.PASS,
            f"Private DNS zone linked to VNet and A record resolves workspace to {matched_zone['ips']}",
            duration_ms=(_time.time() - start) * 1000,
            metadata=matched_zone)
    return CheckResult("Workspace Private DNS", target, Status.FAIL,
        "Private DNS issue: " + "; ".join(issues),
        duration_ms=(_time.time() - start) * 1000,
        recommendation=(
            "Link 'privatelink.azuredatabricks.net' to the data-plane VNet and add an A record for "
            "the workspace pointing to the front-end PE's private IP."
        ))


def check_outbound_to_databricks_com(route_table_check, nhc=None):
    """Does the subnet's default route send www.databricks.com through an appliance?

    We cannot do live HTTPS from serverless on behalf of the broken cluster, so this
    reports the ROUTING disposition only.

    `nhc`: the parse_nhc_error result. the "a 403 from www.databricks.com in the
    NHC error is consistent with…" sentence used to be emitted UNCONDITIONALLY on any
    forced-tunnel route, i.e. it invented an observation. Worse, in the field it
    also MISDESCRIBED the actual failure, which was a curl (35) SSL error, not a 403.
    The clause is now emitted only when parse_nhc_error actually saw that 403.
    """
    start = _time.time()
    _sig = ((nhc or {}).get("signals") or {}) if isinstance(nhc, dict) else {}
    _saw_403 = bool(_sig.get("databricks_com_403"))
    _saw_dbc_failure = bool(_sig.get("databricks_com_failure"))
    if route_table_check is None:
        return CheckResult("Outbound to www.databricks.com", "(unknown subnet)", Status.SKIP,
            "Route table check did not run.",
            duration_ms=(_time.time() - start) * 1000)
    md = route_table_check.metadata or {}
    default_route = md.get("default_route")
    target = route_table_check.target
    if default_route is None:
        return CheckResult("Outbound to www.databricks.com", target, Status.PASS,
            "No 0.0.0.0/0 override — outbound to www.databricks.com uses default Azure Internet path.",
            duration_ms=(_time.time() - start) * 1000)
    hop = default_route.get("next_hop_type")
    if hop == "VirtualAppliance":
        if _saw_403:
            _corr = ("The 403 from www.databricks.com recorded in the NHC error is consistent with "
                     "the NVA blocking or filtering this destination.")
        elif _saw_dbc_failure:
            _corr = ("The www.databricks.com failure recorded in the NHC error is consistent with "
                     "the NVA blocking or filtering this destination.")
        else:
            _corr = ("No NHC evidence about www.databricks.com was available in this run, so nothing "
                     "is attributed to the appliance — this row states the ROUTING fact only.")
        return CheckResult("Outbound to www.databricks.com", target, Status.WARN,
            f"All outbound (including www.databricks.com:443) is forced through NVA at "
            f"{default_route.get('next_hop_ip')}. {_corr}",
            duration_ms=(_time.time() - start) * 1000,
            recommendation=(
                "Verify the NVA / firewall rule set explicitly allows outbound HTTPS to "
                "www.databricks.com, *.databricks.com, and *.azuredatabricks.net. Without those "
                "allowances a cluster's bootstrap NHC cannot reach the control plane."
            ),
            metadata={"default_route": default_route, "nhc_databricks_com_403": _saw_403,
                      "nhc_databricks_com_failure": _saw_dbc_failure})
    if hop == "None":
        return CheckResult("Outbound to www.databricks.com", target, Status.FAIL,
            "Outbound to www.databricks.com is blackholed by the subnet's default UDR.",
            duration_ms=(_time.time() - start) * 1000,
            metadata={"default_route": default_route})
    return CheckResult("Outbound to www.databricks.com", target, Status.PASS,
        f"Default route next-hop={hop}; outbound to www.databricks.com is not forced through an NVA.",
        duration_ms=(_time.time() - start) * 1000)


# ---------------------------------------------------------------------------
# Forced-tunnel firewall egress check (Path C deep analysis)
# ---------------------------------------------------------------------------
#
# When a subnet's 0.0.0.0/0 UDR forces egress through an Azure Firewall (NVA),
# the FIREWALL's allow-list — not the NSG — is the real gate for the bootstrap
# NHC's outbound HTTPS to the Databricks artifact storage and control plane
# (the UDR wins: every packet goes to the firewall regardless of NSG rules).
# This check resolves the next-hop IP to the Azure Firewall, reads its rules
# (policy rule-collection-groups OR classic collections), and cross-checks the
# NHC's failed destinations against what the firewall actually allows — turning
# the generic "verify your NVA" WARN into a precise "missing Storage egress" FAIL.

_REQUIRED_EGRESS = {
    "storage": {
        # Label must fit BOTH uses of this category: Databricks' own artifact/log/DBFS
        # storage AND a customer's own ADLS/blob account reached through the same egress
        # path. Naming only the Databricks-managed case made the prescription read as if
        # the customer's partner-feed ADLS account were a Databricks internal endpoint
        # .
        # Keep this SHORT: it is interpolated mid-sentence into the customer-facing root
        # cause ("BLOCKS egress for <label> via Deny rule '...'"), so a long trailing
        # clause makes the sentence unparseable.
        "label": "Azure Storage :443 (Storage service tag / blob + dfs endpoints)",
        "service_tags": ("storage",),
        # ADLS Gen2 is reached over the dfs endpoint; omitting it meant an application
        # rule allowing *.dfs.core.windows.net was never credited as covering storage.
        "fqdn_suffixes": (".blob.core.windows.net", ".dfs.core.windows.net"),
        "fqdns": (),
    },
    "control_plane": {
        "label": "Databricks control plane / SCC relay / webapp (AzureDatabricks tag / *.azuredatabricks.net / *.databricks.com :443)",
        "service_tags": ("azuredatabricks",),
        "fqdn_suffixes": (".azuredatabricks.net", ".databricks.com"),
        "fqdns": ("www.databricks.com",),
    },
}


def _required_human(cats):
    return "; ".join(_REQUIRED_EGRESS[c]["label"] for c in cats)


def _fw_collect_allows(rule_collections):
    """Flatten Allow rule collections into sets of allowed service tags + FQDNs.

    Handles both the firewall-policy shape (rc['action']['type'], rc['rules'])
    and the classic firewall shape (rc['properties']['action']['type'],
    rc['properties']['rules'])."""
    tags, fqdns = set(), set()
    for rc in rule_collections or []:
        action = ((rc.get("action") or {}).get("type")
                  or ((rc.get("properties") or {}).get("action") or {}).get("type") or "")
        if str(action).lower() != "allow":
            continue
        rules = rc.get("rules") or (rc.get("properties") or {}).get("rules") or []
        for r in rules:
            for fq in (r.get("targetFqdns") or []):
                fqdns.add(str(fq).lower())
            for tag in (r.get("fqdnTags") or []):
                tags.add(str(tag).lower())
            for dest in (r.get("destinationAddresses") or []):
                # service tags look like "Storage" / "Storage.Northcentralus" / "AzureDatabricks" / "*"
                tags.add(str(dest).lower().split(".")[0])
    return tags, fqdns


def _fw_covers(category, tags, fqdns):
    spec = _REQUIRED_EGRESS[category]
    if "*" in tags or any(t in tags for t in spec.get("service_tags", ())):
        return True
    for fq in fqdns:
        if any(fq.endswith(suf) for suf in spec.get("fqdn_suffixes", ())):
            return True
        if fq in spec.get("fqdns", ()):
            return True
    return False


# ---------------------------------------------------------------------------
# Precedence-aware firewall rule evaluation (rule-level inspection)
# ---------------------------------------------------------------------------
#
# WHY: the flat allow-set above (`_fw_collect_allows` + `_fw_covers`) answers only
# "is there ANY Allow for this category?". It silently ignores DENY rules and rule
# PRECEDENCE, so a higher-priority Deny that blocks the Databricks egress is
# invisible and the Doctor would report a (confidently wrong) PASS. It also ignores
# the Azure DNS-proxy requirement: an FQDN used in a NETWORK rule never matches
# unless DNS Proxy is enabled on the policy.
#
# This evaluator models how Azure Firewall actually decides an egress flow:
#   1. Network rules are evaluated BEFORE application rules (rule-type wins over
#      any priority number).
#   2. Within a rule type, by rule-collection-group priority, then rule-collection
#      priority (lower number = evaluated first).
#   3. FIRST matching rule wins; its action (Allow/Deny) is the verdict.
#   4. No rule matches -> implicit deny (Azure default).
#   5. An FQDN match in a NETWORK rule requires DNS Proxy enabled, else it can't
#      resolve and silently fails (service-tag matches and application-rule FQDNs
#      do not need DNS proxy).
# (Threat-intel deny mode, DNAT, and per-source-CIDR matching are out of scope for
# this first pass — see infra.md scope note. Source is treated permissively here.)

# Verdict decisions (per required-egress category):
_FW_ALLOWED = "ALLOWED"
_FW_DENIED = "DENIED_BY_RULE"
_FW_NO_MATCH = "NO_MATCH"                  # implicit deny — the existing "missing allow" case
_FW_DNS_PROXY = "BLOCKED_BY_DNS_PROXY"


def _fw_port_matches(ports, want="443"):
    """True if `want` is covered by an Azure ports list (handles '*' and 'a-b' ranges)."""
    if not ports:
        return False
    w = int(want)
    for p in ports:
        p = str(p).strip()
        if p == "*":
            return True
        if "-" in p:
            try:
                lo, hi = (int(x) for x in p.split("-", 1))
                if lo <= w <= hi:
                    return True
            except ValueError:
                continue
        elif p == want:
            return True
    return False


def _fw_proto_matches(protos):
    """True if the rule's protocols permit TCP/443 (TCP, Any, *, or Https)."""
    if not protos:
        return False
    ok = {"tcp", "any", "*", "https"}
    return any(str(p).strip().lower() in ok for p in protos)


def _fw_normalize_rules(rule_collections, rcg_priority=0):
    """Flatten rule collections (policy OR classic shape) into ordered rule entries
    that preserve action, priority, type, and destination matchers.

    Each entry: {action, rcg_priority, collection_priority, collection_name,
                 rule_type ('network'|'application'), rule_name,
                 dest_tags(set), dest_fqdns(set), ports(set), protos(set)}.
    """
    entries = []
    for rc in rule_collections or []:
        props = rc.get("properties") or rc          # classic nests under .properties
        action = str((props.get("action") or {}).get("type")
                      or (rc.get("action") or {}).get("type") or "").lower()
        cprio = props.get("priority", rc.get("priority", 0)) or 0
        cname = rc.get("name", "")
        for r in (props.get("rules") or rc.get("rules") or []):
            rtype_raw = str(r.get("ruleType") or "").lower()
            is_app = "application" in rtype_raw or bool(r.get("protocols")) or bool(r.get("targetFqdns")) or bool(r.get("fqdnTags"))
            is_net = "network" in rtype_raw or bool(r.get("destinationAddresses")) or bool(r.get("destinationPorts"))
            # default to network if ambiguous (destinationAddresses present)
            rule_type = "application" if (is_app and not r.get("destinationAddresses")) else "network"
            tags, fqdns, ports, protos = set(), set(), set(), set()
            if rule_type == "network":
                for d in (r.get("destinationAddresses") or []):
                    tags.add(str(d).lower().split(".")[0])   # 'Storage.NorthCentralUS' -> 'storage'
                for fq in (r.get("destinationFqdns") or []):
                    fqdns.add(str(fq).lower())
                ports.update(str(p) for p in (r.get("destinationPorts") or []))
                protos.update(str(p) for p in (r.get("ipProtocols") or []))
            else:
                for fq in (r.get("targetFqdns") or []):
                    fqdns.add(str(fq).lower())
                for tag in (r.get("fqdnTags") or []):
                    tags.add(str(tag).lower())
                for pr in (r.get("protocols") or []):
                    protos.add(str(pr.get("protocolType", "")))
                    if pr.get("port") is not None:
                        ports.add(str(pr.get("port")))
            entries.append({
                "action": action or "allow", "rcg_priority": rcg_priority,
                "collection_priority": cprio, "collection_name": cname,
                "rule_type": rule_type, "rule_name": r.get("name", ""),
                "dest_tags": tags, "dest_fqdns": fqdns, "ports": ports, "protos": protos,
            })
    return entries


def _fw_rule_matches_category(entry, category):
    """Does this rule entry match the required-egress category on TCP/443?
    Returns (matches: bool, matched_on: 'tag'|'fqdn'|None)."""
    spec = _REQUIRED_EGRESS[category]
    if not _fw_port_matches(entry["ports"]) or not _fw_proto_matches(entry["protos"]):
        # app rules carry port inside protocols; if protos matched but no explicit
        # port (rare), fall through on port only when '*' tag present
        if not (_fw_proto_matches(entry["protos"]) and _fw_port_matches(entry["ports"] or {"*"})):
            return (False, None)
    tags = entry["dest_tags"]
    if "*" in tags or any(t in tags for t in spec.get("service_tags", ())):
        return (True, "tag")
    for fq in entry["dest_fqdns"]:
        if fq == "*" or any(fq.endswith(suf) for suf in spec.get("fqdn_suffixes", ())) or fq in spec.get("fqdns", ()):
            return (True, "fqdn")
    return (False, None)


def _fw_evaluate_category(entries, category, dns_proxy_enabled):
    """Walk rule entries in Azure precedence order and return the verdict for one
    required-egress category.

    Returns {decision, rule_name, collection_name, priority, rule_type, matched_on}.
    """
    ordered = sorted(
        entries,
        key=lambda e: (0 if e["rule_type"] == "network" else 1,
                       e["rcg_priority"], e["collection_priority"]),
    )
    for e in ordered:
        matches, matched_on = _fw_rule_matches_category(e, category)
        if not matches:
            continue
        base = {"rule_name": e["rule_name"], "collection_name": e["collection_name"],
                "priority": e["collection_priority"], "rule_type": e["rule_type"],
                "matched_on": matched_on}
        if e["action"] == "deny":
            return {**base, "decision": _FW_DENIED}
        # action allow — but an FQDN in a NETWORK rule needs DNS proxy to resolve
        if matched_on == "fqdn" and e["rule_type"] == "network" and not dns_proxy_enabled:
            return {**base, "decision": _FW_DNS_PROXY}
        return {**base, "decision": _FW_ALLOWED}
    return {"decision": _FW_NO_MATCH, "rule_name": "", "collection_name": "",
            "priority": None, "rule_type": "", "matched_on": None}


def _fw_dns_proxy_enabled(policy_props):
    """Azure Firewall Policy: properties.dnsSettings.enableProxy (bool)."""
    return bool(((policy_props or {}).get("dnsSettings") or {}).get("enableProxy"))


def _fw_evaluate(entries, dns_proxy_enabled, categories):
    """Verdict per category. Returns {category: verdict_dict}."""
    return {c: _fw_evaluate_category(entries, c, dns_proxy_enabled) for c in categories}


def _firewall_from_topology(topology, nva_ip):
    """If a Topology graph already resolved this NVA IP to an Azure Firewall (across
    any readable subscription), return (name, id, policy_id, rule_entries, dns_proxy);
    else None. rule_entries are the normalized, precedence-ordered rules built by
    topology._resolve_firewalls (so the verdict is rule-level, not allow-set)."""
    nodes = getattr(topology, "nodes", None) or {}
    for n in nodes.values():
        if n.get("kind") == "firewall" and (n.get("props") or {}).get("nva_ip") == nva_ip:
            p = n.get("props") or {}
            return (n.get("name", ""), n.get("id", ""), p.get("policy_id", ""),
                    p.get("rule_entries", []), bool(p.get("dns_proxy_enabled", True)))
    return None


def check_forced_tunnel_firewall_egress(arm_token, route_check, nhc, workspace_resource_id,
                                        topology=None, backend_pl_present=False,
                                        categories=None, evidence_note=""):
    """Resolve a forced-tunnel UDR's NVA to its Azure Firewall and check whether
    the firewall's allow-list covers the Databricks egress the bootstrap NHC needs.

    When a `topology` graph is provided (phase-0 discovery), the firewall is sourced
    from it — which resolves firewalls in PEERED HUB subscriptions, not just the
    workspace's own. Without a topology, falls back to the original single-subscription
    ARM lookup (behavior-preserving).

    `backend_pl_present`: when an Approved back-end Private Link (databricks_ui_api
    private endpoint) is present, the control plane (SCC relay + workspace REST) is
    carried by the PE, NOT this firewall — so control-plane egress is NOT a firewall
    requirement and must be dropped from `need`. Demanding it anyway produces a
    CRITICAL false positive on a correctly-configured SRA workspace (confirmed against
    a live SRA baseline and with a network SME).

    `categories`: explicit `_REQUIRED_EGRESS` keys to demand, bypassing the NHC-signal
    inference entirely. Non-NHC callers (the CLASSIC CONNECTIVITY path, which has a
    target host instead of a bootstrap failure) MUST pass this — the signal fallback
    "no host signal, so bootstrap needs both" is a bootstrap assumption and demanding
    control-plane egress for an arbitrary connectivity target is how a healthy
    back-end-Private-Link workspace gets a CRITICAL false positive.
    `evidence_note`: replaces the "the bootstrap NHC failed reaching …" sentence in the
    verdict with the caller's own framing. Empty keeps the NHC wording (Path C).

    Returns FAIL (with the specific missing destinations) when the firewall is in
    the path but does NOT allow a destination the NHC failed on; PASS when the
    required egress is allowed; WARN when the NVA can't be resolved to an Azure
    Firewall (3rd-party appliance / unreadable subscription); SKIP when there's no
    forced tunnel (or no firewall egress requirement remains once back-end PL is
    accounted for).
    """
    start = _time.time()
    name = "Forced-Tunnel Firewall Egress"
    md = (route_check.metadata or {}) if route_check is not None else {}
    dr = md.get("default_route")
    if route_check is None or not dr or dr.get("next_hop_type") != "VirtualAppliance":
        return CheckResult(name, "(no forced tunnel)", Status.SKIP,
            "No 0.0.0.0/0 -> VirtualAppliance route; firewall egress analysis not applicable.",
            duration_ms=(_time.time() - start) * 1000)
    nva_ip = dr.get("next_hop_ip", "")
    target = f"NVA {nva_ip}"
    sig = ((nhc or {}).get("signals") or {}) if isinstance(nhc, dict) else {}
    failed_hosts = sig.get("failed_hosts", []) or []
    if categories is not None:
        # Caller stated exactly which egress categories are required for THIS question.
        need = {c for c in categories if c in _REQUIRED_EGRESS}
    else:
        need = set()
        if sig.get("storage_ssl_error") or any("blob.core.windows.net" in h for h in failed_hosts):
            need.add("storage")
        if (sig.get("databricks_com_failure") or sig.get("databricks_com_403")
                or any(("databricks.com" in h or "azuredatabricks.net" in h) for h in failed_hosts)):
            need.add("control_plane")
        if not need:
            # No specific NHC host signal — bootstrap always needs both anyway.
            need = {"storage", "control_plane"}
    # Back-end Private Link carries the control plane via the databricks_ui_api PE,
    # not the forced-tunnel firewall — so control-plane egress is not a firewall
    # requirement here. (Storage egress still traverses the firewall.)
    if backend_pl_present:
        need.discard("control_plane")
    need = sorted(need)
    if not need:
        why = ("back-end Private Link (databricks_ui_api private endpoint) carries control-plane "
               "egress, and no storage egress requirement was indicated"
               if backend_pl_present else
               "no Databricks-required egress category applies to this question")
        return CheckResult(name, target, Status.SKIP,
            f"Forced-tunnel firewall allow-list is not the gate here: {why}. "
            "No firewall allow-list gap applies.",
            metadata={"backend_pl_present": bool(backend_pl_present), "needed": [], "nva_ip": nva_ip},
            duration_ms=(_time.time() - start) * 1000)

    fw_name = fw_id = policy_id = ""
    entries = []
    dns_proxy = True            # default permissive — only the FQDN-in-network-rule case cares
    resolved = False

    # Topology-first (cross-subscription) resolution: if phase-0 discovery already
    # resolved this NVA to a firewall (possibly in a peered hub subscription), use
    # its rule model. Otherwise fall through to the single-subscription inline
    # lookup below (behavior-preserving — never preempts a readable firewall).
    if topology is not None:
        _t = _firewall_from_topology(topology, nva_ip)
        if _t is not None:
            fw_name, fw_id, policy_id, entries, dns_proxy = _t
            resolved = True

    # Live single-subscription lookup (no topology, or topology didn't resolve it).
    if not resolved:
        sub = _parse_resource_id(workspace_resource_id).get("subscription_id", "")
        if not sub:
            return CheckResult(name, target, Status.WARN,
                f"Forced tunnel to NVA {nva_ip}, but could not parse the subscription to locate the firewall. "
                f"Verify the appliance allows outbound 443 to: {_required_human(need)}.",
                duration_ms=(_time.time() - start) * 1000)
        fw_list = _arm_get(arm_token,
            f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Network/azureFirewalls?api-version=2023-09-01")
        if "_error" in fw_list:
            return CheckResult(name, target, Status.WARN,
                f"Forced tunnel to NVA {nva_ip}; could not list Azure Firewalls ({fw_list['_error']}). "
                f"If this NVA is a 3rd-party appliance, verify it allows: {_required_human(need)}.",
                duration_ms=(_time.time() - start) * 1000)
        fw = None
        for cand in fw_list.get("value", []):
            for ic in ((cand.get("properties") or {}).get("ipConfigurations") or []):
                if ((ic.get("properties") or {}).get("privateIPAddress")) == nva_ip:
                    fw = cand
                    break
            if fw:
                break
        if fw is None:
            return CheckResult(name, target, Status.WARN,
                f"The forced-tunnel next hop {nva_ip} is not an Azure Firewall in subscription {sub} "
                "(likely a 3rd-party NVA or a firewall in another subscription). Verify it allows outbound "
                f"443 to: {_required_human(need)}.",
                duration_ms=(_time.time() - start) * 1000)
        fw_name = fw.get("name", "")
        fw_id = fw.get("id", "")
        fwp = fw.get("properties", {}) or {}
        policy_id = (fwp.get("firewallPolicy") or {}).get("id", "")
        if policy_id:
            rcgs = _arm_get(arm_token,
                f"https://management.azure.com{policy_id}/ruleCollectionGroups?api-version=2023-09-01")
            if "_error" in rcgs:
                return CheckResult(name, f"{fw_name} ({nva_ip})", Status.WARN,
                    f"Firewall '{fw_name}' found at {nva_ip}, but could not read its policy rules "
                    f"({rcgs['_error']}). Verify it allows: {_required_human(need)}.",
                    duration_ms=(_time.time() - start) * 1000)
            for g in rcgs.get("value", []):
                gp = (g.get("properties") or {}).get("priority", 0) or 0
                entries.extend(_fw_normalize_rules((g.get("properties") or {}).get("ruleCollections") or [],
                                                   rcg_priority=gp))
            pol = _arm_get(arm_token, f"https://management.azure.com{policy_id}?api-version=2023-09-01")
            dns_proxy = _fw_dns_proxy_enabled(pol.get("properties")) if "_error" not in pol else True
        else:
            classic = []
            for key in ("networkRuleCollections", "applicationRuleCollections"):
                classic.extend(fwp.get(key) or [])
            entries = _fw_normalize_rules(classic, rcg_priority=0)
            dns_proxy = True        # classic legacy firewall — don't false-positive on DNS proxy

    # ---- Precedence-aware verdict per required category ----
    verdicts = _fw_evaluate(entries, dns_proxy, need)
    denied = [c for c in need if verdicts[c]["decision"] == _FW_DENIED]
    dns_blocked = [c for c in need if verdicts[c]["decision"] == _FW_DNS_PROXY]
    no_match = [c for c in need if verdicts[c]["decision"] == _FW_NO_MATCH]
    missing = denied + dns_blocked + no_match     # all three are reachability failures

    allow_entries = [e for e in entries if e["action"] == "allow"]
    tags = set().union(*[e["dest_tags"] for e in allow_entries]) if allow_entries else set()
    fqdns = set().union(*[e["dest_fqdns"] for e in allow_entries]) if allow_entries else set()
    allowed_summary = f"service-tags={sorted(tags) or '[]'} ; fqdns={sorted(fqdns) or '[]'}"
    policy_label = policy_id.split("/")[-1] if policy_id else "classic rules"
    meta = {
        "firewall_name": fw_name, "firewall_id": fw_id,
        "policy_id": policy_id, "nva_ip": nva_ip,
        "allowed_tags": sorted(tags), "allowed_fqdns": sorted(fqdns),
        "dns_proxy_enabled": dns_proxy,
        "verdicts": verdicts, "denied": denied, "dns_proxy_blocked": dns_blocked,
        "no_match": no_match, "missing": missing, "failed_hosts": failed_hosts, "needed": need,
    }

    if not missing:
        # A green "the firewall allows Storage" row sitting next to a blackhole on the
        # Storage prefix reads as "egress is fine" and pulls the customer away from the real
        # fault — the doctrine's "must_NOT covers the whole customer-visible report" point.
        # The allow-list IS correct, so this stays PASS; what changes is that the row says
        # plainly it is not proof the traffic arrives. Read from the route check's own
        # classification — no second implementation.
        _bh_preempt = [b for b in ((route_check.metadata or {}).get("blackholes") or [])
                       if b.get("verdict") in ("required", "unverified")
                       and not b.get("is_default_route")]
        _preempt_note = ""
        if _bh_preempt:
            _preempt_note = (
                " IMPORTANT: this does NOT mean the egress works. The subnet's route table also "
                "black-holes %s (next hop 'None'), and under longest-prefix match that route wins "
                "over the 0.0.0.0/0 route to this firewall — so the traffic is dropped in the "
                "routing table and never arrives here. Fix the route first; the allow-list needs "
                "no change." % ", ".join("'%s' (%s)" % (b.get("name"), b.get("prefix"))
                                         for b in _bh_preempt))
        # Only claim "the NHC failure" when an NHC failure was actually observed:
        # on a run whose signals were empty this asserted a failure nothing had seen.
        if evidence_note:
            _pass_tail = "The firewall allow-list is therefore NOT the gate for this destination."
        elif failed_hosts or sig.get("storage_ssl_error") or sig.get("databricks_com_failure"):
            _pass_tail = "The NHC failure is NOT a firewall allow-list gap."
        else:
            _pass_tail = ("The firewall allow-list is therefore NOT the gate for the required "
                          "Databricks egress.")
        return CheckResult(name, f"{fw_name} ({nva_ip})", Status.PASS,
            f"Firewall '{fw_name}' allows the required Databricks egress ({_required_human(need)}) — verified at "
            f"the RULE level (no higher-precedence Deny, DNS proxy {'on' if dns_proxy else 'n/a'}). "
            f"{_pass_tail} Allowed: {allowed_summary}." + _preempt_note,
            metadata=meta, duration_ms=(_time.time() - start) * 1000)

    # Build a per-category detail line and pick the most-specific failure framing.
    detail, rec = [], ""
    for c in missing:
        v = verdicts[c]
        if v["decision"] == _FW_DENIED:
            detail.append(f"{_REQUIRED_EGRESS[c]['label']} is BLOCKED by Deny rule "
                          f"'{v['rule_name']}' (collection '{v['collection_name']}', priority {v['priority']}, "
                          f"{v['rule_type']} rule) which wins over any Allow")
        elif v["decision"] == _FW_DNS_PROXY:
            detail.append(f"{_REQUIRED_EGRESS[c]['label']} is matched by an FQDN in a NETWORK rule "
                          f"('{v['rule_name']}') but DNS Proxy is DISABLED on the policy — the FQDN never "
                          "resolves, so the rule silently does not apply")
        else:
            detail.append(f"{_REQUIRED_EGRESS[c]['label']} has NO matching Allow rule (implicit deny)")

    if denied:
        v = verdicts[denied[0]]
        rec = (f"A Deny rule is the gate. On policy '{policy_label}', remove or re-scope Deny rule "
               f"'{v['rule_name']}' in collection '{v['collection_name']}' (priority {v['priority']}), OR add an "
               f"Allow rule for the Databricks egress at a HIGHER precedence (lower priority number, and in a "
               f"network rule collection since network rules are evaluated before application rules).")
    elif dns_blocked:
        rec = (f"Enable DNS Proxy on firewall policy '{policy_label}' "
               "(properties.dnsSettings.enableProxy = true) so the FQDN network rules resolve — OR move those "
               "FQDNs to an APPLICATION rule, OR switch the network rule to the 'Storage'/'AzureDatabricks' "
               "service tags (service-tag matches do not need DNS proxy).")
    else:
        rec = (
            f"On firewall policy '{policy_label}' add an ALLOW rule for the Databricks data-plane "
            "subnets covering the missing egress:\n"
            "  - NETWORK rule: destination service tag 'Storage.<region>' on TCP 443, and 'AzureDatabricks' "
            "on TCP 443 for the control plane.\n"
            "  - APPLICATION rule (if you prefer FQDN): '*.blob.core.windows.net', "
            "'*.azuredatabricks.net', '*.databricks.com', 'www.databricks.com' on 443.\n"
            "CLI sketch:\n"
            f"  az network firewall policy rule-collection-group collection add-filter-collection \\\n"
            f"    --policy-name {policy_label} -g <hub-rg> --rule-collection-group-name <rcg> \\\n"
            "    --name databricks-storage --collection-priority 200 --action Allow --rule-type NetworkRule \\\n"
            "    --rule-name adb-storage --source-addresses <adb-subnet-cidrs> \\\n"
            "    --destination-addresses 'Storage.<region>' 'AzureDatabricks' --destination-ports 443 --ip-protocols TCP"
        )

    # NEVER narrate an observation that was not made. `failed_hosts` is empty
    # whenever the customer described the symptom in prose instead of pasting an NHC
    # block (is_nhc can be set by a phrase match alone), and the old
    # `or 'the artifact storage'` fallback then stated as OBSERVED FACT — "the bootstrap
    # NHC failed reaching the artifact storage" — something nothing had observed. It
    # merely happened to sound right. When there is no observation, state the
    # REQUIREMENT instead; the two read very differently to a customer.
    if evidence_note:
        _evidence = evidence_note
    elif failed_hosts:
        _evidence = (f"The bootstrap NHC failed reaching {', '.join(failed_hosts[:4])} (the UDR "
                     "forces these flows here regardless of NSG).")
    else:
        _evidence = ("No per-host NHC failure list was available, so this is not attributed to an "
                     "observed host failure: nodes at bootstrap normally require this egress, and "
                     "the UDR forces those flows here regardless of NSG.")
    return CheckResult(name, f"{fw_name} ({nva_ip})", Status.FAIL,
        f"Firewall '{fw_name}' (policy '{policy_label}') is in the forced-tunnel path and does NOT permit "
        f"required Databricks egress — " + "; ".join(detail) + ". "
        f"{_evidence} Firewall currently allows: {allowed_summary}.",
        recommendation=rec, metadata=meta,
        duration_ms=(_time.time() - start) * 1000)
