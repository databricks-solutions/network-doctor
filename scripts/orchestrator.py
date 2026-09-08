"""DAG-based diagnostic orchestrator for the Network Connectivity Doctor.

Encodes check dependencies, runs checks in the correct order, skips
irrelevant checks, and delegates to the correlation engine for diagnosis.

Importable module: sibling scripts resolve via sys.path (the skill dir is
inserted by SKILL.md Step 1). Also works exec-loaded for back-compat.
"""

import json
import time

from models import (
    CheckResult, DiagnosticReport, Status, classic_plane_skip, derive_overall_status,
    merge_gate_skips, not_applicable, not_needed, plane_bucket_gaps,
    probes_measured_data_plane_vnet, skip_kind,
    SKIP_KIND_META, SKIP_UNVERIFIED,
    status_value, unverified,
)
from classic_probers import (
    check_dns, check_latency, check_local_dns_override, check_ping, check_tcp, check_tls,
    check_traceroute,
)
from serverless_ncc_checks import (
    ACCOUNT_UNREADABLE_META, account_dump_meta, account_unreadable_row,
    check_egress_policy, check_ncc_attached, check_ncc_pe_rules,
    get_account_data_cache, infer_resource_type, is_databricks_firstparty_host,
    run_on_cluster, set_account_data_cache,
)
from cluster_start_checks import (
    check_backend_private_link, check_dns_resolution_for_workspace,
    check_forced_tunnel_firewall_egress, check_outbound_to_databricks_com,
    check_subnet_delegation, check_subnet_egress_ip,
    check_subnet_required_nsg_rules, check_subnet_route_table,
    check_workspace_private_link,
    get_workspace_network_config, parse_nhc_error, probe_arm_reachability,
)
from correlation_engine import correlate, generate_summary
from report_builder import check_from_dict, check_to_dict, _default_report_dir
from azure_infra_checks import (
    AzureInfraChecker, auto_discover_azure_context, cross_check_dns_pe_alignment,
)
from secret_utils import load_azure_sp_from_secrets
from serverless_ncc_checks import _get_dbutils
from storage_access_checks import get_arm_token, get_databricks_account_token

# ---------------------------------------------------------------------------
# Check execution order (topological)
# ---------------------------------------------------------------------------

_EXEC_ORDER = [
    # `dns_local_override` is a DERIVED observation off the DNS row: when the node's local
    # resolver disagrees with DNS (routine on a Databricks node, which proxies workspace
    # traffic through itself), that override is a fact in its own right and must not be
    # laundered into "the resolved IP" — an earlier defect.
    "dns", "dns_local_override", "ping", "tcp", "traceroute", "tls", "latency",
    # `routes` answers "is there a UDR for the TARGET"; `subnet_egress` +
    # `subnet_egress_firewall` answer "where does internet-bound traffic from the
    # data-plane subnet go, and does that appliance allow what Databricks needs".
    # They are DIFFERENT questions and the second one is a property of the subnet, not
    # of the destination — collapsing them into the target-IP route lookup left the
    # forced-tunnel path untraced on back-end-Private-Link workspaces.
    "nsg", "routes", "subnet_egress", "subnet_egress_firewall",
    "peering", "pe", "dns_zones", "dns_pe_alignment",
    "ncc_attach", "ncc_pe", "egress_policy",
]

# Every key above must declare its network plane in models (CLASSIC_PLANE_CHECKS /
# SERVERLESS_PLANE_CHECKS / PLANE_NEUTRAL_CHECKS). A key in none of them would be a
# check that "runs everywhere" by omission — which is exactly how `dns_pe_alignment`
# came to conclude about the customer's VNet DNS from a serverless session. Say so at
# import time rather than leaving it for a reviewer to notice.
_PLANE_GAPS = plane_bucket_gaps(_EXEC_ORDER)
if _PLANE_GAPS["unbucketed"] or _PLANE_GAPS["multiple"]:
    print("[Doctor] INTERNAL: check(s) do not declare exactly one network plane "
          f"(unbucketed: {_PLANE_GAPS['unbucketed']}; in several: {_PLANE_GAPS['multiple']}). "
          "Add them to a bucket in models.py — an unbucketed check can conclude about the "
          "customer VNet from a serverless session.")


# ---------------------------------------------------------------------------
# Gate logic (exec()-safe, no lambdas)
# ---------------------------------------------------------------------------

def _ncc_skip_reason(context, default):
    """Skip reason for an NCC check when ncc_config is absent.

    Distinguishes "NCC inspection was REQUESTED (account_id given) but could not
    run" from "NCC was never requested". The former MUST surface as an honest
    finding — otherwise the diagnosis silently omits the NCC verdict the customer
    asked for and the skip reason lies ("account_id needed") when the id WAS given
    on a run where the id WAS supplied.
    """
    err = context.get("ncc_inspection_error")
    if err:
        return unverified(f"NCC inspection REQUESTED but could not be performed: {err}")
    if get_account_data_cache() is not None:
        return unverified(
            f"{default} An account snapshot IS loaded, but it does not contain the read this "
            "check needs — re-take the snapshot for THIS workspace and load it again.")
    # Always `unverified`: on a serverless problem the NCC IS the governing layer, so
    # not inspecting it is a real gap in the diagnosis, never a not-applicable answer.
    return unverified(default)


# Why is there no AzureInfraChecker? There are FIVE distinct causes and they were
# all reported with the same fixed string, "No Azure SP secret references provided".
# In the field that string was printed for `pe` and `dns_pe_alignment` on a run
# where the scope WAS provided and the SP authenticated successfully in the same
# cell — the customer was told to supply something they had already supplied, and
# the real cause (this runtime cannot reach management.azure.com) went unnamed.
#
# The infra phase now records which cause actually happened
# (`context["azure_infra_error"]`), and every azure_checker gate asks here instead of
# asserting. Same shape, and same reason for existing, as `_ncc_skip_reason` above.
_NO_SP_SKIP = "No Azure SP secret references provided"

# The other reason the ARM layer can be absent, and the only one that is a DECISION
# rather than a gap: nothing about this run has an Azure resource to read. Kept next to
# `_NO_SP_SKIP` so the two reasons stay visibly distinct — never tell a customer they
# withheld a credential when the credential would have answered nothing.
_ARM_NOT_CONSULTED = (
    "serverless egress to a public destination is governed by the workspace's serverless "
    "network policy (its egress allow-list), and no Azure resource backs this target — "
    "an Azure Reader SP would add nothing here")


def _azure_skip_reason(context, default=_NO_SP_SKIP):
    """Skip reason for an ARM check when `azure_checker` is absent.

    Distinguishes "no SP was given" (the default, and the only case in which asking
    for credentials is the right ask) from "the SP WAS given and something else
    stopped the ARM read" — an unreadable secret scope, an unreachable ARM
    endpoint, a discovery miss, or a build error. Never claim the customer withheld
    something they provided.
    """
    err = (context or {}).get("azure_infra_error")
    if err:
        return unverified(str(err))
    # Always `unverified`: the layer applies and the ARM read is what failed.
    return unverified(default)


# The NCC is a PRIVATE-ENDPOINT mechanism: an NCC private-endpoint rule names an Azure
# resource id and a group id. So the NCC layer answers questions about reaching an AZURE
# RESOURCE privately — it does not govern whether serverless may reach a public host.
# THAT is the network policy's egress allow-list (`egress_policy`).
#
# Running the NCC rows against a public FQDN was actively misleading, not merely noisy:
# in the field a `%pip install` case against pypi.org reported "NCC found:
# e8cc0212-..." as a PASS row, inviting the reader to think the NCC was the relevant
# layer, while the real blocker was the network policy's allow-list. The customer's own
# reading of that report was "there is nothing NCC-related in this case" — and they were
# right. Gate the rows off by DESTINATION, not just by compute plane.
#
# Absent flag => True, so every existing caller keeps its behaviour and only a caller that
# has actually classified the target can switch these off.
_NCC_PUBLIC_TARGET_SKIP = (
    "NCC private-endpoint layer — an NCC rule names an Azure resource, and this target is "
    "an ordinary public destination. Whether serverless may reach it is governed by the "
    "network policy's egress allow-list (see the Egress Network Policy check), not by the NCC")


def _ncc_public_target_skip(context):
    """(should_skip, SkipReason) for an NCC row whose target is not an Azure resource."""
    if (context or {}).get("target_is_azure_resource", True):
        return False, ""
    return True, not_applicable(_NCC_PUBLIC_TARGET_SKIP)


def _ncc_attachment_unknown(ncc_check):
    """Did the NCC attachment lookup fail to ESTABLISH anything?

    Structural first: `check_ncc_attached` declares `metadata["readable"] = False`
    when the account API did not answer. Status is only the fallback (for rows
    restored from a checkpoint written by an older build): ERROR is "I could not
    read it", FAIL is "I read it and there is none".

    D1 — "skip" joins the status fallback. The unreadable row is now a SKIP/unverified
    gap rather than an ERROR (an expected permission boundary is not an error and must
    not drive the WARNINGS banner), so a checkpoint written by THIS build and read back
    by a build whose `readable` handling regressed must still resolve to UNKNOWN. Both
    spellings mean the same thing here, and the pessimistic reading is the safe one.
    """
    md = getattr(ncc_check, "metadata", None) or {}
    if "readable" in md:
        return not md["readable"]
    return status_value(ncc_check) in ("error", "skip")


def _account_read_cause(check):
    """One short clause naming WHY an account read did not answer.

    The row itself carries the structured cause (`ACCOUNT_UNREADABLE_META`), so a
    dependent gate can state it in a few words instead of re-quoting the parent row's
    entire message — which is what turned the limits block into a nested restatement.
    """
    md = (getattr(check, "metadata", None) or {}).get(ACCOUNT_UNREADABLE_META) or {}
    kind, status = md.get("kind", ""), md.get("status", 0)
    label = {
        "unauthorized": "HTTP 403, this principal is not a Databricks account admin",
        "credentials": "HTTP 401, the token was rejected",
        "unreachable": "accounts.azuredatabricks.net was not reachable from this runtime",
        "cache_miss": "the loaded account snapshot does not contain this read",
    }.get(kind, "")
    if label:
        return label
    if status:
        return f"HTTP {status}"
    return "no usable response"


def _dns_usable(dns_check):
    """Did the DNS check produce an address we can analyse?

    Deliberately NOT `status == PASS`: since an earlier fix the DNS row is WARN when the node's local
    resolver disagrees with DNS (the DNS answer is then the authoritative one and is the
    RIGHT target for infra analysis) and when DNS could not be confirmed at all. Both
    still yield a usable address; only an outright resolution failure does not.
    """
    if dns_check is None:
        return False
    if dns_check.status in (Status.FAIL, Status.ERROR, Status.SKIP):
        return False
    return bool((dns_check.metadata or {}).get("ips"))


def _should_run(check_name, completed, context):
    """Decide whether a check should execute.

    Returns:
        (should_run: bool, skip_reason: str)
    """
    compute_type = context.get("compute_type", "classic")
    azure_checker = context.get("azure_checker")
    ncc_config = context.get("ncc_config")

    # Probes (dns/ping/...) execute in THIS session's process. For a SERVERLESS
    # problem that is exactly the right network plane — in-session probes ARE the
    # serverless measurement (field-confirmed: socket/ssl connects work from the
    # serverless session; the old "needs a classic cluster" skip was a mislabel
    # that produced vacuous probe phases, observed in the field). For a CLASSIC
    # problem driven from a serverless session, in-session results are the wrong
    # plane — that path uses run_on_cluster() per SKILL.md 4d, not these gates.
    if check_name == "dns":
        return True, ""

    if check_name == "ping":
        # ICMP needs a resolved address exactly like the other probes: `ping <host>` asks
        # the OS resolver first. With DNS failing, the ping fails for a NAME reason and
        # then reports "100% loss -- ICMP may be blocked by policy", which mis-attributes
        # the cause to ICMP policy. In the field that row rode a pypi.org report as its
        # ONLY warning while tcp/tls/latency correctly skipped on the same missing address.
        dns = completed.get("dns")
        if dns is None:
            return False, unverified("DNS check did not run")
        if not _dns_usable(dns):
            return False, unverified("DNS resolution failed — no address to ping")
        return True, ""

    if check_name == "dns_local_override":
        if completed.get("dns") is None:
            return False, unverified("DNS check did not run")
        return True, ""

    if check_name == "tcp":
        dns = completed.get("dns")
        if dns is None:
            return False, unverified("DNS check did not run")
        # WARN is a SUCCESSFUL resolution that disagreed with the local resolver or
        # could not be confirmed — an address exists, so the probe must still run. Gating
        # on PASS would have silently dropped TCP/NSG/routes the moment the DNS check
        # started reporting that disagreement honestly.
        if not _dns_usable(dns):
            return False, unverified("DNS resolution failed — no IP to connect to")
        return True, ""

    if check_name == "traceroute":
        tcp = completed.get("tcp")
        if tcp is None:
            return False, unverified("TCP check did not run")
        if not tcp.is_failure():
            # A determinate answer, not a gap: the hop-by-hop path only matters when the
            # connection does not come up, and it did.
            return False, not_needed("TCP succeeded — traceroute not needed")
        return True, ""

    if check_name == "tls":
        tcp = completed.get("tcp")
        if tcp is None or tcp.is_failure():
            return False, unverified("TCP failed — cannot perform TLS handshake")
        return True, ""

    if check_name == "latency":
        tcp = completed.get("tcp")
        if tcp is None or tcp.is_failure():
            return False, unverified("TCP failed — cannot measure latency")
        return True, ""

    # Workspace-VNet checks are CLASSIC-plane: serverless compute runs in
    # Databricks-managed infrastructure outside the customer VNet — it does not
    # use the VNet's DNS, NSGs, routes, or peerings. For a serverless-only
    # problem these checks produce wrong-layer diagnoses (field feedback);
    # serverless egress is governed by the NCC. `pe` still runs:
    # the TARGET's private-link posture informs the NCC-layer conclusion.
    #
    # The predicate and the reason text live in models (`classic_plane_skip`), so
    # this gate list is the ONLY place they are applied and there is no second
    # notion of plane to drift from. Do not re-inline `compute_type ==
    # "serverless"` here: that copy is what `dns_pe_alignment` was able to skip.
    def _classic_plane(name):
        return classic_plane_skip(name, context)

    if check_name == "nsg":
        _skip, _why = _classic_plane(check_name)
        if _skip:
            return False, _why
        if azure_checker is None:
            return False, _azure_skip_reason(context)
        dns = completed.get("dns")
        if not _dns_usable(dns):
            return False, unverified("DNS failed — no resolved IP for NSG check")
        return True, ""

    if check_name == "routes":
        _skip, _why = _classic_plane(check_name)
        if _skip:
            return False, _why
        if azure_checker is None:
            return False, _azure_skip_reason(context)
        dns = completed.get("dns")
        if not _dns_usable(dns):
            return False, unverified("DNS failed — no resolved IP for route check")
        return True, ""

    # The subnet's internet-bound egress path does NOT depend on the target resolving:
    # a DNS failure is no reason to leave the forced-tunnel path untraced, and the
    # answer is the same whatever the target is. So, unlike `routes`, this has no DNS
    # gate. Serverless still skips it — serverless egress is the account NCC, not this
    # VNet.
    if check_name == "subnet_egress":
        _skip, _why = _classic_plane(check_name)
        if _skip:
            return False, _why
        if azure_checker is None:
            return False, _azure_skip_reason(context)
        return True, ""

    if check_name == "subnet_egress_firewall":
        _skip, _why = _classic_plane(check_name)
        if _skip:
            return False, _why
        if azure_checker is None:
            return False, _azure_skip_reason(context)
        se = completed.get("subnet_egress")
        if se is None:
            return False, unverified("Subnet egress route check did not run")
        _dr = (se.metadata or {}).get("default_route") or {}
        if _dr.get("next_hop_type") != "VirtualAppliance":
            # Determinate: the route table was READ and there is no appliance in the
            # path, so there is no allow-list to inspect. Nothing is unverified here.
            return False, not_applicable(
                "No 0.0.0.0/0 -> VirtualAppliance route on the data-plane subnet — "
                "no appliance allow-list is in the egress path")
        return True, ""

    if check_name == "peering":
        _skip, _why = _classic_plane(check_name)
        if _skip:
            return False, _why
        if azure_checker is None:
            return False, _azure_skip_reason(context)
        return True, ""

    if check_name == "pe":
        if azure_checker is None:
            return False, _azure_skip_reason(context)
        return True, ""

    if check_name == "dns_zones":
        _skip, _why = _classic_plane(check_name)
        if _skip:
            return False, _why
        if azure_checker is None:
            return False, _azure_skip_reason(context)
        return True, ""

    # Cross-check, not a probe: compares the DNS-authoritative address against the PE
    # IPs — which makes it a statement about the CUSTOMER VNET, so it is classic-plane
    # like its six siblings above and asks the same gate.
    #
    # It used to opt out here, on the reasoning that "a serverless target served by a PE
    # has the same misalignment failure mode". That is true of the TARGET and false of
    # the RESOLVER, and the resolver is what this check measures: in the field on a
    # HEALTHY workspace it compared the serverless runtime's own internal resolver
    # address against the workspace's PE IPs, declared the customer's A record stale,
    # and its recommendation told them to rewrite a healthy privatelink zone. The
    # consuming rule (`_rule_dns_pe_misalignment`) was already plane-guarded, so no
    # diagnosis fired — the whole harm travelled through the check ROW and its
    # recommendation, which the chat renders for every failed row and the dashboard
    # reprints under "Quick Fix Checklist". Guard the producer, not just the consumer.
    if check_name == "dns_pe_alignment":
        # NOT `_classic_plane`: this cross-check consumes the PROBE's resolved address and
        # compares it with private endpoints inside the customer VNet, so what it needs is
        # the MEASURED plane — did the probe run in that VNet — not the declared one. Live
        # In the field the declared gate let it compare a serverless resolver's answer against
        # the workspace's PE IPs and call a correct A record stale, ranked above the real
        # cause. `probes_measured_data_plane_vnet` carries the full account.
        _ok, _why = probes_measured_data_plane_vnet(context)
        if not _ok:
            return False, unverified(_why)
        if azure_checker is None:
            return False, _azure_skip_reason(context)
        if not _dns_usable(completed.get("dns")):
            return False, "DNS produced no address to compare against the PE IPs"
        if completed.get("pe") is None:
            return False, "Private Endpoint check did not run"
        return True, ""

    if check_name == "ncc_attach":
        if compute_type != "serverless":
            return False, not_applicable("Not testing serverless compute")
        _skip, _why = _ncc_public_target_skip(context)
        if _skip:
            return False, _why
        if ncc_config is None:
            return False, _ncc_skip_reason(context, "No NCC configuration provided (account_id needed)")
        return True, ""

    if check_name == "ncc_pe":
        if compute_type != "serverless":
            return False, not_applicable("Not testing serverless compute")
        _skip, _why = _ncc_public_target_skip(context)
        if _skip:
            return False, _why
        if ncc_config is None:
            return False, _ncc_skip_reason(context, "No NCC configuration provided")
        # the NCC wiring defect, second half. This gate used to collapse `is_failure()` into
        # "NCC not attached — cannot check PE rules". In the field the attachment
        # lookup returned HTTP 403, so the ONLY call that could establish attachment
        # never answered — and the skip reason asserted, as fact, the very thing that
        # was unknown. It was also FALSE: an NCC was attached, with 10 established
        # private-endpoint rules. UNREADABLE and ABSENT are different facts and only
        # one of them was ever established, so they get different sentences.
        ncc = completed.get("ncc_attach")
        if ncc is None:
            return False, _ncc_skip_reason(
                context,
                "the NCC attachment check did not run, so whether an NCC is attached is "
                "UNKNOWN — its private-endpoint rules were not read. This is NOT a "
                "finding that no NCC is attached.")
        if _ncc_attachment_unknown(ncc):
            # D2 — the prescription used to end "fix the account-API access (the SP must
            # be an ACCOUNT ADMIN) and re-run", which is correct and, for an enterprise
            # that will not delegate account admin to a non-human identity, a dead end.
            # In the graded run that one sentence WAS the whole deliverable. The hand-off
            # is primary now and the escalation is the fallback; the full prescription
            # (with the read-only script) rides the `account_layer` row, which is where a
            # recommendation is actually rendered — the limits block, where this skip
            # reason lands, prints a row's MESSAGE only.
            # Do NOT inline the parent row's whole message here. It is ~70 words that the
            # limits block already prints one bullet above, so quoting it in full made
            # the second bullet a nested restatement of the first and buried its own
            # point. Name the cause; the detail has a home.
            return False, _ncc_skip_reason(
                context,
                f"the NCC attachment could not be READ ({_account_read_cause(ncc)}), so which "
                "private-endpoint rules the NCC carries is UNKNOWN — not a finding that none "
                "exists. Settled by the same read-only hand-off as the row above; no new "
                "permission needed.")
        if ncc.is_failure():
            # Determinate: the account API ANSWERED. There are no rules to read because
            # there is no NCC, and that fact is already carried by the ncc_attach row —
            # so this is an answer, not an unverified layer.
            return False, not_applicable(
                "no NCC is attached to this workspace (the account API answered "
                "and reported none), so there are no private-endpoint rules to "
                "check — attach an NCC first")
        return True, ""

    if check_name == "egress_policy":
        if compute_type != "serverless":
            return False, not_applicable("Not testing serverless compute")
        if ncc_config is None:
            return False, _ncc_skip_reason(context, "No account credentials provided (account_id + token needed)")
        host = context.get("host", "")
        if is_databricks_firstparty_host(host):
            return False, not_applicable("Target is a Databricks first-party host")
        dns = completed.get("dns")
        tcp = completed.get("tcp")
        relevant_failed = (
            (dns is not None and dns.is_failure()) or
            (tcp is not None and tcp.is_failure())
        )
        if not relevant_failed:
            return False, not_needed("DNS/TCP succeeded — egress policy not implicated")
        return True, ""

    return False, unverified(f"Unknown check: {check_name}")


# ---------------------------------------------------------------------------
# Where the probes RUN
# ---------------------------------------------------------------------------
# A probe measures the network of whatever machine executes it. That makes the
# execution location part of the evidence, not an implementation detail: when the
# customer says the failure is on CLASSIC compute, a DNS or TCP result taken in this
# serverless notebook describes a different network — different VNet, different DNS,
# different egress — and presenting it as evidence about the classic path is simply
# wrong.
#
# So a classic problem sends its probes to the customer's classic cluster over the
# Command Execution API. The intake already collects that cluster (and provisions one
# when the customer answers `create`), and until this existed the answer was collected
# and then DISCARDED: `context["cluster_id"]` had no consumer anywhere, the probes ran
# locally regardless, and the report then said it "cannot establish that the in-session
# probes ran INSIDE the customer VNet" — true, but only because the one thing the
# customer had supplied to make it establishable was thrown away. A customer who
# answered `create` paid for a cluster that measured nothing.
#
# One remote call runs the whole probe suite, because each one costs a round trip. The
# same call reports whether the instance-metadata endpoint answers THERE, which is what
# makes `probe_runtime` an honest measurement of the plane the probes ran on rather than
# a guess about this notebook (models.probes_measured_data_plane_vnet).
_PROBE_CHECKS = ("dns", "dns_local_override", "ping", "tcp", "traceroute", "tls", "latency")
_REMOTE_PROBE_CACHE = "_remote_probe_results"
_REMOTE_PROBE_FAILED = "_remote_probe_error"


def _remote_probe_code(host, port, compute_type, private_link_capable):
    """The snippet executed ON the customer's cluster. Returns JSON on stdout.

    It resolves the skill's script directory ON THE CLUSTER, the same way the Step 1
    loader does, rather than being handed a path: this session cannot name the workspace
    user (get_workspace_context does not return one), and a wrong path here fails the
    import silently on the far side.
    """
    return (
        "import json, sys\n"
        "_u = spark.sql('SELECT current_user()').collect()[0][0]\n"
        "sys.path.insert(0, '/Workspace/Users/' + _u + "
        "'/.assistant/skills/network-doctor/scripts')\n"
        "from classic_probers import (check_dns, check_tcp, check_tls, check_ping,\n"
        "                            check_traceroute, check_latency,\n"
        "                            check_local_dns_override)\n"
        # NOT models.results_to_dict: it drops `metadata`, and the metadata is what the
        # downstream gates and infra checks read. Losing `dns.metadata["ips"]` silently
        # skipped tcp/tls/ping/traceroute/latency with "DNS resolution failed" on a run
        # whose DNS had just PASSED, and would have taken nsg/routes with it (both index
        # dns.metadata["ips"][0]). Serialize explicitly instead.
        "def _nd_ser(c):\n"
        "    _st = getattr(c.status, 'value', c.status)\n"
        "    return {'check_name': c.check_name, 'target': c.target, 'status': _st,\n"
        "            'message': c.message, 'recommendation': c.recommendation,\n"
        "            'raw_output': c.raw_output, 'duration_ms': c.duration_ms,\n"
        "            'metadata': dict(c.metadata or {})}\n"
        "_imds = False\n"
        "try:\n"
        "    import requests as _r\n"
        "    _r.get('http://169.254.169.254/metadata/instance?api-version=2021-02-01',\n"
        "           headers={'Metadata': 'true'}, timeout=2)\n"
        "    _imds = True\n"
        "except Exception:\n"
        "    _imds = False\n"
        "_out = {}\n"
        f"_host, _port = {host!r}, {int(port)}\n"
        "try:\n"
        f"    _dns = check_dns(_host, compute_type={compute_type!r},\n"
        f"                     private_link_capable={bool(private_link_capable)})\n"
        "    _out['dns'] = _dns\n"
        "    _out['dns_local_override'] = check_local_dns_override(_dns)\n"
        "except Exception as _e:\n"
        "    _out['_dns_error'] = str(_e)\n"
        "for _name, _fn in ((\'tcp\', lambda: check_tcp(_host, _port)),\n"
        "                   (\'tls\', lambda: check_tls(_host, _port)),\n"
        "                   (\'ping\', lambda: check_ping(_host, compute_type=\'classic\')),\n"
        "                   (\'traceroute\', lambda: check_traceroute(_host)),\n"
        "                   (\'latency\', lambda: check_latency(_host, _port, samples=10))):\n"
        "    try:\n"
        "        _out[_name] = _fn()\n"
        "    except Exception as _e:\n"
        "        _out['_' + _name + '_error'] = str(_e)\n"
        "_ser = {k: _nd_ser(v) for k, v in _out.items() if not k.startswith('_')}\n"
        "_errs = {k: v for k, v in _out.items() if k.startswith('_')}\n"
        "print('ND_REMOTE_PROBES_JSON' + json.dumps("
        "{'imds': _imds, 'results': _ser, 'errors': _errs}))\n")


def _revive_check(payload, cluster_id, imds=False):
    """Rebuild a CheckResult from the remote JSON, marked with where it ran."""
    meta = dict(payload.get("metadata") or {})
    meta["execution_location"] = "remote_classic_cluster"
    meta["execution_cluster_id"] = cluster_id
    # Stamped on the ROW, not just the context, because the context is rebuilt from the
    # session on every turn and the phases run on separate turns: a measurement recorded
    # only in memory was gone by the time the infra phase asked whether the probes had run
    # in the VNet, so the report still called the plane unproven right after proving it.
    if imds:
        meta["probe_plane_confirmed"] = True
    try:
        status = Status(str(payload.get("status", "error")).lower())
    except ValueError:
        status = Status.ERROR
    return CheckResult(
        check_name=payload.get("check_name", "") or "",
        target=payload.get("target", "") or "",
        status=status,
        message=payload.get("message", "") or "",
        recommendation=payload.get("recommendation", "") or "",
        raw_output=payload.get("raw_output", "") or "",
        duration_ms=payload.get("duration_ms") or 0,
        metadata=meta)


def _remote_probes(context, host, port):
    """Run the probe suite on the customer's classic cluster. Cached per run.

    Returns a dict of check_name -> CheckResult, or {} when the remote run is not
    applicable or did not succeed. The two empty cases are NOT the same and the caller
    tells them apart by `_REMOTE_PROBE_FAILED`: no cluster in play means probe locally
    (that is the right plane for serverless), while a cluster that was supposed to run
    them and could not means record an unverified gap — never a local substitution
    presented as the customer's VNet.
    """
    if _REMOTE_PROBE_CACHE in context:
        return context[_REMOTE_PROBE_CACHE]
    plan = context.get("probe_on_cluster") or {}
    cluster_id = str(plan.get("cluster_id") or "").strip()
    if not (cluster_id and plan.get("workspace_url") and plan.get("token")):
        context[_REMOTE_PROBE_CACHE] = {}
        return {}
    rtype, _g, _n = infer_resource_type(host, port)
    code = _remote_probe_code(host, port, context.get("compute_type", "classic"),
                              rtype != "unknown")
    print(f"[Doctor] Running the network probes ON classic cluster {cluster_id} — a probe "
          "measures the network of the machine that runs it, and the problem is on the "
          "classic plane.")
    out = run_on_cluster(plan["workspace_url"], plan["token"], cluster_id, code)
    if out.get("status") == "ERROR" or "ND_REMOTE_PROBES_JSON" not in str(out.get("results") or ""):
        why = out.get("error") or "the cluster returned no probe payload"
        context[_REMOTE_PROBE_FAILED] = str(why)
        context[_REMOTE_PROBE_CACHE] = {}
        print(f"[Doctor] Could not run the probes on {cluster_id} ({why}). NOT falling back "
              "to this session: on a classic diagnosis that would measure a different "
              "network. The probe rows are recorded as unverified, naming the cluster and "
              "this reason. Most often the cluster is not RUNNING.")
        return {}
    raw = str(out["results"])
    payload = json.loads(raw[raw.index("ND_REMOTE_PROBES_JSON") + len("ND_REMOTE_PROBES_JSON"):].strip())
    if payload.get("imds"):
        # MEASURED where the probes ran, which is the whole point.
        context["probe_runtime"] = "classic"
    _imds = bool(payload.get("imds"))
    revived = {k: _revive_check(v, cluster_id, _imds)
               for k, v in (payload.get("results") or {}).items()}
    for _k, _err in (payload.get("errors") or {}).items():
        print(f"[Doctor] remote probe {_k}: {_err}")
    print(f"[Doctor] {len(revived)} probe(s) executed on {cluster_id}; "
          f"instance metadata answered there: {bool(payload.get('imds'))}.")
    context[_REMOTE_PROBE_CACHE] = revived
    return revived


# ---------------------------------------------------------------------------
# Check dispatcher
# ---------------------------------------------------------------------------

def _run_check(check_name, host, port, completed, context):
    """Execute a single check and return a CheckResult."""
    target = f"{host}:{port}"
    azure_checker = context.get("azure_checker")
    ncc_config = context.get("ncc_config")

    t0 = time.time()

    # A classic problem's probes belong on the classic cluster. Anything the remote run
    # could not produce falls through to the local branches below.
    if check_name in _PROBE_CHECKS and context.get("probe_on_cluster"):
        remote = _remote_probes(context, host, port)
        if check_name in remote:
            return remote[check_name]
        _why = str(context.get(_REMOTE_PROBE_FAILED) or "").strip()
        if _why:
            # A cluster id the customer supplied is a promise about WHICH network gets
            # measured. When the dispatch to it fails — most often because the cluster is
            # not actually RUNNING — re-running the probe here measures this session's
            # network and nothing marks the substitution: in the field that shipped a
            # root cause of "DNS Resolution Failed" whose only evidence came from the
            # serverless notebook (`execution_location=None`), on a classic diagnosis. A
            # named gap is worth more than a confident answer about the wrong machine.
            _cid = str((context.get("probe_on_cluster") or {}).get("cluster_id") or "")
            return CheckResult(
                check_name=check_name, target=target, status=Status.SKIP,
                message=("Not measured: this is a CLASSIC diagnosis, so the probe has to run "
                         f"on cluster {_cid} inside your VNet, and that did not work ({_why}). "
                         "Running it from this session instead would measure a different "
                         "network. Check the cluster is RUNNING and send the id again."),
                metadata={SKIP_KIND_META: SKIP_UNVERIFIED},
            )

    if check_name == "dns":
        resource_type, _group, _name = infer_resource_type(host, port)
        result = check_dns(
            host, compute_type=context.get("compute_type", "classic"),
            private_link_capable=resource_type != "unknown")
    elif check_name == "dns_local_override":
        result = check_local_dns_override(completed.get("dns"))
    elif check_name == "tcp":
        result = check_tcp(host, port)
    elif check_name == "tls":
        result = check_tls(host, port)
    elif check_name == "traceroute":
        result = check_traceroute(host)
    elif check_name == "latency":
        result = check_latency(host, port, samples=10)
    elif check_name == "ping":
        result = check_ping(host, compute_type=context.get("compute_type", "classic"))
    elif check_name == "nsg":
        dns = completed.get("dns")
        resolved_ip = dns.metadata.get("ips", [host])[0] if dns else host
        result = azure_checker.check_nsg(resolved_ip, port)
    elif check_name == "routes":
        dns = completed.get("dns")
        resolved_ip = dns.metadata.get("ips", [host])[0] if dns else host
        result = azure_checker.check_routes(resolved_ip, target_host=host)
    elif check_name == "subnet_egress":
        result = azure_checker.check_subnet_egress()
    elif check_name == "subnet_egress_firewall":
        dns = completed.get("dns")
        resolved_ip = dns.metadata.get("ips", [""])[0] if dns else ""
        result = azure_checker.check_subnet_egress_firewall(
            completed.get("subnet_egress"), target_host=host, target_ip=resolved_ip,
            # Reuse the phase-0 graph when discovery built one: it resolves a
            # forced-tunnel firewall living in a PEERED HUB SUBSCRIPTION, which the
            # single-subscription inline lookup cannot find.
            topology=context.get("_topology"))
    elif check_name == "peering":
        result = azure_checker.check_peering()
    elif check_name == "pe":
        result = azure_checker.check_private_endpoints(host)
    elif check_name == "dns_zones":
        result = azure_checker.check_dns_zones(host)
    elif check_name == "dns_pe_alignment":
        # cross_check_dns_pe_alignment returns a LIST (0..n findings); the dispatcher
        # slot holds one CheckResult, so collapse to the most severe and keep the rest in
        # metadata. Previously this function existed but was never called from anywhere —
        # dead code, which is why the private-but-wrong-address case had never fired.
        _xs = cross_check_dns_pe_alignment(completed.get("dns"), completed.get("pe"))
        if not _xs:
            result = CheckResult(
                check_name="DNS \u2192 Private Endpoint Alignment", target=target,
                status=Status.PASS,
                message=("The DNS-authoritative address for this target matches a Private Endpoint "
                         "IP (or no Private Endpoint applies), so name resolution and the private "
                         "path agree."))
        else:
            _rank = {Status.FAIL: 0, Status.ERROR: 0, Status.WARN: 1, Status.PASS: 2, Status.SKIP: 3}
            _xs = sorted(_xs, key=lambda c: _rank.get(c.status, 9))
            result = _xs[0]
            if len(_xs) > 1:
                result.metadata = dict(result.metadata or {},
                                       additional_findings=[c.message for c in _xs[1:]])
    elif check_name == "ncc_attach":
        ncc_id, result = check_ncc_attached(
            ncc_config["account_host"],
            ncc_config["account_id"],
            ncc_config["workspace_id"],
            ncc_config["token"],
        )
        # Store ncc_id in context for subsequent ncc_pe check
        if ncc_id:
            ncc_config["ncc_id"] = ncc_id
    elif check_name == "ncc_pe":
        ncc_id = ncc_config.get("ncc_id", "")
        result = check_ncc_pe_rules(
            ncc_config["account_host"],
            ncc_config["account_id"],
            ncc_id,
            ncc_config["token"],
            host,
            port,
        )
    elif check_name == "egress_policy":
        result = check_egress_policy(
            ncc_config["account_host"],
            ncc_config["account_id"],
            ncc_config["workspace_id"],
            ncc_config["token"],
            host,
            port,
            product=context.get("egress_product"),
        )
    else:
        result = CheckResult(
            check_name=check_name,
            target=target,
            status=Status.ERROR,
            message=f"Unknown check: {check_name}",
        )

    elapsed = (time.time() - t0) * 1000
    if result.duration_ms == 0.0:
        result.duration_ms = elapsed

    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def diagnose_target(host, port, context):
    """Run all applicable diagnostic checks for a single target.

    Args:
        host: Target hostname
        port: Target port
        context: dict with keys:
            - compute_type: "classic" | "serverless"
            - azure_checker: AzureInfraChecker instance or None
            - ncc_config: dict with account_host, account_id, workspace_id, token, or None
            - ws_ctx: workspace context dict
            - cluster_id: cluster ID for remote execution (optional)
            - rerun_failed_only: bool (default False)
            - previous_results: dict of check_name -> CheckResult (for rerun mode)

    Returns:
        DiagnosticReport
    """
    # PROGRAMMATIC GUARD — cluster-start/NHC/launch symptoms must run the FULL
    # cluster_start_checks suite via diagnose_cluster_start, never the generic
    # probe path here. Hand-running diagnose_target for a cluster-start problem
    # runs a DIFFERENT, smaller check set and can surface a different primary
    # cause, so the headline diagnosis flips between passes (seen in real deployments
    # ROUND #1: generic probe path led with the UDR blackhole, the full suite led
    # with missing NSG rules). Refuse deterministically rather than rely on agent
    # prose. Signals: an explicit cluster-start path/error text or a workspace
    # ARM resource id in the context.
    _cs_signal = (
        str(context.get("diagnostic_path", "")).lower() == "cluster_start"
        or bool(context.get("nhc_error_text"))
        or bool(context.get("workspace_resource_id"))
    )
    if _cs_signal and not context.get("allow_generic_for_cluster_start"):
        raise RuntimeError(
            "diagnose_target refused: this looks like a cluster-start / NHC / launch "
            "failure (Path C). Run the FULL cluster-start ARM suite instead so the "
            "primary diagnosis is deterministic — do NOT use the generic probe path:\n"
            "  report = diagnose_cluster_start(nhc_error_text, workspace_resource_id, arm_token=...)\n"
            "(run_network_doctor() routes Path C here automatically — prefer it.)"
        )

    # PROGRAMMATIC GUARD — long runs must use the chunked flow. A single-cell run
    # that includes Azure infra / NCC checks outlives a Genie execution turn and
    # dies with "Tool output was not persisted" (observed in the field);
    # prose rules about this proved invisible (observed in the field), so
    # the function itself refuses and tells the caller exactly what to do.
    is_long_run = bool(context.get("azure_checker") or context.get("ncc_config")
                       or context.get("azure_sp"))
    if (is_long_run and not context.get("rerun_failed_only")
            and not context.get("allow_long_single_call")):
        raise RuntimeError(
            "diagnose_target refused: this run includes Azure infra/NCC checks, which is "
            "too long for one execution turn. Use the chunked flow — one cell each:\n"
            "  ckpt = start_diagnosis(host, port, context)      # cell 1: probes\n"
            "  ckpt = continue_diagnosis(ckpt, context)         # cell 2: infra + NCC\n"
            "  report = finalize_diagnosis(ckpt, context)       # cell 3: correlate -> report\n"
            "(For re-verification pass rerun_failed_only=True; to force a single call "
            "anyway pass allow_long_single_call=True — not recommended on serverless.)"
        )

    completed = {}
    skipped = []
    context = dict(context)
    context["host"] = host
    context["port"] = port
    _run_check_list(_EXEC_ORDER, host, port, completed, skipped, context)
    return _assemble_report(host, port, completed, skipped, context)


def _run_check_list(check_names, host, port, completed, skipped, context, after_each=None):
    """Run a list of checks in order, honoring gates and rerun mode.

    Mutates `completed`/`skipped` in place. `after_each(check_name)` fires after
    every check lands in `completed` (the chunked path persists the checkpoint
    there, so a session reset loses at most the check in flight).
    """
    target = f"{host}:{port}"
    rerun_mode = context.get("rerun_failed_only", False)
    previous = context.get("previous_results", {})

    for check_name in check_names:
        # Re-verification mode: carry forward passing checks
        if rerun_mode and check_name in previous:
            prev = previous[check_name]
            # A SKIP is not a result — it is the absence of one. `previous_results` is
            # documented as `report.checks` from a prior run, and since gate skips are
            # materialised into that container (models.merge_gate_skips) a skip row would
            # otherwise be carried forward as "already fine" and its gate never
            # re-evaluated. Re-verifying after fixing the very thing that caused the skip
            # (an unreadable secret scope, an unreachable ARM) has to re-ask the gate.
            if status_value(prev) == "skip":
                pass
            elif not prev.is_failure():
                completed[check_name] = prev
                continue

        should, reason = _should_run(check_name, completed, context)
        if not should:
            # Third slot = the skip CLASS. `reason` is a models.SkipReason and already
            # carries it, but the checkpoint and the saved report JSON serialise it to a
            # bare string, which would silently downgrade every not-applicable skip to
            # "unverified" on resume. Recording it positionally is what survives.
            skipped.append((check_name, reason, skip_kind(reason)))
            continue

        try:
            result = _run_check(check_name, host, port, completed, context)
            completed[check_name] = result
        except Exception as e:
            completed[check_name] = CheckResult(
                check_name=check_name,
                target=target,
                status=Status.ERROR,
                message=f"Check raised exception: {str(e)}",
            )
        if after_each is not None:
            after_each(check_name)


def _assemble_report(host, port, completed, skipped, context):
    """Correlate completed checks and build the final DiagnosticReport."""
    # `correlate` sees ONLY the checks that ran: several rules key on a check being
    # ABSENT (no Azure check at all -> ask for an SP; the NCC was never inspected), and
    # a materialised SKIP row would make absence unrepresentable. Everything
    # customer-facing — counts, tiles, the limits block, the headline — reads `rows`.
    # The gate skips still travel as DATA, so the one rule that must NAME them
    # (_rule_all_healthy: "NOT tested, and therefore unverified: ...") can.
    context = dict(context or {})
    context["gate_skipped"] = list(skipped or [])
    diagnoses = correlate(completed, context)

    # ONE container for skips. `rows` = executed rows + one SKIP row per gate
    # skip, so no consumer can count 7 rows on a run that skipped 11 checks.
    rows = merge_gate_skips(completed, skipped)
    summary = generate_summary(diagnoses, rows)

    # the headline is derived from what was CONCLUDED (diagnosis severity),
    # not from "any row is red". A red row with only a `medium` latent finding on it
    # is not a failed workspace; a CRITICAL/HIGH diagnosis is, whatever the rows say.
    # Row-level truth is untouched — see models.derive_overall_status for the policy.
    overall = derive_overall_status(rows, diagnoses)

    return DiagnosticReport(
        target=f"{host}:{port}",
        host=host,
        port=port,
        checks=rows,
        diagnoses=diagnoses,
        skipped=skipped,
        overall_status=overall,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Chunked / resumable diagnostic (one phase per Genie execution turn)
# ---------------------------------------------------------------------------
# Long single-cell diagnose_target runs outlive a Genie Code execution turn and
# die with "Tool output was not persisted" (observed in the field), losing
# everything. The chunked path splits the run into phases — one notebook cell
# each — and persists a checkpoint JSON after EVERY check, so a session reset
# loses at most the check in flight and the next cell resumes from disk.

_PHASES = [
    ("probes", ["dns", "dns_local_override", "ping", "tcp", "traceroute", "tls", "latency"]),
    ("infra", ["nsg", "routes", "subnet_egress", "subnet_egress_firewall",
               "peering", "pe", "dns_zones", "dns_pe_alignment",
               "ncc_attach", "ncc_pe", "egress_policy"]),
]

_CHECKPOINT_SCHEMA = "network_doctor_checkpoint_v1"


class _CheckpointHandle(str):
    """Return type of start_diagnosis/continue_diagnosis: the value IS the
    checkpoint path (safe to pass anywhere a path string goes), and it also
    carries the phase state + the literal next call, so the flow cannot be
    misread. Field-observed: a bare path-string return was assumed
    to be an object (`ckpt.phase`) — the AttributeError derailed the whole run.
    """

    def __new__(cls, path, phases_done, next_call):
        obj = super().__new__(cls, path)
        obj._phases_done = list(phases_done)
        obj._next_call = next_call
        return obj

    @property
    def path(self):
        return str(self)

    @property
    def phases_done(self):
        return list(self._phases_done)

    @property
    def next_step(self):
        """The literal code to run in the NEXT notebook cell."""
        return self._next_call

    def __repr__(self):
        return (f"CheckpointHandle(path={str(self)!r}, phases_done={self._phases_done}, "
                f"next_step={self._next_call!r})")


def _checkpoint_path_for(host, port):
    import os
    import re
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{host}_{port}")
    return os.path.join(_default_report_dir(), f"{safe}.ckpt.json")


def _save_checkpoint(ckpt, path):
    import json
    import os
    from datetime import datetime, timezone
    ckpt["updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ckpt, f, indent=2)


def load_checkpoint(path):
    """Load a chunked-diagnosis checkpoint. Returns the raw dict."""
    import json
    with open(path, "r", encoding="utf-8") as f:
        ckpt = json.load(f)
    if ckpt.get("schema") != _CHECKPOINT_SCHEMA:
        raise ValueError(f"Not a network-doctor checkpoint: {path}")
    return ckpt


def reopen_checks(checkpoint_path, check_names, phase="infra"):
    """Discard the recorded outcomes for `check_names` so a later phase run re-executes them.

    `_run_phase` resumes by running only checks with no outcome yet (`pending = [n for n
    in check_names if n not in completed and n not in already_skipped]`). That is what
    makes a resumed run cheap — and it is also why a check that skipped for a reason the
    customer has since REMOVED would stay skipped forever. The serverless account-layer
    offer is exactly that case: the NCC / network-policy rows skip while no account
    credential exists, the customer is shown the probe verdict and then supplies one, and
    those three rows have to become runnable again.

    Clears the rows from both `checks` and `skipped`, and removes `phase` from
    `phases_done` so the phase is pending again. Returns the names actually cleared.
    """
    ckpt = load_checkpoint(checkpoint_path)
    names = {str(n) for n in (check_names or [])}
    cleared = {n for n in (ckpt.get("checks") or {}) if n in names}
    ckpt["checks"] = {n: c for n, c in (ckpt.get("checks") or {}).items() if n not in names}
    kept = []
    for entry in (ckpt.get("skipped") or []):
        if entry and str(entry[0]) in names:
            cleared.add(str(entry[0]))
        else:
            kept.append(entry)
    ckpt["skipped"] = kept
    if cleared and phase in (ckpt.get("phases_done") or []):
        ckpt["phases_done"] = [p for p in ckpt["phases_done"] if p != phase]
    _save_checkpoint(ckpt, checkpoint_path)
    return sorted(cleared)


# ---------------------------------------------------------------------------
# Why the ARM layer could not be read — and how the customer is guided back
# ---------------------------------------------------------------------------
# When the ARM layer cannot be read, this classifies WHY and records a durable
# CheckResult row for it: the row rides the checkpoint, lands in the report, is
# counted in the row totals, is named in "Limits of this diagnosis", and — being a
# WARN — stops the headline from reading as a clean PASS.
#
# The one cause that is about the NETWORK, "unreachable", does NOT fall back to an
# offline snapshot (there is no offline mode). The runtime cannot reach ARM, so the
# deliverable is the exact egress to enable — management.azure.com and
# login.microsoftonline.com — after which the customer re-runs and the Azure layer
# is read LIVE. A snapshot would be a point-in-time copy from another identity; the
# product reads the configuration as it is now or says plainly that it could not.

_ARM_BLIND_ROW = "arm_reachability"


def _arm_blindness_reason(sp, cause, detail="", discovery_log=None, arm_token=""):
    """Classify WHY there is no AzureInfraChecker. Returns (reason, kind, evidence).

    kind is one of:
      "secret_unreadable" — the SP refs were given but Databricks Secrets refused
      "credentials"       — the SP could not mint an ARM token (or ARM rejects it)
      "unreachable"       — no network path from this runtime to management.azure.com
      "permissions"       — ARM answers, but nothing containing this workspace is
                            visible to the SP (a missing Reader assignment)
      "error"             — the checker build itself raised
    Only "unreachable" is a network/egress problem (guide the customer to enable
    egress and re-run). "permissions" means telling them to grant the SP Reader —
    NOT to change the network — which is why `probe_arm_reachability` reports
    reachable-but-401/403 distinctly.
    """
    log = "; ".join(str(m) for m in (discovery_log or [])[:6])
    if cause == "secret_unreadable":
        return (("The Azure Service Principal WAS provided, but it could not be read from "
                 f"the Databricks secret scope ({detail}). Nothing about your Azure network "
                 "was read — verify the scope and key names and re-run."),
                "secret_unreadable", log)
    if cause == "build_error":
        return ((f"The Azure ARM client could not be built ({detail}), so the ARM layer was "
                 "not read at all. This is a Doctor-side failure, not a statement about your "
                 "configuration."), "error", log)

    probe = {}
    if arm_token:
        probe = probe_arm_reachability(arm_token) or {}
    if not arm_token:
        return ((f"An ARM access token could not be minted from the provided Service "
                 f"Principal ({detail or 'token request failed'}), so no Azure resource was "
                 "read. Either the credentials are wrong or this runtime cannot reach "
                 "login.microsoftonline.com."), "credentials", log)
    if probe.get("ok"):
        return (("The Service Principal authenticated and Azure ARM IS reachable from this "
                 "runtime, but no subscription or resource group containing this workspace "
                 "was visible to it — that is a MISSING READER ASSIGNMENT, not a network "
                 f"problem. Discovery log: {log or '(empty)'}."), "permissions", log)
    if probe.get("reachable"):
        return ((f"Azure ARM is reachable but rejected the Service Principal "
                 f"({probe.get('reason', 'HTTP 401/403')}). This is a token/RBAC problem, not "
                 "a network block: give the SP READER on the workspace subscription (or at "
                 "least the workspace RG, managed RG and data-plane VNet RG) and re-run."),
                "permissions", log)
    return ((f"Azure ARM (management.azure.com) is NOT reachable from this notebook runtime "
             f"({probe.get('reason', 'no route to management.azure.com')}). Every Azure "
             "configuration check was therefore skipped — this says NOTHING about whether "
             "your Azure configuration is correct, and it is NOT a permissions problem. It is "
             "normal on serverless with a restrictive egress policy or NCC default-deny."),
            "unreachable", log)


def _record_arm_blindness(context, completed, sp, cause, detail="", discovery_log=None):
    """Record why the ARM layer is unreadable and, when the cause is egress, tell the
    customer exactly what to enable so the diagnosis can run LIVE.

    There is no offline/snapshot fallback: a blocked runtime is guided to open egress
    to management.azure.com and re-run, so the Azure layer is always read as it is now.
    Sets `context["azure_infra_error"]` (every azure_checker gate reads it through
    `_azure_skip_reason`, so no row claims the customer withheld an SP they gave) and
    adds the `arm_reachability` row. Returns the reason string.
    """
    arm_token = ""
    if cause in ("discovery_miss", "credentials") and sp.get("client_id") and sp.get("client_secret"):
        tok = get_arm_token(sp.get("tenant_id", ""), sp["client_id"], sp["client_secret"]) or {}
        if tok.get("error"):
            detail = detail or tok["error"]
        else:
            arm_token = tok.get("token", "")
    reason, kind, log = _arm_blindness_reason(
        sp, cause, detail=detail, discovery_log=discovery_log, arm_token=arm_token)

    rec_lines = []
    if kind == "unreachable":
        # No offline snapshot. The runtime cannot reach ARM, so the deliverable is
        # the exact egress to enable — then re-run and the diagnosis is live.
        rec_lines.append(
            "This runtime cannot reach Azure ARM (management.azure.com), so the Azure layer "
            "was NOT inspected. This is an EGRESS block, not a permissions problem and not a "
            "finding about your Azure configuration. To let me diagnose it live, enable "
            "outbound HTTPS to management.azure.com and login.microsoftonline.com from the "
            "compute you are running me on, then re-run:")
        rec_lines.append(
            "- SERVERLESS: Account Console > Settings > Network — add those two endpoints to "
            "the account network policy / NCC egress allow-list (this is an account-admin "
            "setting, and a narrow, reversible allow-list entry, not opening the internet).")
        rec_lines.append(
            "- CLASSIC: the data-plane subnet's route table / NSG / hub firewall must permit "
            "outbound HTTPS to those two endpoints.")
        rec_lines.append(
            "If your security policy forbids that egress, I cannot inspect the Azure layer "
            "from here — that is a deliberate limitation of your environment, not a defect, "
            "and the report will say the Azure layer was not inspected rather than guess.")
    elif kind == "permissions":
        rec_lines.append(
            "Grant the Service Principal READER on the workspace subscription (or at least "
            "the workspace RG, managed RG, data-plane VNet RG, and any RGs holding route "
            "tables / NSGs / NAT / Private DNS zones / Private Endpoints): Azure Portal > "
            "Subscription > Access control (IAM) > Add role assignment > Reader. Then re-run.")
    elif kind == "credentials":
        rec_lines.append(
            "Check the Service Principal's tenant id, client id and client secret (an expired "
            "or rotated secret gives AADSTS7000215), and confirm this compute can reach "
            "login.microsoftonline.com. Then re-run. Nothing needs to change in your network "
            "configuration on the strength of this row.")
    elif kind == "secret_unreadable":
        rec_lines.append(
            "Check the Databricks secret scope and key names for the Service Principal "
            "(tenant id, client id, client secret) and re-run.")
    else:
        rec_lines.append(
            "Report this to the Doctor's maintainers with the message above — the ARM layer "
            "was not read because of a failure inside the diagnostic, not because of your "
            "configuration.")

    completed[_ARM_BLIND_ROW] = CheckResult(
        check_name="Azure ARM Reachability",
        target="management.azure.com",
        status=Status.WARN,
        message=reason,
        recommendation="\n".join(rec_lines),
        # Deliberately WARN and deliberately NOT flagged `inconclusive`. A WARN row
        # already keeps the headline off PASS (models.derive_overall_status) and already
        # lands in the all_healthy card's "NOT proven healthy" list, so the honesty is
        # covered either way — but `inconclusive` rows are routed to the limits block,
        # which prints a row's MESSAGE and not its RECOMMENDATION. This row's
        # recommendation IS the deliverable (which egress to enable), so it has to land
        # in the chat's action section, where `_guide_audit` also enforces that it is
        # rendered complete rather than truncated.
        metadata={"arm_blind_kind": kind,
                  "discovery_log": log},
    )
    context["azure_infra_error"] = reason
    print(f"[Doctor] Azure ARM layer NOT read ({kind}). Every ARM check will be SKIPPED with "
          "this reason, and the report will say so instead of claiming no SP was provided:")
    print(f"[Doctor]   {reason}")
    if kind == "unreachable":
        print("[Doctor] The Azure layer is NOT inspected because this runtime cannot reach "
              "ARM. There is no offline fallback. RELAY to the customer: (1) WHY — this is an "
              "EGRESS block, not a permissions problem and not a finding about their config; "
              "(2) enable outbound HTTPS to management.azure.com + login.microsoftonline.com "
              "(serverless: Account Console > Settings > Network / NCC; classic: the "
              "data-plane subnet's route table / NSG / firewall) and re-run; (3) if their "
              "security policy forbids that egress, the Azure layer stays uninspected — say so "
              "plainly and do NOT present this run's Azure silence as a clean result.")
    return reason


# ---------------------------------------------------------------------------
# Why the ACCOUNT layer could not be read — and the OFFLINE fallback (REUSE 2)
# ---------------------------------------------------------------------------
# Exactly the shape of `_record_arm_blindness` above, one layer up, and for the same
# reason. When the Databricks account API refuses us (HTTP 403, "This API is disabled
# for users without account admin status"), the honest UNVERIFIED rows were already
# right — measured in the field, the request ARRIVES and is refused, so it is
# authorization and not egress, and the product's attribution needed no change.
#
# What needed changing is that the customer's only route forward was "make the
# Service Principal an account admin": a permanent, very high privilege on a
# non-human identity, which many enterprises refuse outright. One row now carries the
# hand-off — a read-only snapshot an EXISTING account admin runs once — with that
# escalation demoted to a fallback. There is ONE row for the whole layer, not one per
# dead-end, because four different reads can hit the same 403 and four copies of the
# same paragraph is not a better deliverable.

_ACCOUNT_BLIND_ROW = "account_layer"


def _account_blindness_from_rows(completed):
    """(kind, detail, url) of the FIRST account-layer read that did not answer.

    The checks self-report it (`ACCOUNT_UNREADABLE_META`), so this scans rows rather
    than re-deriving the cause from prose or re-issuing the failing call.
    """
    for row in (completed or {}).values():
        md = (getattr(row, "metadata", None) or {}).get(ACCOUNT_UNREADABLE_META)
        if md:
            return md.get("kind", "http"), md.get("detail", ""), md.get("url", "")
    return "", "", ""


def _account_row_to_carry(completed):
    """The (key, row) that already reported the account-layer failure, if any.

    The hand-off is ATTACHED to that row rather than added as a row of its own. A
    second row would be a second unverified entry naming a CAUSE, not a layer, so the
    limits block would list the same blindness twice and the headline's gap count —
    which D3 just made meaningful — would inflate. Rows are layers; causes ride on
    them.
    """
    for key, row in (completed or {}).items():
        if (getattr(row, "metadata", None) or {}).get(ACCOUNT_UNREADABLE_META):
            return key, row
    return "", None


def _record_account_blindness(context, completed, kind, detail="", url=""):
    """Attach the account-layer hand-off to the row that reported the failure — or, if
    no account check ran at all, materialise the one row that carries it.

    Returns the hand-off message, or "" when nothing was recorded.
    """
    if not kind or _ACCOUNT_BLIND_ROW in completed:
        return ""
    ncc = context.get("ncc_config") or {}
    meta = account_dump_meta()
    account_id = ncc.get("account_id") or meta.get("account_id") or ""
    ws_ctx = context.get("ws_ctx") or {}
    workspace_id = (ncc.get("workspace_id") or meta.get("workspace_id")
                    or ws_ctx.get("workspace_id") or "")
    workspace_url = ws_ctx.get("workspace_url") or meta.get("workspace_url") or ""
    row = account_unreadable_row(
        kind, detail=detail, account_id=account_id, workspace_id=workspace_id,
        workspace_url=workspace_url,
        account_host=ncc.get("account_host", ""), url=url)
    carrier_key, carrier = _account_row_to_carry(completed)
    if carrier is not None:
        # Attach, don't duplicate: the check's own message already states what is
        # unknown at ITS layer (and is better placed to — it knows the target), so only
        # the prescription and the script move across.
        carrier.recommendation = row.recommendation
        carrier.raw_output = ((carrier.raw_output or "") + "\n\n"
                              if (carrier.raw_output or "").strip() else "") + row.raw_output
        carrier.metadata = dict(carrier.metadata or {}, **{
            k: v for k, v in (row.metadata or {}).items()
            if k != ACCOUNT_UNREADABLE_META})
        row = carrier
    else:
        completed[_ACCOUNT_BLIND_ROW] = row
    print(f"[Doctor] Databricks ACCOUNT layer NOT read ({kind}). The NCC / network-policy "
          "checks are UNVERIFIED gaps — NOT findings that an NCC or a policy is absent, and "
          "NOT errors: an authorization boundary is not a fault in the customer's network.")
    if (row.metadata or {}).get("account_dump_script"):
        print("[Doctor] A READ-ONLY account snapshot script was generated. RELAY to the "
              "customer: (1) WHAT stays unknown — the NCC attachment, its private-endpoint "
              "rules, and the attached egress network policy; (2) this needs NO new "
              "permission — someone who is ALREADY a Databricks account admin runs a few "
              "GETs that change nothing; (3) it runs in Azure Portal > Cloud Shell (Bash) "
              "and uploads account_dump.json to this workspace; (4) tell me when it is done "
              "and I finish the account half from that file with load_account_dump(<path>). "
              "Offer granting the SP account admin only as the FALLBACK, and say why it is "
              "the fallback.")
    else:
        print("[Doctor] No Databricks ACCOUNT ID is available, so the read-only snapshot "
              "script could not be generated. ASK the customer for the account id (a UUID, "
              "visible in the accounts.azuredatabricks.net URL) — then the script can be "
              "produced. Do NOT present this run's account-layer silence as a clean result.")
    return row.message


def _run_phase(ckpt, path, phase_name, check_names, context):
    """Run one phase against the checkpoint, persisting after every check."""
    host, port = ckpt["host"], ckpt["port"]
    completed = {n: check_from_dict(c) for n, c in ckpt["checks"].items()}
    skipped = [tuple(s) for s in ckpt["skipped"]]
    already_skipped = {s[0] for s in skipped}

    context = dict(context or {})
    context["host"] = host
    context["port"] = port

    # REUSE 2, consumption half. `context["account_data"]` carries a snapshot taken by
    # an existing account admin (see `_record_account_blindness`). Installing it here —
    # a context KEY, not a new parameter — is what makes the hand-off consumable
    # through the entry points that already exist, with no signature to document and
    # nothing for a relay to pass along. `load_account_dump(<path>)` in the notebook
    # reaches the same cache, so either route completes the account half.
    if context.get("account_data") is not None:
        set_account_data_cache(context["account_data"])
        print("[Doctor] An account-layer snapshot is installed — the NCC / network-policy "
              "checks will read from it. No account-admin token is needed for this run.")

    # NCC checks are OPTIONAL — say so loudly BEFORE the phase runs, so the
    # agent does not derail into hunting account ids / account-admin tokens
    # (observed in the field): the gates mark them SKIP and the diagnosis
    # proceeds without them.
    if phase_name == "infra" and not context.get("ncc_config"):
        print("[Doctor] NCC checks will be SKIPPED — no account-level credentials provided. "
              "This is NORMAL and does not block the diagnosis. Do NOT hunt for account ids "
              "or admin tokens; just proceed to finalize_diagnosis afterwards.")

    # NCC inspection: when the customer provided an account_id, the phase mints
    # the account-API token ITSELF from the same SP (Azure Databricks audience).
    # The SP must be an account admin — a 403 from accounts.azuredatabricks.net
    # means missing account access, which the checks report honestly.
    if phase_name == "infra" and context.get("ncc_config") is not None:
        ncc = context["ncc_config"]
        # With a snapshot loaded there is nothing to mint: every account read resolves
        # from the file. Gating on the token here would have made the hand-off
        # unusable — the run would still null `ncc_config` and skip the very checks the
        # snapshot was taken to answer.
        if not ncc.get("token") and get_account_data_cache() is not None:
            _meta = account_dump_meta()
            for _k in ("account_id", "workspace_id"):
                if not ncc.get(_k) and _meta.get(_k):
                    ncc[_k] = _meta[_k]
            print("[Doctor] Reading the account layer from the loaded snapshot (no account "
                  "token minted, none needed).")
        elif not ncc.get("token"):
            sp_for_ncc = dict(context.get("azure_sp") or {})
            if sp_for_ncc.get("scope") and not sp_for_ncc.get("client_secret"):
                try:
                    sp_for_ncc = load_azure_sp_from_secrets(_get_dbutils(), sp_for_ncc)
                except Exception as e:
                    print(f"[Doctor] NCC token: SP secret resolution failed ({e}) — NCC checks will error honestly.")
                    sp_for_ncc = {}
            if sp_for_ncc.get("client_id") and sp_for_ncc.get("client_secret"):
                print("[Doctor] Minting the Databricks account-API token from the SP "
                      "(the SP must be an account admin for NCC inspection)...")
                tok = get_databricks_account_token(
                    sp_for_ncc.get("tenant_id", ""), sp_for_ncc["client_id"], sp_for_ncc["client_secret"])
                if tok["error"]:
                    print(f"[Doctor] Account token mint failed ({tok['error']}) — NCC inspection "
                          "REQUESTED but cannot run; this will be reported as a finding, NOT hidden.")
                    # Record BEFORE nulling ncc_config: the row needs the account id the
                    # customer supplied in order to generate the read-only script, and
                    # `ncc_config` is where that id lives.
                    _record_account_blindness(context, completed, "credentials", tok["error"])
                    context["ncc_config"] = None
                    context["ncc_inspection_error"] = (
                        f"the account-API token could not be minted from the provided Service "
                        f"Principal ({tok['error']}), so no account-level fact was read. An "
                        f"EXISTING Databricks account admin can settle this layer with a few "
                        f"read-only GETs — no new permission for the Service Principal (see the "
                        f"'Databricks Account API Readability' row).")
                else:
                    ncc["token"] = tok["token"]
            else:
                print("[Doctor] NCC inspection REQUESTED but no SP credentials available to mint "
                      "the account token — this will be reported as a finding, NOT hidden.")
                _record_account_blindness(
                    context, completed, "no_credentials",
                    "no Service Principal credentials were available to mint the account-API token")
                context["ncc_config"] = None
                context["ncc_inspection_error"] = (
                    "no Service Principal credentials were available to mint the account-API "
                    "token, so no account-level fact was read. Verify the SP secret scope/key "
                    "names — or skip the credential question entirely: an EXISTING Databricks "
                    "account admin can settle this layer with a few read-only GETs (see the "
                    "'Databricks Account API Readability' row).")

    # The infra phase builds its own AzureInfraChecker when the caller passed SP
    # material in context["azure_sp"] instead of a ready checker — otherwise every
    # infra check gate-skips and the phase is vacuous (observed in the field).
    # azure_sp accepts BOTH forms (seen in real runs: the intake collects
    # secret REFS — scope + key names — exactly as SKILL.md documents, and the
    # phase must resolve them itself):
    #   - secret REFS:  {"scope": ..., "tenant_id_key": ..., "client_id_key": ...,
    #                    "client_secret_key": ...}  -> resolved via Databricks Secrets here
    #   - loaded VALUES: {"tenant_id": ..., "client_id": ..., "client_secret": ...}
    #
    # `skip_arm_layer` switches the ARM half off outright. Set by the caller for a
    # SERVERLESS-only run whose destination is not an Azure resource (a package index,
    # an external API): every classic-plane check already plane-skips
    # (models.classic_plane_skip), and the one remaining ARM consumer (`pe`) would be
    # describing a target no Azure resource backs — so building the checker means
    # running a full subscription/RG/VNet discovery sweep to answer nothing. Record the
    # REASON, because the default skip text ("no SP was provided") would blame the
    # customer for withholding a credential we deliberately chose not to need.
    if phase_name == "infra" and context.get("skip_arm_layer"):
        context.setdefault("azure_infra_error", _ARM_NOT_CONSULTED)
        print(f"[Doctor] Azure ARM layer NOT consulted — {_ARM_NOT_CONSULTED}. "
              "No ARM discovery sweep will run and no Azure credential is needed for "
              "this run; the account layer (NCC / serverless network policy) is where "
              "this answer lives.")
    elif phase_name == "infra" and not context.get("azure_checker"):
        sp = dict(context.get("azure_sp") or {})
        # Set when auto-discovery matched this workspace in ARM: it makes the
        # topology-first graph available even if the customer declined to paste the
        # workspace ARM id (that graph is what resolves route tables and a firewall
        # living in a peered HUB subscription).
        _discovered_ws_arm = ""
        # (cause, detail) for the ONE reason the ARM layer ended up unreadable, so the
        # skip rows can state it instead of a fixed "no SP provided" string.
        _blind = None
        if sp.get("scope") and not sp.get("client_secret"):
            print(f"[Doctor] Resolving Azure SP from Databricks secret scope '{sp['scope']}'...")
            try:
                sp = load_azure_sp_from_secrets(_get_dbutils(), sp)
            except Exception as e:
                print(f"[Doctor] SP secret resolution FAILED ({e}) — infra checks will be "
                      "SKIPPED. The SP WAS provided but could not be read from the secret "
                      "scope; verify the scope/key names and re-run continue_diagnosis.")
                _blind = ("secret_unreadable", str(e))
                sp = {}
        if sp.get("client_id") and sp.get("client_secret"):
            print("[Doctor] Building AzureInfraChecker from the provided SP "
                  "(auto-discovering subscription / resource group / VNet)...")
            try:
                ctx2 = auto_discover_azure_context(
                    sp["client_id"], sp["client_secret"],
                    tenant_id=sp.get("tenant_id", ""),
                    # Prefer the exact workspace ARM id when the customer supplied it: it pins
                    # the subscription + data-plane VNet directly, so the check suite builds even
                    # when this runtime has no IMDS/spark to match the workspace by URL.
                    workspace_arm_id=context.get("workspace_arm_id", ""),
                )
                _discovered_ws_arm = ctx2.get("workspace_id", "") or ""
                if ctx2.get("subscription_id") and ctx2.get("resource_group"):
                    context["azure_checker"] = AzureInfraChecker(
                        tenant_id=ctx2["tenant_id"],
                        client_id=ctx2["client_id"],
                        client_secret=ctx2["client_secret"],
                        subscription_id=ctx2["subscription_id"],
                        resource_group=ctx2["resource_group"],
                        vnet_name=ctx2.get("vnet_name", ""),
                    )
                    print(f"[Doctor] AzureInfraChecker ready (rg={ctx2['resource_group']}, "
                          f"vnet={ctx2.get('vnet_name', '') or '(none)'}).")
                else:
                    print("[Doctor] Azure auto-discovery could not find the resource group — "
                          "infra checks will be SKIPPED. Discovery log:")
                    for msg in ctx2.get("discovery_log", []):
                        print(f"  {msg}")
                    _blind = ("discovery_miss", "", ctx2.get("discovery_log", []))
            except Exception as e:
                print(f"[Doctor] AzureInfraChecker build failed ({e}) — infra checks will be SKIPPED.")
                _blind = ("build_error", str(e))
        elif not context.get("azure_sp"):
            pass  # genuinely no SP — the gates' skip reason is accurate

        # ROOT B (second half). An SP was supplied and the ARM layer is still
        # unreadable: say WHICH cause, and when the cause is "this runtime cannot reach
        # ARM", guide the customer to enable egress and re-run (no offline snapshot)
        # instead of asking for access that is already granted.
        if _blind is not None and _ARM_BLIND_ROW not in completed:
            _record_arm_blindness(context, completed, sp, _blind[0],
                                  detail=(_blind[1] if len(_blind) > 1 else ""),
                                  discovery_log=(_blind[2] if len(_blind) > 2 else None))

        # Topology-first egress trace (classic Path A). When the consumer is classic
        # and the workspace ARM id + a readable SP are available, DISCOVER the customer
        # network graph (VNet -> subnets -> route tables -> peerings -> hub firewall,
        # across peered subscriptions) and trace the effective egress path to host:port.
        # A FAIL lands as a `topology_egress_path` CheckResult in `completed` so it (a)
        # survives the checkpoint and (b) feeds the existing _rule_egress_firewall_missing
        # headline (same engine Path B/C use). Best-effort: a declined ARM id, no SP, a
        # token-mint error, or any build/trace exception is skipped silently — the basic
        # AzureInfraChecker probes (nsg/routes/peering) still run and cover those layers.
        _ws_arm = context.get("workspace_arm_id", "") or _discovered_ws_arm
        if _ws_arm and not context.get("workspace_arm_id"):
            print(f"[Doctor] Using the auto-discovered workspace ARM id for topology discovery "
                  f"({_ws_arm.split('/')[-1]}).")
        if ("topology_egress_path" not in completed
                and context.get("compute_type", "").lower() == "classic"
                and _ws_arm.startswith("/subscriptions/")
                and sp.get("client_id") and sp.get("client_secret")):
            try:
                from topology import build_topology as _build_topology, trace as _topo_trace
                _tok = get_arm_token(sp.get("tenant_id", ""), sp["client_id"], sp["client_secret"])
                if not _tok["error"]:
                    _topo = _build_topology(_tok, _ws_arm, compute_type="classic")
                    # Share the graph with the per-check dispatcher: the firewall-egress
                    # check reuses it to resolve an appliance in a peered hub
                    # subscription instead of re-deriving one single-subscription view.
                    context["_topology"] = _topo
                    _subnets = (_topo.roots or {}).get("subnet_ids") or []
                    if _subnets:
                        # ALWAYS validate general egress in addition to the customer's
                        # target. The forced-tunnel path is a property of the SUBNET, not
                        # of the destination, and the customer's target may be served by a
                        # private endpoint (or by back-end Private Link, as the workspace's
                        # own control plane is) — in which case tracing only that target
                        # says nothing about whether ordinary egress works.
                        #
                        # In the field: with the spoke->hub peering deleted the Doctor
                        # twice reported all_healthy. The first fix keyed this second trace
                        # on the "setup" audit answer, but the agent supplied the workspace
                        # URL directly instead of the literal keyword, so the flag was never
                        # set and the extra trace never ran. Keying on intent was too
                        # narrow; the check is cheap (same in-memory graph, no extra ARM
                        # calls), so just always do it.
                        _traces = [(host, port, None), ("*.blob.core.windows.net", 443, "storage")]
                        _unproven = None   # a peer_vnet_unreadable WARN, recorded only if no FAIL wins
                        for _h, _p, _cat in _traces:
                            _tr = _topo_trace(_topo, _subnets[0], _h, _p, category=_cat)
                            if _tr.get("status") == "fail":
                                completed["topology_egress_path"] = CheckResult(
                                    check_name="topology_egress_path", target=f"{_h}:{_p}",
                                    status=Status.FAIL, message=_tr.get("reason", ""),
                                    recommendation=_tr.get("recommendation", ""),
                                    metadata={"trace": _tr})
                                print("[Doctor] Topology egress trace: FAIL — discovered a blocking gate "
                                      f"on the path to {_h}:{_p} (see the egress-path finding).")
                                _unproven = None
                                break
                            # Surface an UNPROVEN forced-tunnel leg (Connected peering, hub VNet
                            # unreadable) as WARN so it is not silent — but never as a FAIL, and
                            # let a real FAIL on a later trace take precedence.
                            if (_unproven is None
                                    and (_tr.get("blocking_gate") or {}).get("kind") == "peer_vnet_unreadable"):
                                _unproven = (f"{_h}:{_p}", _tr)
                        if "topology_egress_path" not in completed and _unproven is not None:
                            _ut, _tr = _unproven
                            completed["topology_egress_path"] = CheckResult(
                                check_name="topology_egress_path", target=_ut,
                                status=Status.WARN, message=_tr.get("reason", ""),
                                recommendation=_tr.get("recommendation", ""),
                                metadata={"trace": _tr})
                            print("[Doctor] Topology egress trace: WARN — forced-tunnel leg UNPROVEN "
                                  f"(hub VNet unreadable) on the path to {_ut}; peering is Connected.")
            except Exception as _e:
                print(f"[Doctor] Topology egress trace skipped ({_e}); basic probes still cover "
                      "NSG/routes/peering.")

    def _persist(_check_name):
        ckpt["checks"] = {n: check_to_dict(c) for n, c in completed.items()}
        ckpt["skipped"] = [list(s) for s in skipped]
        # Carry the NCC-inspection failure reason to finalize so the chat
        # prescription stays honest (the context is rebuilt fresh per cell and
        # would otherwise lose it). It is a reason STRING, never a token — safe to
        # persist, unlike the account token which we deliberately do NOT store.
        if context.get("ncc_inspection_error"):
            ckpt.setdefault("context_lite", {})["ncc_inspection_error"] = context["ncc_inspection_error"]
        _save_checkpoint(ckpt, path)

    # Resume support: only run checks that have no recorded outcome yet.
    pending = [n for n in check_names if n not in completed and n not in already_skipped]
    _run_check_list(pending, host, port, completed, skipped, context, after_each=_persist)

    # REUSE 2. A check may have RUN and still not have read the account layer (the 403
    # case — the common one). The checks report that structurally, so scan the rows
    # here rather than duplicating the classification: one hand-off row for the layer,
    # whichever of the four reads was refused first.
    _acct_kind, _acct_detail, _acct_url = _account_blindness_from_rows(completed)
    if _acct_kind and _acct_kind != "not_found":
        _msg = _record_account_blindness(context, completed, _acct_kind,
                                        detail=_acct_detail, url=_acct_url)
        if _msg:
            _persist(_ACCOUNT_BLIND_ROW)

    if phase_name not in ckpt["phases_done"]:
        ckpt["phases_done"].append(phase_name)
    _persist("")
    ran = [n for n in pending if n in completed]

    remaining = [p for p, _ in _PHASES if p not in ckpt["phases_done"]]
    if remaining:
        next_call = f"ckpt_path = continue_diagnosis(r'{path}', context)"
    else:
        next_call = f"report = finalize_diagnosis(r'{path}', context)"
    print(f"[Doctor] Phase '{phase_name}' complete ({len(ran)} check(s) ran, "
          f"{len(completed)} total recorded). Checkpoint: {path}")
    print(f"[Doctor] NEXT — run this in a NEW cell: {next_call}")
    return _CheckpointHandle(path, ckpt["phases_done"], next_call)


def start_diagnosis(host, port, context, checkpoint_path=None):
    """Phase 1 of the chunked diagnostic: network probes (dns/ping/tcp/traceroute/tls/latency).

    Creates (or RESUMES, if the file already exists for this target) a checkpoint
    JSON in network_doctor_reports/, persisted after every check. Run this in its
    own notebook cell, then continue_diagnosis() in the next cell, then
    finalize_diagnosis() in a third.

    Returns a _CheckpointHandle: it IS the checkpoint path string (pass it
    directly to continue_diagnosis / finalize_diagnosis), and it also exposes
    .path, .phases_done, and .next_step (the literal code for the next cell).
    It is NOT a report object — there is no .phase/.report on it.
    """
    import os
    from datetime import datetime, timezone
    path = checkpoint_path or _checkpoint_path_for(host, port)
    if os.path.exists(path):
        ckpt = load_checkpoint(path)
        print(f"[Doctor] Found an existing checkpoint for this target "
              f"({len(ckpt['checks'])} check(s) recorded) — RESUMING. This is normal; "
              "recorded checks are never re-run. Do NOT delete the checkpoint; to start "
              "completely fresh, remove the file first and re-call start_diagnosis.")
    else:
        ckpt = {
            "schema": _CHECKPOINT_SCHEMA,
            "host": host,
            "port": port,
            "phases_done": [],
            "checks": {},
            "skipped": [],
            "context_lite": {"compute_type": (context or {}).get("compute_type", "")},
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    return _run_phase(ckpt, path, "probes", dict(_PHASES)["probes"], context)


def continue_diagnosis(checkpoint_path, context):
    """Run the next pending phase from the checkpoint (idempotent — safe to re-run
    the same cell after a session reset; completed checks are never re-executed).

    `context` must be rebuilt in this cell if the session reset (azure_checker,
    ncc_config, etc. are not serializable and are NOT stored in the checkpoint).
    """
    ckpt = load_checkpoint(checkpoint_path)
    for phase_name, check_names in _PHASES:
        if phase_name not in ckpt["phases_done"]:
            return _run_phase(ckpt, checkpoint_path, phase_name, check_names, context)
    next_call = f"report = finalize_diagnosis(r'{checkpoint_path}', context)"
    print(f"[Doctor] All phases already complete. NEXT — run this in a NEW cell: {next_call}")
    return _CheckpointHandle(str(checkpoint_path), ckpt["phases_done"], next_call)


def finalize_diagnosis(checkpoint_path, context=None, keep_checkpoint=False):
    """Correlate the checkpointed checks and return the DiagnosticReport.

    Runs NO new checks. Deletes the checkpoint on success (zero-footprint) unless
    keep_checkpoint=True. Render + save the dashboard from the returned report as
    usual (build_dashboard_v2 / save_dashboard_html).
    """
    import os
    ckpt = load_checkpoint(checkpoint_path)
    pending = [p for p, _ in _PHASES if p not in ckpt["phases_done"]]
    if pending:
        print(f"[Doctor] WARNING: finalizing with pending phase(s) {pending} — "
              "diagnoses may be based on partial evidence. Run continue_diagnosis() first.")
    completed = {n: check_from_dict(c) for n, c in ckpt["checks"].items()}
    skipped = [tuple(s) for s in ckpt["skipped"]]
    context = dict(context or {})
    context.setdefault("compute_type", ckpt.get("context_lite", {}).get("compute_type", ""))
    _ncc_err = ckpt.get("context_lite", {}).get("ncc_inspection_error")
    if _ncc_err and not context.get("ncc_inspection_error"):
        context["ncc_inspection_error"] = _ncc_err
    context["host"] = ckpt["host"]
    context["port"] = ckpt["port"]
    report = _assemble_report(ckpt["host"], ckpt["port"], completed, skipped, context)
    if not pending and not keep_checkpoint:
        try:
            os.remove(checkpoint_path)
            print(f"[Doctor] Checkpoint removed (zero-footprint): {checkpoint_path}")
        except OSError:
            pass
    return report


# ---------------------------------------------------------------------------
# Cluster-start diagnostic path (NHC failures — broken cluster, ARM-only)
# ---------------------------------------------------------------------------

def diagnose_cluster_start(nhc_error_text, workspace_resource_id, arm_token="",
                          databricks_pat=""):
    """Diagnose why a classic cluster failed NHC and could not bootstrap.

    LIVE ONLY: pass `arm_token`. The orchestrator reads Azure ARM directly, from
    the runtime the problem lives on. Works from any compute that can reach
    login.microsoftonline.com and management.azure.com (classic cluster, or
    serverless with the account network policy / NCC allow-listing those
    endpoints). There is no offline/snapshot mode: if this runtime cannot reach
    ARM, the driver tells the customer which egress to enable and to re-run — the
    Azure layer is always read as it is now, never from a pre-fetched file.

    Args:
        nhc_error_text: The full text from the "Terminating" / "Add nodes
            failed" event (must include X_NHC_*, failed components, and
            entity:/last_error_code: lines).
        workspace_resource_id: ARM id of the Databricks workspace.
        arm_token: Azure ARM bearer token.
        databricks_pat: Optional Databricks workspace PAT.

    Returns:
        DiagnosticReport. The `checks` dict uses these keys:
            nhc_parse, ws_network_cfg, public_subnet_delegation,
            private_subnet_delegation, public_subnet_nsg, private_subnet_nsg,
            public_subnet_routes, private_subnet_routes,
            public_subnet_egress_ip, private_subnet_egress_ip,
            ws_ip_access_list, ws_private_link, ws_private_dns,
            outbound_databricks_com.
    """
    completed = {}
    skipped = []
    workspace_url = ""
    return _diagnose_cluster_start_inner(
        nhc_error_text, workspace_resource_id, arm_token,
        completed, skipped, workspace_url,
    )


def _diagnose_cluster_start_inner(nhc_error_text, workspace_resource_id, arm_token,
                                  completed, skipped, workspace_url):
    # Step 1: parse the error text up front (no ARM call needed).
    nhc = parse_nhc_error(nhc_error_text)
    if nhc["is_nhc"] and nhc.get("is_launch_failure") and not nhc["entities"] and not nhc["failed_components"]:
        # Non-NHC classic launch failure (e.g. X_UnexpectedLaunchFailure /
        # UNEXPECTED_LAUNCH_FAILURE / SERVICE_FAULT / "No such workerEnvironment").
        # This is a SYMPTOM, not proof of a Databricks-side bug — run the full
        # Azure-infra diagnostic to find a customer-side root cause.
        nhc_msg = (
            f"Classic cluster launch failure detected (signatures: "
            f"{', '.join(nhc['launch_failure_signatures'])}). This is NOT a canonical NHC "
            "health-check error and a SERVICE_FAULT classification alone does NOT prove a "
            "Databricks-side bug. Running the full workspace Azure-infra diagnostic "
            "(subnet delegation, required NSG rules, route tables/forced-tunnel, egress, "
            "private link, DNS) to find a customer-side root cause."
        )
    elif nhc["is_nhc"]:
        nhc_msg = (
            f"Parsed {nhc['error_code']} ; failed_components={nhc['failed_components']} ; "
            f"{len(nhc['entities'])} entity(ies) ; retryable={nhc['retryable']}"
        )
    else:
        nhc_msg = (
            "Could not recognise this error text as a cluster-start / NHC failure. "
            "Continuing with workspace network checks anyway."
        )
    completed["nhc_parse"] = CheckResult(
        check_name="NHC Error Parse",
        target=nhc.get("error_code") or "(unknown)",
        status=Status.PASS if nhc["is_nhc"] else Status.WARN,
        message=nhc_msg,
        metadata=nhc,
    )

    # Step 2: workspace network config (single ARM call).
    ws_cfg = get_workspace_network_config(arm_token, workspace_resource_id)
    if not ws_cfg["ok"]:
        completed["ws_network_cfg"] = CheckResult(
            check_name="Workspace Network Config",
            target=workspace_resource_id or "(no resource id)",
            status=Status.ERROR,
            message=ws_cfg["error"] or "Failed to fetch workspace.",
        )
        # Without workspace config, no further ARM checks make sense.
        return _build_cluster_start_report(workspace_resource_id, completed, skipped, nhc)

    workspace_url = ws_cfg["workspace_url"]
    completed["ws_network_cfg"] = CheckResult(
        check_name="Workspace Network Config",
        target=workspace_url or workspace_resource_id,
        status=Status.PASS,
        message=(
            f"workspaceUrl={workspace_url} ; publicNetworkAccess={ws_cfg['public_network_access'] or 'Enabled'} ; "
            f"requiredNsgRules={ws_cfg['required_nsg_rules'] or '(unset)'} ; "
            f"VNet-injected={'yes' if ws_cfg['vnet_id'] else 'no'} ; "
            f"PE_connections={len(ws_cfg['private_endpoint_connections'])}"
        ),
        metadata=ws_cfg,
    )

    vnet_id = ws_cfg["vnet_id"]
    public_subnet = ws_cfg["public_subnet"]
    private_subnet = ws_cfg["private_subnet"]

    # If not VNet-injected, the entire VNet-inject diagnostic is moot.
    if not vnet_id:
        completed["public_subnet_delegation"] = CheckResult(
            "Subnet Delegation", "(default networking)", Status.SKIP,
            "Workspace uses default Databricks-managed networking — VNet inject not in use.",
        )
        return _build_cluster_start_report(workspace_resource_id, completed, skipped, nhc,
                                           workspace_url=workspace_url)

    # Step 2b: back-end (classic compute plane) Private Link detection runs BEFORE the
    # subnet checks, because the NSG check needs its verdict. With an Approved
    # databricks_ui_api PE in the data-plane VNet, requiredNsgRules=NoAzureDatabricksRules
    # is the documented-correct setting and the missing public AzureDatabricks NSG rules are
    # EXPECTED. Previously this ran at step 4, AFTER the NSG check — so the NSG row went
    # hard red with "flip to AllRules" advice while the diagnosis underneath said the exact
    # opposite. has_backend_pe is set only with an Approved PE VERIFIED in the
    # data-plane VNet: front-end PEs share the databricks_ui_api sub-resource and must not
    # suppress the AllRules option.
    completed["ws_backend_private_link"] = check_backend_private_link(ws_cfg, vnet_id, arm_token=arm_token)

    # Step 3: subnet checks (run for both public and private subnets).
    for label, subnet in (("public", public_subnet), ("private", private_subnet)):
        if not subnet:
            skipped.append((f"{label}_subnet_*", f"workspace has no {label} subnet name set"))
            continue
        completed[f"{label}_subnet_delegation"] = check_subnet_delegation(
            arm_token, vnet_id, subnet)
        completed[f"{label}_subnet_nsg"] = check_subnet_required_nsg_rules(
            arm_token, vnet_id, subnet, ws_cfg["required_nsg_rules"],
            backend_pl_check=completed["ws_backend_private_link"])
        completed[f"{label}_subnet_routes"] = check_subnet_route_table(
            arm_token, vnet_id, subnet)
        completed[f"{label}_subnet_egress_ip"] = check_subnet_egress_ip(
            arm_token, vnet_id, subnet)

    # Step 4: workspace-level checks.
    # NOTE: Workspace IP access list is NOT included in this path. Per
    # https://learn.microsoft.com/en-us/azure/databricks/security/network/front-end/ip-access-list-workspace
    # the IP access list governs end-user / SDK ingress to the workspace UI and
    # REST API. While the doc notes that with SCC enabled the data plane's
    # public egress IP must also be allow-listed, the "Configured privacy
    # settings disallow access" 401 message is the publicNetworkAccess=Disabled
    # signal — handled by check_workspace_private_link below.
    completed["ws_private_link"] = check_workspace_private_link(ws_cfg, vnet_id)
    # ws_backend_private_link already ran at step 2b (the NSG check consumes it).
    completed["ws_private_dns"] = check_dns_resolution_for_workspace(
        arm_token, vnet_id, workspace_url, ws_cfg["public_network_access"])

    # Step 5: derived outbound check (uses the private subnet's UDR result).
    _route_check = completed.get("private_subnet_routes") or completed.get("public_subnet_routes")
    # Pass the parsed NHC so the check only correlates against evidence that EXISTS
    #: with no www.databricks.com signal it must state the routing fact and
    # attribute nothing.
    completed["outbound_databricks_com"] = check_outbound_to_databricks_com(_route_check, nhc=nhc)

    # Step 5b: if a subnet forces 0.0.0.0/0 through an Azure Firewall, resolve the
    # NVA IP to the firewall and check whether its allow-list actually covers the
    # Databricks egress the bootstrap NHC failed on (the UDR wins over the NSG, so
    # the firewall — not the NSG — is the real gate). Turns the generic forced-
    # tunnel WARN into a precise "missing Storage egress" root cause.
    #
    # Phase-0 topology (classic VNet plane): build the graph once so the firewall
    # resolution spans PEERED HUB subscriptions, not just the workspace's own.
    # Best-effort — any failure degrades to the single-subscription inline lookup.
    _topo = None
    try:
        from topology import build_topology as _build_topology
        _topo = _build_topology(arm_token, workspace_resource_id, compute_type="classic")
    except Exception:
        _topo = None
    # Back-end Private Link (Approved databricks_ui_api PE) carries the control
    # plane, so the firewall must NOT be required to allow control-plane egress
    # (else a correctly-configured SRA workspace gets a CRITICAL false positive).
    _bpl = completed.get("ws_backend_private_link")
    _backend_pl_present = bool(_bpl is not None and _bpl.status == Status.PASS)
    completed["forced_tunnel_firewall"] = check_forced_tunnel_firewall_egress(
        arm_token, _route_check, nhc, workspace_resource_id, topology=_topo,
        backend_pl_present=_backend_pl_present)

    return _build_cluster_start_report(workspace_resource_id, completed, skipped, nhc,
                                       workspace_url=workspace_url)


def _build_cluster_start_report(workspace_resource_id, completed, skipped, nhc,
                                 workspace_url=""):
    """Assemble the final report and run NHC correlation rules."""
    diagnoses = correlate(completed, context={"diagnostic_path": "cluster_start", "nhc": nhc,
                                              "gate_skipped": list(skipped or [])})
    # Same single-container rule as _assemble_report: rules read the checks
    # that RAN, the customer-facing report reads every row including the skips.
    rows = merge_gate_skips(completed, skipped)
    summary = generate_summary(diagnoses, rows)
    # the headline is derived from what was CONCLUDED (diagnosis severity),
    # not from "any row is red". A red row with only a `medium` latent finding on it
    # is not a failed workspace; a CRITICAL/HIGH diagnosis is, whatever the rows say.
    # Row-level truth is untouched — see models.derive_overall_status for the policy.
    overall = derive_overall_status(rows, diagnoses)
    return DiagnosticReport(
        target=workspace_url or workspace_resource_id,
        host=workspace_url,
        port=443,
        checks=rows,
        diagnoses=diagnoses,
        skipped=skipped,
        overall_status=overall,
        summary=summary,
    )
