"""Correlation engine for the Network Connectivity Doctor.

Analyzes combinations of check results to produce high-confidence diagnoses
with severity levels, fix ordering, and prescriptions.

Importable module: sibling scripts resolve via sys.path (the skill dir is
inserted by SKILL.md Step 1). Also works exec-loaded for back-compat.
"""

import re as _re

from models import (SKIP_UNVERIFIED, Diagnosis, Severity, Status, actionable_diagnoses,
                    companion_egress_clause,
                    check_verdict_counts, gate_skip_title, is_data_plane_vnet,
                    severity_value, skip_kind, status_value)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find(checks, name):
    """Get a CheckResult by check_name from a dict."""
    return checks.get(name)


def _has_status(check, *statuses):
    if check is None:
        return False
    return check.status in statuses


def _msg_contains(check, *keywords):
    if check is None:
        return False
    msg = check.message.lower()
    return any(k.lower() in msg for k in keywords)


def _meta(check, key, default=None):
    if check is None:
        return default
    return check.metadata.get(key, default)


def _account_row_was_read(check):
    """True only when an account-layer row contains a definitive observation.

    Row existence is not evidence: SKIP/UNKNOWN rows are deliberately materialised so
    the report can show an authorization gap. Treat only an actual PASS/FAIL/WARN whose
    producer did not mark `readable=False` as inspected account state.
    """
    return bool(
        check is not None
        and _has_status(check, Status.PASS, Status.FAIL, Status.WARN)
        and _meta(check, "readable", True) is not False
    )


def _account_row_is_unread(check):
    """Did this applicable account layer explicitly remain UNKNOWN / NOT READ?"""
    if check is None:
        return False
    return (_meta(check, "readable", None) is False
            or (_has_status(check, Status.SKIP)
                and skip_kind(check) == SKIP_UNVERIFIED))


def _is_private_ip(ip_str):
    """Check if an IP string is RFC 1918 private."""
    if not ip_str:
        return False
    try:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        return False
    except (ValueError, IndexError):
        return False


def _resolved_ips(dns_check):
    """Extract resolved IPs from DNS check metadata or message."""
    ips = _meta(dns_check, "ips", [])
    if ips:
        return ips
    # Fallback: parse from message like "Resolved to 10.0.1.5"
    if dns_check and "resolved to" in dns_check.message.lower():
        msg = dns_check.message
        idx = msg.lower().find("resolved to")
        tail = msg[idx + len("resolved to"):].strip()
        ip = tail.split()[0].strip(",;")
        if ip:
            return [ip]
    return []


# ---------------------------------------------------------------------------
# Unified egress-firewall diagnosis (shared by Path A rule + Path B selector)
# ---------------------------------------------------------------------------

def make_egress_firewall_diagnosis(trace, source="topology_egress_path"):
    """Build the single, layer-agnostic `egress_firewall_missing` Diagnosis from a
    topology.trace() result whose blocking_gate is a firewall. One source of truth so
    Path A / B / C emit identical wording + the same path line. Returns None when the
    trace is not a firewall block.
    """
    gate = (trace or {}).get("blocking_gate") or {}
    if (trace or {}).get("status") != "fail" or gate.get("kind") != "firewall":
        return None
    missing = gate.get("missing") or (trace or {}).get("missing") or []
    cat = missing[0] if missing else "egress"
    dest_label = {
        "storage": "Databricks storage (blob / DBFS / artifact)",
        "control_plane": "the Databricks control plane / SCC relay",
    }.get(cat, cat)
    try:
        from topology import render_path_line
        path_line = render_path_line(trace)
    except Exception:
        path_line = ""
    fw_name = gate.get("name", "the firewall")
    # Rule-level verdict (set by topology.trace): a Deny rule winning, or an FQDN
    # network rule blocked by disabled DNS proxy, are DISTINCT causes from a plain
    # "no allow rule" gap — different pattern_id so the prescription + precedence
    # differ. Decision strings mirror cluster_start_checks._FW_* (kept as literals
    # to avoid a cross-module import here).
    decision = gate.get("decision")
    if decision == "DENIED_BY_RULE":
        pattern_id = "firewall_rule_denies_egress"
        title = f"Forced-Tunnel Firewall Has a Deny Rule Blocking {dest_label}"
        default_rx = ("Remove or re-scope the Deny rule that matches this egress, or add a higher-precedence "
                      "Allow (lower priority, network rule) for the Databricks destinations on TCP 443.")
    elif decision == "BLOCKED_BY_DNS_PROXY":
        pattern_id = "firewall_dns_proxy_disabled"
        title = f"Firewall FQDN Rule for {dest_label} Needs DNS Proxy"
        default_rx = ("Enable DNS Proxy on the firewall policy (dnsSettings.enableProxy=true) so FQDN network "
                      "rules resolve, move the FQDN to an application rule, or use the matching service tag.")
    else:
        pattern_id = "egress_firewall_missing"
        title = f"Forced-Tunnel Firewall Is Missing Egress for {dest_label}"
        default_rx = ("Add the missing egress allow rule to the firewall in the forced-tunnel path "
                      "(Storage / AzureDatabricks service tags or the matching FQDNs on TCP 443).")
    root = trace.get("reason") or f"Forced-tunnel firewall '{fw_name}' blocks egress for {dest_label}."
    if path_line:
        root = root + "\n" + path_line
    return Diagnosis(
        pattern_id=pattern_id,
        title=title,
        severity=Severity.CRITICAL, confidence="high",
        root_cause=root,
        evidence=[(source, trace.get("reason", ""))],
        prescription=([trace["recommendation"]] if trace.get("recommendation") else [default_rx]),
        fix_order=1,
        # This finding is always about the EGRESS PATH (a firewall rule / UDR in the
        # forced-tunnel hop), never about the storage account's own network ACLs or
        # RBAC — so do NOT label it with the storage layer just because the blocked
        # CATEGORY happens to be storage. Doing so pointed the customer at the storage
        # account blade while the actual misconfiguration sat on the hub firewall
        # . The blocked category is already stated in the text.
        layer="forced-tunnel-egress",
    )


# ---------------------------------------------------------------------------
# Correlation Rules
# ---------------------------------------------------------------------------

def _rule_nsg_deny(checks):
    """TCP FAIL (timeout) + NSG Deny => NSG blocking outbound."""
    tcp = _find(checks, "tcp")
    nsg = _find(checks, "nsg")
    if not (_has_status(tcp, Status.FAIL) and _msg_contains(tcp, "timed out")):
        return None
    if not (_has_status(nsg, Status.FAIL) and _msg_contains(nsg, "DENIES", "Deny")):
        return None
    return Diagnosis(
        pattern_id="nsg_deny",
        title="NSG Rule Blocking Outbound Traffic",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            "An NSG deny rule is dropping outbound packets. "
            "TCP timeout confirms packets are silently dropped, which matches NSG deny behavior."
        ),
        evidence=[
            ("tcp", tcp.message),
            ("nsg", nsg.message),
        ],
        prescription=[
            nsg.recommendation if nsg.recommendation else
            "Open Azure Portal > NSG > Outbound rules > add an Allow rule for the target IP and port "
            "with a priority lower (numerically) than the deny rule.",
            "Wait 30-60 seconds for propagation, then re-run diagnostics.",
        ],
        fix_order=1,
    )


def _rule_nsg_pass_eliminates(checks):
    """TCP FAIL + NSG PASS => NSG is NOT the cause (elimination)."""
    tcp = _find(checks, "tcp")
    nsg = _find(checks, "nsg")
    if not _has_status(tcp, Status.FAIL):
        return None
    if not _has_status(nsg, Status.PASS):
        return None
    return Diagnosis(
        pattern_id="nsg_pass_eliminates",
        title="NSG Allows Traffic (Not the Cause)",
        severity=Severity.INFO,
        confidence="high",
        root_cause="NSG explicitly allows outbound traffic to this target. NSG is not blocking connectivity.",
        evidence=[("nsg", nsg.message)],
        fix_order=99,
    )


def _rule_blackhole_route(checks):
    """TCP FAIL + Routes next_hop=None => Blackhole UDR."""
    tcp = _find(checks, "tcp")
    routes = _find(checks, "routes")
    if not _has_status(tcp, Status.FAIL):
        return None
    if not _has_status(routes, Status.FAIL):
        return None
    if _meta(routes, "next_hop") != "None":
        return None
    table = _meta(routes, "table", "unknown")
    route = _meta(routes, "route", "unknown")
    prefix = _meta(routes, "prefix", "unknown")
    return Diagnosis(
        pattern_id="blackhole_route",
        title="Blackhole Route Dropping All Traffic",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            f"UDR route '{route}' in table '{table}' with prefix {prefix} has next-hop 'None' (blackhole). "
            "All traffic to this range is silently dropped."
        ),
        evidence=[
            ("tcp", tcp.message),
            ("routes", routes.message),
        ],
        prescription=[
            f"Azure Portal > Route tables > {table} > Routes > find '{route}' with prefix {prefix}.",
            "Delete this route or change next-hop to the correct destination (VirtualNetworkGateway, VnetLocal, etc.).",
            "Wait 1-2 minutes for propagation, then re-run diagnostics.",
        ],
        fix_order=1,
    )


def _rule_subnet_egress_blackhole(checks):
    """The data-plane subnet's DEFAULT route (0.0.0.0/0) is a blackhole.

    Distinct from _rule_blackhole_route, which asks about the route matching the
    diagnostic TARGET. When the target is served in-VNet (private endpoint / back-end
    Private Link) its own route is fine and TCP to it can even succeed, while every
    internet-bound flow from the subnet is dropped — the exact blind spot an earlier defect
    describes. Without this rule the subnet_egress FAIL would name no cause.

    Row name differs by path: Path A/B name it `subnet_egress`; the Path C cluster-start
    diagnostic names its data-plane route rows `private_subnet_routes` / `public_subnet_routes`
    and carries the SAME `default_route` metadata. This rule scans all of them, so a
    blackhole default route LEADS the diagnosis on a cluster-start failure too (it used to
    only look at `subnet_egress`, so the real root cause never became a diagnosis on Path C)."""
    se = None
    for _name in ("subnet_egress", "private_subnet_routes", "public_subnet_routes"):
        _row = _find(checks, _name)
        if _has_status(_row, Status.FAIL) and ((_row.metadata or {}).get("default_route") or {}).get("next_hop_type") == "None":
            se = _row
            break
    if se is None:
        return None
    dr = (se.metadata or {}).get("default_route") or {}
    # Don't emit twice — but only defer when _rule_blackhole_route ACTUALLY fires
    # (it additionally requires a TCP failure, which an in-VNet target does not
    # produce even when every internet-bound flow is black-holed).
    if (_has_status(_find(checks, "tcp"), Status.FAIL)
            and _has_status(_find(checks, "routes"), Status.FAIL)
            and _meta(_find(checks, "routes"), "next_hop") == "None"):
        return None
    rt_name = ((se.metadata or {}).get("route_table_id", "") or "").split("/")[-1] or "the route table"
    subnet = (se.metadata or {}).get("subnet_name", "the data-plane subnet")
    return Diagnosis(
        pattern_id="blackhole_route",
        title="Blackhole Default Route Drops All Egress From the Data-Plane Subnet",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            f"Route table '{rt_name}', associated with data-plane subnet '{subnet}', sends "
            f"0.0.0.0/0 to next-hop 'None' (blackhole). Every internet-bound packet from the "
            "workspace's compute is silently dropped. Targets served inside the VNet (private "
            "endpoints, back-end Private Link) can still work, which is why the symptom can look "
            "partial."
        ),
        evidence=[("subnet_egress", se.message)],
        prescription=([se.recommendation] if se.recommendation else [
            f"Azure Portal > Route tables > {rt_name} > Routes > the 0.0.0.0/0 entry: delete it, or "
            "set the next hop to 'Internet' (direct egress) or to 'Virtual appliance' + the hub "
            "firewall's private IP (forced tunneling). Wait 1-2 minutes for propagation.",
        ]),
        fix_order=1,
        layer="classic-vnet",
    )


def _rule_udr_blackhole_required_destination(checks, context=None):
    """A next-hop-'None' route on a NON-default prefix that covers something the
    workspace must reach.

    Field experience: a UDR on the `Storage` service tag with next hop `None`
    was added to the data-plane subnets. The route table was read, the report showed
    only the 0.0.0.0/0 entry, and the run concluded `launch_failure_arm_clean` — "no
    customer-side network misconfiguration" — then steered the customer at DNS and
    Private Link. Nothing named the route.

    The existing blackhole rules only ask about the 0.0.0.0/0 entry
    (_rule_subnet_egress_blackhole) or about the diagnostic TARGET's own route
    (_rule_blackhole_route). Neither can see a blackhole on a specific destination
    prefix, which is the one that WINS under longest-prefix match. Reuses pattern_id
    `blackhole_route`; the per-route classification is done once, in the check
    (cluster_start_checks.classify_blackhole_route), so this rule adds no second
    implementation of "what does this prefix cover".
    """
    # A UDR blackhole is a customer-data-plane-VNET conclusion, so it takes the same
    # plane predicate as every other one. It is the only rule that discovers its input
    # by SCANNING every check's metadata rather than naming check keys, which means the
    # orchestrator's per-check gate cannot protect it: the day any serverless-reachable
    # check starts carrying `blackholes`, an ungated rule would prescribe a route-table
    # edit on a VNet the workload does not use. Today no serverless-reachable check
    # produces that metadata, so this guard changes nothing observable — it closes the
    # same escape route `dns_pe_alignment` took, before it is used.
    if not is_data_plane_vnet(context):
        return None
    hits, seen = [], set()
    for name, c in (checks or {}).items():
        for bh in ((getattr(c, "metadata", None) or {}).get("blackholes") or []):
            if bh.get("is_default_route"):
                continue     # owned by _rule_subnet_egress_blackhole / _rule_blackhole_route
            if bh.get("verdict") not in ("required", "unverified"):
                continue
            table = ((c.metadata or {}).get("route_table_id") or "").split("/")[-1]
            key = (table, bh.get("name"), bh.get("prefix"))
            if key in seen:
                continue     # same table reached via the public AND private subnet check
            seen.add(key)
            hits.append((name, c, bh, table or "the route table"))
    if not hits:
        return None
    proven = [h for h in hits if h[2].get("verdict") == "required"]
    lead = proven or hits
    routes_txt = "; ".join("'%s' (prefix %s) in route table '%s'" % (bh.get("name"),
                                                                    bh.get("prefix"), table)
                           for _n, _c, bh, table in lead)
    covers = sorted({lbl for _n, _c, bh, _t in lead for lbl in (bh.get("covers") or [])})
    _w = [(bh.get("why") or "") for _n, _c, bh, _t in lead]
    whys = " ".join((w[:1].upper() + w[1:]) if w else "" for w in _w)
    # Only assert that the firewall is bypassed when a forced tunnel is actually present
    # in the same check's metadata (never narrate an observation nothing made).
    _dr = (lead[0][1].metadata or {}).get("default_route") or {}
    if _dr.get("next_hop_type") == "VirtualAppliance":
        _wins = ("Azure applies LONGEST-PREFIX MATCH, so this route WINS over the subnet's 0.0.0.0/0 "
                 "route to the NVA/firewall at %s: the packets never reach the appliance, and a fully "
                 "correct firewall allow-list cannot compensate. "
                 % (_dr.get("next_hop_ip") or "the appliance"))
    elif _dr:
        _wins = ("Azure applies LONGEST-PREFIX MATCH, so this route WINS over the subnet's 0.0.0.0/0 "
                 "route (-> %s). " % _dr.get("next_hop_type"))
    else:
        _wins = ("A UDR overrides Azure's own system route for the prefix it names, so this prefix is "
                 "black-holed even though the table has no 0.0.0.0/0 entry. ")
    return Diagnosis(
        pattern_id="blackhole_route",
        title=("Blackhole Route Drops a Destination the Cluster Bootstrap Requires"
               if proven else
               "Blackhole Route on Public Address Space — Coverage Unverified"),
        severity=Severity.CRITICAL if proven else Severity.HIGH,
        confidence="high" if proven else "medium",
        root_cause=(
            "A user-defined route with next hop 'None' (a blackhole) silently drops traffic to a "
            f"destination this workspace must reach: {routes_txt}. {whys} "
            + (f"Dropped destination(s): {'; '.join(covers)}. " if covers else "")
            + _wins
            + "Blackholed packets are discarded with no ICMP, so the symptom is a connection TIMEOUT "
              "(curl 28) rather than a TLS or HTTP error."
            + ("" if proven else " Coverage of a Databricks-required destination could not be "
                                 "proven from ARM, so this is a candidate, not a confirmed cause.")
        ),
        evidence=[(name, c.message) for name, c, _bh, _t in lead],
        prescription=([lead[0][1].recommendation] if lead[0][1].recommendation else []) + [
            "Then re-check the route table for ANY other next-hop-'None' entry — Azure evaluates "
            "every route, so one blackhole hidden behind a correct default route is enough to "
            "break a single destination while everything else looks healthy.",
        ],
        fix_order=1,
        layer="classic-vnet",
    )


def _rule_internet_route_private_target(checks):
    """DNS resolves to private IP + Routes next_hop=Internet => wrong UDR."""
    dns = _find(checks, "dns")
    routes = _find(checks, "routes")
    if not _has_status(dns, Status.PASS):
        return None
    if not _has_status(routes, Status.FAIL):
        return None
    ips = _resolved_ips(dns)
    if not ips or not _is_private_ip(ips[0]):
        return None
    if _meta(routes, "next_hop") != "Internet":
        return None
    table = _meta(routes, "table", "unknown")
    return Diagnosis(
        pattern_id="internet_route_private_target",
        title="UDR Sends Private Traffic to Internet",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            f"DNS resolves to private IP {ips[0]} but the UDR sends traffic for this range to the Internet. "
            "Private IPs are not routable on the internet so traffic is dropped."
        ),
        evidence=[
            ("dns", f"Resolved to private IP {ips[0]}"),
            ("routes", routes.message),
        ],
        prescription=[
            f"Azure Portal > Route tables > {table} > Routes.",
            "Change the route from 'Internet' to 'Virtual Network Gateway' or 'VnetLocal' depending on topology.",
        ],
        fix_order=1,
    )


def _rule_egress_peering_unreachable(checks, context=None):
    """Forced-tunnel next hop is unreachable because no Connected peering carries it.

    topology.trace() can now fail with blocking_gate.kind == "peering" (the appliance
    lives outside this VNet and no peering is Connected). Without this rule that FAIL
    produced NO diagnosis at all, so `_rule_all_healthy` still fired — live on
    In the field the Doctor told a customer "connectivity is healthy" with high confidence
    while the spoke→hub peering was deleted and every packet was being black-holed.

    Unlike the probe-driven `peering_broken` hypothesis, this one is VERIFIED from the
    topology graph (the route's next hop is outside every reachable address space), so
    it is asserted with high confidence and does NOT need customer confirmation.
    """
    trace = None
    tcheck = _find(checks, "topology_egress_path")
    # A peer_vnet_unreadable verdict is a WARN, not a FAIL, so read either status.
    if _has_status(tcheck, Status.FAIL) or _has_status(tcheck, Status.WARN):
        trace = (tcheck.metadata or {}).get("trace")
    if trace is None and context:
        ct = context.get("topology_trace")
        if ct and ct.get("status") in ("fail", "warn"):
            trace = ct
    gate = (trace or {}).get("blocking_gate") or {}
    kind = gate.get("kind")
    nva = gate.get("nva_ip", "")
    _src = "topology_egress_path" if (tcheck is not None) else "topology_trace"

    # A Connected peering whose peer (hub) VNet was unreadable: the reachability of the
    # forced-tunnel next hop is UNPROVEN, not broken. Assert a degraded MEDIUM/low note —
    # NEVER the CRITICAL "recreate the peering", which would send the customer to rebuild a
    # peering that is Connected and healthy (the SP simply lacks Reader on the hub).
    if kind == "peer_vnet_unreadable":
        return Diagnosis(
            pattern_id="forced_tunnel_leg_unproven",
            title="Forced-tunnel egress leg UNPROVEN — hub VNet unreadable (peering IS Connected)",
            severity=Severity.MEDIUM,
            confidence="low",
            needs_confirmation=False,
            root_cause=((trace or {}).get("reason")
                        or f"a Connected peering exists but the hub VNet hosting next hop {nva} "
                           "could not be read, so this egress leg cannot be confirmed"),
            evidence=[(_src, (trace or {}).get("reason", ""))],
            prescription=([(trace or {}).get("recommendation")] if (trace or {}).get("recommendation")
                          else ["Grant the Reader Service Principal access to the hub VNet's "
                                f"subscription/resource group and re-run to confirm next hop {nva}. "
                                "Do NOT recreate the peering — it is Connected."]),
            fix_order=5,
            layer="classic-vnet",
        )

    if kind != "peering":
        return None
    return Diagnosis(
        pattern_id="peering_broken",
        title="Forced-tunnel next hop unreachable — VNet peering missing/disconnected",
        severity=Severity.CRITICAL,
        confidence="high",
        needs_confirmation=False,
        root_cause=((trace or {}).get("reason")
                    or f"the forced-tunnel next hop {nva} is unreachable because no Connected "
                       "peering joins the workspace VNet to the VNet hosting it"),
        evidence=[(_src, (trace or {}).get("reason", ""))],
        prescription=([(trace or {}).get("recommendation")] if (trace or {}).get("recommendation")
                      else ["Recreate/reconnect the VNet peering to the VNet hosting the "
                            f"forced-tunnel appliance {nva}, in both directions."]),
        fix_order=1,
        layer="classic-vnet",
    )


def _rule_egress_firewall_missing(checks, context=None):
    """UNIFIED forced-tunnel-firewall-missing-egress headline across Path A/B/C.

    Fires from a `topology_egress_path` check (FAIL, firewall gate) or a
    context-provided trace (`context['topology_trace']`). Outranks the legacy
    per-path firewall/NVA rules (precedence 12) which defer to it."""
    trace = None
    tcheck = _find(checks, "topology_egress_path")
    if _has_status(tcheck, Status.FAIL):
        trace = (tcheck.metadata or {}).get("trace")
    if trace is None and context:
        ct = context.get("topology_trace")
        if ct and ct.get("status") == "fail":
            trace = ct
    if not trace:
        return None
    # Attribute to whichever producer actually supplied the trace: the
    # topology_egress_path CHECK, or the context-carried trace on Path B.
    return make_egress_firewall_diagnosis(
        trace, source=("topology_egress_path" if _has_status(tcheck, Status.FAIL)
                       else "topology_trace"))


def _rule_nva_firewall(checks):
    """TCP FAIL + Routes to NVA => Firewall/NVA blocking."""
    # Defer to the precise, unified egress_firewall_missing headline when a topology
    # trace OR the rule-level firewall check already pinpointed the firewall gap
    # (no vague duplicate card).
    if _has_status(_find(checks, "topology_egress_path"), Status.FAIL):
        return None
    if _has_status(_find(checks, "subnet_egress_firewall"), Status.FAIL):
        return None
    tcp = _find(checks, "tcp")
    routes = _find(checks, "routes")
    if not _has_status(tcp, Status.FAIL):
        return None
    if routes is None:
        return None
    if _meta(routes, "next_hop") != "VirtualAppliance":
        return None
    nva_ip = _meta(routes, "next_hop_ip", "unknown")
    return Diagnosis(
        pattern_id="nva_firewall",
        title="NVA/Firewall in Path May Be Blocking Traffic",
        severity=Severity.HIGH,
        confidence="medium",
        root_cause=(
            f"Traffic is routed through an NVA/Firewall at {nva_ip}. "
            "The TCP failure combined with correct NSG suggests the NVA is blocking or misconfigured."
        ),
        evidence=[
            ("tcp", tcp.message),
            ("routes", routes.message),
        ],
        follow_up_questions=[
            f"What NVA/firewall appliance is running at {nva_ip}?",
            "Does it have rules allowing outbound TCP to the target IP and port?",
            "Is IP forwarding enabled on the NVA NIC in Azure Portal?",
        ],
        fix_order=2,
    )


def _rule_nva_tls_interception(checks):
    """TCP PASS + TLS FAIL (cert) + Routes to NVA => SSL interception."""
    if _has_status(_find(checks, "topology_egress_path"), Status.FAIL):
        return None  # defer to the unified egress_firewall_missing headline
    tcp = _find(checks, "tcp")
    tls = _find(checks, "tls")
    routes = _find(checks, "routes")
    if not _has_status(tcp, Status.PASS):
        return None
    if not _has_status(tls, Status.FAIL):
        return None
    if routes is None or _meta(routes, "next_hop") != "VirtualAppliance":
        return None
    nva_ip = _meta(routes, "next_hop_ip", "unknown")
    return Diagnosis(
        pattern_id="nva_tls_interception",
        title="NVA/Firewall Performing TLS Interception",
        severity=Severity.HIGH,
        confidence="high",
        root_cause=(
            f"TCP passes but TLS fails while traffic routes through NVA at {nva_ip}. "
            "The NVA is performing SSL/TLS inspection, replacing the certificate with its own."
        ),
        evidence=[
            ("tls", tls.message),
            ("routes", f"Traffic via NVA at {nva_ip}"),
        ],
        prescription=[
            f"Add an SSL inspection exception/bypass on the NVA at {nva_ip} for Databricks traffic.",
            "OR install the NVA's CA certificate in the Databricks cluster truststore (init script).",
        ],
        fix_order=1,
    )


def _rule_dns_pe_misalignment(checks, context=None):
    """DNS resolves to public IP + PE exists => traffic bypasses PE.

    CLASSIC-plane only: the "link the private DNS zone to the VNet" fix does not
    apply to serverless (NCC layer — see _rule_serverless_egress_ncc)."""
    if (context or {}).get("compute_type") == "serverless":
        return None

    # PREFERRED SOURCE: the dns_pe_alignment cross-check, which compares the
    # DNS-authoritative address against the PE IPs over the whole answer set. Consume its
    # verdict rather than re-deriving one here — a second implementation is how the
    # private-but-wrong-address case stayed invisible while the logic to catch it existed.
    align = _find(checks, "dns_pe_alignment")
    if _has_status(align, Status.FAIL):
        amd = align.metadata or {}
        pub = amd.get("public_ips") or []
        pe_ips_l = amd.get("pe_ips") or []
        if pub:
            return Diagnosis(
                pattern_id="dns_pe_misalignment",
                title="DNS Resolves to Public IP Despite Private Endpoint",
                severity=Severity.CRITICAL, confidence="high",
                root_cause=align.message,
                evidence=[("dns_pe_alignment", align.message)],
                prescription=[align.recommendation] if align.recommendation else [
                    "Link the matching privatelink.* Private DNS zone to the VNet and point the A "
                    "record at the Private Endpoint IP."],
                fix_order=1,
            )
        return Diagnosis(
            pattern_id="dns_wrong_private_target",
            title="DNS Points at a Private Address That Is Not the Private Endpoint",
            severity=Severity.CRITICAL, confidence="high",
            root_cause=align.message,
            evidence=[("dns_pe_alignment", align.message)],
            prescription=([align.recommendation] if align.recommendation else [
                f"Point the A record at a Private Endpoint IP ({', '.join(pe_ips_l) or 'the PE IP'}) "
                "and confirm the privatelink zone is linked to the resolving VNet."])
            + ["Re-run afterwards: the NSG / route / firewall findings in this report were "
               "computed against the wrong address and will change."],
            fix_order=1,
        )

    # FALLBACK for reports produced before dns_pe_alignment existed.
    dns = _find(checks, "dns")
    pe = _find(checks, "pe")
    # WARN is a successful resolution that disagreed with the local resolver.
    if not _has_status(dns, Status.PASS, Status.WARN):
        return None
    if not _has_status(pe, Status.PASS, Status.WARN):
        return None
    ips = _resolved_ips(dns)
    pe_ips = _meta(pe, "pe_ips", [])
    if not ips or not pe_ips:
        return None
    # Check if DNS resolves to a public IP (not matching PE IPs)
    has_public = any(not _is_private_ip(ip) for ip in ips)
    if not has_public:
        return None
    return Diagnosis(
        pattern_id="dns_pe_misalignment",
        title="DNS Resolves to Public IP Despite Private Endpoint",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            f"Private Endpoint exists (PE IPs: {pe_ips}) but DNS resolves to public IP {ips[0]}. "
            "Traffic bypasses the PE and goes over the public internet."
        ),
        evidence=[
            ("dns", f"Resolved to public IP {ips[0]}"),
            ("pe", f"PE private IPs: {pe_ips}"),
        ],
        prescription=[
            "Create a Private DNS zone for the appropriate privatelink.* domain "
            "(e.g., privatelink.database.windows.net for SQL).",
            "Link the zone to the Databricks VNet: Azure Portal > Private DNS zones > Virtual network links > Add.",
            f"Add an A record pointing to PE IP {pe_ips[0]}.",
            "If using custom DNS, add a conditional forwarder for privatelink.* to 168.63.129.16.",
        ],
        fix_order=1,
    )


def _rule_dns_zone_unlinked(checks):
    """DNS FAIL + dns_zones FAIL (not linked) => zone not linked to VNet."""
    dns = _find(checks, "dns")
    zones = _find(checks, "dns_zones")
    if not _has_status(dns, Status.FAIL):
        return None
    if not (_has_status(zones, Status.FAIL) and _msg_contains(zones, "not linked", "no virtual network link")):
        return None
    return Diagnosis(
        pattern_id="dns_zone_unlinked",
        title="Private DNS Zone Not Linked to VNet",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            "A Private DNS zone exists but is NOT linked to the Databricks VNet. "
            "The cluster cannot resolve the hostname via the private zone."
        ),
        evidence=[
            ("dns", dns.message),
            ("dns_zones", zones.message),
        ],
        prescription=[
            "Azure Portal > Private DNS zones > select zone > Virtual network links > Add.",
            "Select the Databricks VNet. Enable auto-registration: No.",
            "Wait 2-5 minutes for DNS propagation, then re-run diagnostics.",
        ],
        fix_order=1,
    )


def _rule_dns_fail_no_azure(checks, context=None):
    """DNS FAIL + no Azure infra checks => ask about DNS setup.

    CLASSIC-plane only: serverless compute does not use the workspace VNet's DNS,
    so a "no Azure checks / confirm your VNet DNS" headline is the WRONG PLANE for
    a serverless failure and (being CRITICAL) would outrank the correct
    serverless-plane rules. Mirror the guard in _rule_dns_fail_needs_dns_type —
    _rule_serverless_egress_ncc / the NCC rules own the serverless case."""
    if (context or {}).get("compute_type") == "serverless":
        return None
    dns = _find(checks, "dns")
    nsg = _find(checks, "nsg")
    zones = _find(checks, "dns_zones")
    if not _has_status(dns, Status.FAIL):
        return None
    # If Azure checks ran, a more specific rule should match instead
    if nsg is not None or zones is not None:
        return None
    # If the egress network policy is the proven cause, defer to that rule.
    egress = _find(checks, "egress_policy")
    if _has_status(egress, Status.FAIL, Status.WARN):
        return None
    return Diagnosis(
        pattern_id="dns_fail_no_azure",
        title="DNS Resolution Failed (No Azure Checks Available)",
        severity=Severity.HIGH,
        confidence="low",
        root_cause="DNS resolution failed. Without Azure infrastructure checks, the root cause cannot be determined.",
        evidence=[("dns", dns.message)],
        follow_up_questions=[
            "What DNS configuration does your VNet use? (1) Azure-default 168.63.129.16, "
            "(2) Custom DNS server, (3) Azure DNS Private Resolver. (I only need WHICH of the three "
            "— not the DNS server's IP; that detail is not actionable from here.)",
            "Providing an Azure Service Principal would enable deeper infrastructure checks.",
        ],
        fix_order=1,
    )


def _rule_serverless_egress_ncc(checks, context=None):
    """SERVERLESS layer rule: connectivity failure from serverless is an NCC
    (Serverless Egress Controls) matter — NEVER a workspace-VNet DNS/NSG/peering
    matter. Serverless compute runs in Databricks-managed infrastructure outside
    the customer VNet (field feedback; an earlier prescription
    is the template).
    """
    if (context or {}).get("compute_type") != "serverless":
        return None
    dns = _find(checks, "dns")
    tcp = _find(checks, "tcp")
    if not (_has_status(dns, Status.FAIL) or _has_status(tcp, Status.FAIL)):
        return None

    # DEFER when the egress network policy already PROVED the cause (seen in a real run:
    # this umbrella rule and _rule_egress_policy_blocks both fired for
    # the same pypi.org run, so the report showed two serverless diagnoses for one
    # cause). _rule_egress_policy_blocks (FAIL) / _rule_egress_policy_dry_run (WARN)
    # are more specific — they name the policy and the exact missing allow-list
    # entry — so this general rule steps aside and lets them be the single headline.
    egress = _find(checks, "egress_policy")
    if _has_status(egress, Status.FAIL, Status.WARN):
        return None

    # DEFER to the more specific NCC rules too, so one cause never renders two
    # serverless cards. _rule_ncc_missing owns "no NCC attached" (ncc_attach FAIL);
    # _rule_ncc_pe_missing owns "NCC attached but no PE rule" (ncc_attach PASS +
    # ncc_pe FAIL). This umbrella stays as the FALLBACK when none of the specific
    # rules apply (e.g. no NCC checks ran at all — pure public-egress case).
    ncc_attach = _find(checks, "ncc_attach")
    ncc_pe = _find(checks, "ncc_pe")
    if _has_status(ncc_attach, Status.FAIL):
        return None  # ncc_missing owns it
    if _has_status(ncc_attach, Status.PASS) and _has_status(ncc_pe, Status.FAIL):
        return None  # ncc_pe_missing owns it

    host = (getattr(dns, "target", "") or getattr(tcp, "target", "") or "the target").split(":")[0]
    pe = _find(checks, "pe")
    ncc_inspected = any(_account_row_was_read(c) for c in (ncc_attach, ncc_pe, egress))
    account_unread = any(_account_row_is_unread(c) for c in (ncc_attach, ncc_pe, egress))

    # `check_private_endpoints` reads a whole RG, but only its target-attributed subset
    # can establish that THIS hostname is private-linked. A generic `pe_ips` inventory
    # from an older/unattributed row is intentionally insufficient.
    target_private = bool(
        pe is not None
        and _meta(pe, "target_attribution_available", False)
        and int(_meta(pe, "pe_count", 0) or 0) > 0
    )
    evidence = [(c.check_name, c.message) for c in (dns, tcp, pe, ncc_attach, ncc_pe, egress) if c is not None]

    # NOMENCLATURE (field feedback): the customer-facing control for
    # serverless egress is the account-level **Network policy** (Account Console >
    # Security > Context based ingress and egress — verified against the live console;
    # the old "Security > Network policies" route no longer exists), which has
    # an **Egress** tab with **Egress rules**. A PUBLIC destination (the majority case —
    # pypi.org, login.microsoftonline.com, etc.) is allowed by adding it to Egress rules >
    # Allowed domains (Type DNS_NAME); it has NOTHING to do with Private Endpoints. Private Endpoints
    # / NCC rules are ONLY relevant when the target is private-linked. So this rule
    # branches on target_private: never say "NCC / private-endpoint" for a public host.
    root = (
        f"The failure is on SERVERLESS compute, which runs in Databricks-managed "
        f"infrastructure OUTSIDE the workspace VNet — it does not use the VNet's DNS, "
        f"NSGs, routes, or peerings. Serverless egress to {host} is governed by the "
        f"workspace's account-level Network policy (Egress rules)"
        + (" and, for private-linked targets, the NCC private endpoint rules." if target_private
           else " — and since this target is a PUBLIC endpoint, by the Egress rules "
                 "(Allowed internet destinations), NOT by any Private Endpoint / NCC rule.")
    )

    prescription = None
    if account_unread:
        # The account API did not establish attachment, PE-rule, or network-policy
        # state. Keep the correct governing layer as the diagnosis, but make the
        # already-generated read-only hand-off the primary next step. In particular,
        # never turn `not PASS` into "no NCC attached" — absence requires the explicit
        # readable FAIL emitted by `check_ncc_attached`, which is handled by
        # `_rule_ncc_missing` before this fallback rule.
        root += (
            " The Databricks account layer is UNKNOWN / NOT READ in this run. This is "
            "not evidence that an NCC is absent, that its private-endpoint rule is "
            "missing, or that the Network policy allows or blocks this destination."
        )
        prescription = [
            "Do not create, attach or change an NCC from this result: the account state "
            "was not read.",
            "Use the preferred read-only account-snapshot hand-off in the account-layer "
            "NOT READ row: an existing Databricks account admin runs the generated "
            "five-GET script, which changes nothing and uploads account_dump.json.",
            "Then provide that snapshot path in a fresh notebook so the Doctor can finish "
            "the account-layer diagnosis without repeating the probes.",
        ]
        return Diagnosis(
            pattern_id="serverless_egress_ncc",
            title="Serverless Egress — Account Network State Not Read",
            severity=Severity.HIGH,
            confidence="medium",
            root_cause=root,
            evidence=evidence,
            prescription=prescription,
            fix_order=1,
        )

    if target_private:
        # PRIVATE-LINKED target: NCC private-endpoint rules are the right layer, and
        # if a restricted Network policy is in place the target FQDN must ALSO be in
        # the Egress rules. Affirm the NCC state when it was actually inspected.
        root += (f" The target appears to be private-linked (private endpoint(s) found), "
                 f"the classic signature of a missing/unapproved NCC private-endpoint rule "
                 f"for {host} (and, if the Network policy is restricted, a missing Egress rule "
                 f"for its DNS name).")
        if ncc_inspected:
            attach_ok = _has_status(ncc_attach, Status.PASS)
            rule_ok = _has_status(ncc_pe, Status.PASS)
            if not attach_ok:
                root += (" NCC VERDICT: no NCC attached, so serverless has no private "
                         "connectivity path to the target at all.")
                prescription = [
                    "NCC VERDICT: ✗ no NCC attached to this workspace.",
                    "1. Account Console > Cloud resources > Network Connectivity Configurations > "
                    "create an NCC in the workspace's region (or pick the existing one) and attach "
                    "it to this workspace.",
                    f"2. In the NCC > Private endpoint rules > add a rule for {host}'s resource id "
                    "with the right sub-resource (e.g. sqlServer / dfs / blob), then APPROVE the "
                    "pending private endpoint on the target (Azure Portal > resource > Networking > "
                    "Private endpoint connections) and wait for ESTABLISHED.",
                    "3. If a restricted Network policy is attached, also add the target's DNS name "
                    "under Security > Context based ingress and egress > the policy > Egress > Egress rules.",
                    "4. Re-test from serverless after a few minutes.",
                ]
            elif not rule_ok:
                root += (f" NCC VERDICT: an NCC IS attached, but it has no ESTABLISHED "
                         f"private-endpoint rule matching {host} (see the ncc_pe check).")
                prescription = [
                    f"NCC VERDICT: ✗ NCC attached, but the private-endpoint rule for {host} is "
                    "missing or not ESTABLISHED.",
                    "1. Account Console > Cloud resources > Network Connectivity Configurations > "
                    "the attached NCC > Private endpoint rules > add a rule for the target's "
                    "resource id with the right sub-resource (e.g. sqlServer / dfs / blob).",
                    "2. APPROVE the pending private endpoint on the target resource (Azure Portal > "
                    "resource > Networking > Private endpoint connections) and wait for ESTABLISHED.",
                    "3. Re-test from serverless after a few minutes.",
                ]
            else:
                root += (f" NCC VERDICT: attached and its private-endpoint rule for {host} is "
                         f"ESTABLISHED — so the NCC is NOT the cause; look at the target side "
                         f"(resource firewall / publicNetworkAccess) or the Egress-policy check.")
                prescription = [
                    f"NCC VERDICT: ✓ attached + ESTABLISHED rule for {host}.",
                    "The NCC is not the cause. Next: verify the TARGET resource — its firewall / "
                    "publicNetworkAccess (a private-linked target must allow the PE path) and any "
                    "recent changes; then re-check the Egress-policy result if present.",
                    "If the target side is clean too, capture the exact error and timestamps for a "
                    "Databricks support ticket — the NCC layer has been verified working.",
                ]
        prescription = prescription or [
            "Target is private-linked, so work at the NCC private-endpoint layer:",
            "1. Account Console > Cloud resources > Network Connectivity Configurations > confirm an "
            "NCC is attached to this workspace.",
            f"2. NCC > Private endpoint rules > add a rule for {host}'s resource id (right "
            "sub-resource, e.g. sqlServer / dfs / blob), then APPROVE the pending private endpoint "
            "on the target and wait for ESTABLISHED.",
            "3. If a restricted Network policy is attached, also add the target's DNS name under "
            "Security > Context based ingress and egress > the policy > Egress > Egress rules.",
            "4. Re-test from serverless after the rule is ESTABLISHED (allow a few minutes).",
        ]
    else:
        # PUBLIC target: the control is Network policy > Egress > Egress rules. Never
        # mention Private Endpoints here.
        ncc_err = (context or {}).get("ncc_inspection_error")
        if ncc_err:
            root += (f" NOTE: the Network policy egress rules were REQUESTED for inspection but "
                     f"could not be read — {ncc_err} Until then, this serverless root cause is a "
                     f"HYPOTHESIS: any VNet-level findings in this report are CLASSIC-plane only "
                     f"and do not explain the serverless failure.")
        elif not ncc_inspected:
            root += (" NOTE: I could not inspect the account-level Network policy (no account-admin "
                     "credentials provided) — any VNet-level findings here describe the CLASSIC "
                     "plane only and do not explain the serverless failure.")
        prescription = [
            "Public egress is controlled by the account-level Network policy — the workspace VNet's "
            "DNS/NSG/peering settings do NOT apply to serverless:",
            "1. Account Console > Security > Context based ingress and egress > the policy attached to this "
            "workspace > Egress tab.",
            "2. If Network access = 'Restricted access to specific destinations', add the target "
            f"under Egress rules > Allowed internet destinations: destination = {host}, Type = "
            "DNS_NAME (or its registrable parent suffix to cover related hosts).",
            "3. Check Policy enforcement mode — if it is 'Enforced', the destination is hard-blocked "
            "until allow-listed; 'Dry run' only logs (system.access.network_outbound).",
            "4. Save and re-test from serverless after a few minutes (egress changes are not "
            "instantaneous).",
        ]

    return Diagnosis(
        pattern_id="serverless_egress_ncc",
        title=("Serverless Egress Blocked by the Network Policy (Egress Rules)" if not target_private
               else "Serverless Egress to a Private-Linked Target (NCC / Egress Rules)"),
        severity=Severity.HIGH,
        confidence="high" if (ncc_inspected or target_private) else "medium",
        root_cause=root,
        evidence=evidence,
        prescription=prescription,
        fix_order=1,
    )


def _rule_dns_fail_needs_dns_type(checks, context=None):
    """DNS FAIL, Azure checks ran, but no specific zone/PE rule pinned the cause.

    DNS failed (correct), but the ROOT CAUSE and FIX differ entirely depending on
    whether the VNet uses custom DNS, Azure-provided DNS (168.63.129.16), or an
    Azure DNS Private Resolver. The skill cannot determine which from probes/ARM
    alone, so it must ASK before asserting a final DNS diagnosis. This guards
    against the field failure where the skill assumed "custom DNS server in
    the peered network" without confirming.

    CLASSIC-plane only: serverless compute does not use the workspace VNet's DNS,
    so the VNet DNS-architecture question is the wrong layer for a serverless
    problem (field feedback) — _rule_serverless_egress_ncc covers it.
    """
    if (context or {}).get("compute_type") == "serverless":
        return None
    dns = _find(checks, "dns")
    if not _has_status(dns, Status.FAIL):
        return None
    # Defer to the no-Azure variant when no Azure infra checks are available.
    nsg = _find(checks, "nsg")
    zones = _find(checks, "dns_zones")
    if nsg is None and zones is None:
        return None
    # If a Private DNS zone exists but is simply unlinked, that's a verified cause.
    if _has_status(zones, Status.FAIL) and _msg_contains(zones, "not linked", "no virtual network link"):
        return None
    # If the egress network policy is the proven cause, defer to that rule.
    egress = _find(checks, "egress_policy")
    if _has_status(egress, Status.FAIL, Status.WARN):
        return None
    host = getattr(dns, "target", "") or "the target"
    return Diagnosis(
        pattern_id="dns_fail_needs_dns_type",
        title="DNS Resolution Failed (DNS architecture must be confirmed)",
        severity=Severity.HIGH,
        confidence="low",
        needs_confirmation=True,
        root_cause=(
            f"DNS resolution for {host} failed from the Databricks VNet. The root cause and the fix "
            "differ entirely depending on the VNet's DNS architecture (custom DNS server vs "
            "Azure-provided 168.63.129.16 vs Azure DNS Private Resolver). The diagnostic cannot "
            "determine which is in use, so this must be confirmed with the customer before a final "
            "DNS root cause is asserted — do NOT assume a custom DNS server."
        ),
        evidence=[("dns", dns.message)],
        follow_up_questions=[
            "What DNS configuration does your Databricks VNet use? (1) Azure-provided DNS "
            "(168.63.129.16, the default), (2) a custom DNS server, or (3) Azure DNS "
            "Private Resolver. The fix depends entirely on this answer. (I only need WHICH of the "
            "three — I do NOT need the DNS server's IP address; I cannot reach into your DNS server, "
            "so that detail would not change the recommendation.)",
        ],
        # Once the customer answers WHICH architecture, the skill must FINALIZE with the
        # matching recommendation below — it must NOT ask a further un-actionable question
        # (e.g. "what is the custom DNS server IP?"). These are the three final answers, keyed
        # by architecture. The agent selects the one matching the customer's reply.
        prescription=[
            "FINAL RECOMMENDATION — select the line matching the DNS architecture the customer confirms:",
            "(1) Azure-provided DNS (168.63.129.16): for PRIVATE Azure resources, ensure the relevant "
            "Azure Private DNS zone (e.g. privatelink.database.windows.net for SQL, privatelink.blob/"
            "dfs.core.windows.net for storage) is linked to the Databricks VNet via Azure Portal > "
            "Private DNS zones > <zone> > Virtual network links > Add. For on-prem / corporate names "
            "(e.g. corp.internal), Azure-provided DNS alone CANNOT resolve them — the VNet needs a "
            "custom DNS server or an Azure DNS Private Resolver that forwards that zone.",
            "(2) Custom DNS server: verify the custom DNS server has a conditional forwarder for the "
            "target's zone (e.g. corp.internal, and the privatelink.* zones for any private endpoints) "
            "pointing at the correct resolver — 168.63.129.16 for Azure-internal / privatelink zones, "
            "or the authoritative on-prem DNS for corporate zones — AND that the forwarder target is "
            "reachable from the Databricks VNet. (The skill cannot reach into the DNS server, so apply "
            "this on the DNS server itself; no IP needs to be shared here.)",
            "(3) Azure DNS Private Resolver: check the Private Resolver's inbound endpoint and its "
            "forwarding ruleset for the target's zone — confirm a forwarding rule exists for that zone, "
            "its target DNS IPs are correct and reachable, and the ruleset is linked to the Databricks VNet.",
        ],
        fix_order=1,
    )


def _rule_peering_broken(checks):
    """TCP FAIL + Peering not Connected."""
    tcp = _find(checks, "tcp")
    peering = _find(checks, "peering")
    if not _has_status(tcp, Status.FAIL):
        return None
    if not _has_status(peering, Status.FAIL):
        return None
    # Discriminate on STRUCTURED metadata, not on substring-matching the message: the
    # message is only "N peering issue(s) found", so the old `_msg_contains` guard never
    # matched and this rule fired for peerings that were actually Connected in the
    # field. Only claim "not Connected" when a peering really is not Connected.
    not_connected = _meta(peering, "not_connected")
    if isinstance(not_connected, list) and not not_connected:
        return None  # nothing is disconnected — _rule_peering_no_forwarding owns this
    if _msg_contains(peering, "forwarded traffic", "allow_forwarded"):
        return None  # Handled by _rule_peering_no_forwarding
    first = (not_connected or [{}])[0] if isinstance(not_connected, list) else {}
    peering_name = (first.get("name") if isinstance(first, dict) else "") \
        or _meta(peering, "peering_name") or _meta(peering, "name") or "the peering"
    remote_vnet = (first.get("remote") if isinstance(first, dict) else "") \
        or _meta(peering, "remote_vnet") or ""
    remote_clause = f" Its remote VNet is '{remote_vnet}'." if remote_vnet else ""
    # IMPORTANT: We can observe that a peering is not 'Connected', but we CANNOT
    # verify from probes/ARM alone whether THIS peering is the path to the target
    # or the DNS servers. Asserting it as the #1 root cause is an unverified
    # topology assumption (the field failure on a `.corp.internal` host). Emit
    # it as a HYPOTHESIS pending customer confirmation: medium confidence, HIGH
    # (not CRITICAL) severity so it does not outrank verified findings, and an
    # explicit relevance question the agent must ask before finalizing.
    return Diagnosis(
        pattern_id="peering_broken",
        title="VNet Peering Not Connected (relevance to this target unverified)",
        severity=Severity.HIGH,
        confidence="medium",
        needs_confirmation=True,
        root_cause=(
            f"VNet peering '{peering_name}' is not in 'Connected' state.{remote_clause} This drops "
            "traffic to the VNet on the other side of THIS peering. Whether that remote VNet is "
            "actually the path to this target (or to the DNS servers that resolve it) is NOT something "
            "the diagnostic can verify — even if the remote VNet name looks suggestive, it must be "
            "confirmed with the customer before this is treated as the root cause."
        ),
        evidence=[
            ("tcp", tcp.message),
            ("peering", peering.message),
        ],
        follow_up_questions=[
            f"I found VNet peering '{peering_name}' in a non-Connected state.{remote_clause} Please "
            "confirm this peering is on the path to the target (or to your DNS servers) before I treat "
            "it as a root cause. Does this peering lead to the network where this target lives or where "
            "your DNS resolves? (If it is unrelated to this target, it is not the cause and we should "
            "look elsewhere — I am NOT assuming it just because the remote VNet name looks related.)",
        ],
        prescription=[
            "Only if the customer confirms this peering is on the path to the target/DNS:",
            "Azure Portal > Virtual networks > Databricks VNet > Peerings.",
            "Check peering state. If 'Disconnected' or 'Initiated', the remote side must also create/accept the peering.",
            "Ensure both sides reach 'Connected' state.",
        ],
        fix_order=2,
    )


def _rule_peering_no_forwarding(checks):
    """TCP FAIL + Peering FAIL (allow_forwarded_traffic off)."""
    tcp = _find(checks, "tcp")
    peering = _find(checks, "peering")
    if not _has_status(tcp, Status.FAIL):
        return None
    if not _has_status(peering, Status.FAIL):
        return None
    # Structured metadata first (the message is only a generic issue count, so the
    # substring check below can never see the detail); fall back to the old substring
    # match for reports produced by an older build.
    no_forwarding = _meta(peering, "no_forwarding")
    if isinstance(no_forwarding, list):
        if not no_forwarding:
            return None
    elif not _msg_contains(peering, "forwarded traffic", "allow_forwarded"):
        return None
    names = [d.get("name", "") for d in (no_forwarding or []) if isinstance(d, dict) and d.get("name")]
    named = ", ".join(f"'{n}'" for n in names)
    subject = f"VNet peering {named}" if named else "The VNet peering"
    return Diagnosis(
        pattern_id="peering_no_forwarding",
        title="VNet Peering Missing 'Allow Forwarded Traffic'",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            f"{subject} is Connected, but 'Allow forwarded traffic' is disabled. Traffic that a "
            "firewall/NVA or gateway in the peered VNet forwards on your behalf is dropped at the "
            "peering boundary — so with a forced-tunnel default route pointing at an appliance in "
            "that peered VNet, egress fails even when the firewall's own allow rules are correct."
        ),
        evidence=[
            ("tcp", tcp.message),
            ("peering", peering.message),
        ],
        prescription=[
            "Azure Portal > Virtual networks > Databricks VNet > Peerings > Edit.",
            "Enable 'Allow forwarded traffic'.",
            "Also verify 'Use remote gateways' is enabled if the gateway is in the hub VNet.",
            "On the hub side, ensure 'Allow gateway transit' is enabled.",
        ],
        fix_order=1,
    )


def _rule_peering_no_forwarding_latent(checks):
    """Peering FAIL (allow_forwarded_traffic OFF) while connectivity to THIS target works.

    `_rule_peering_no_forwarding` requires a TCP failure, so in the field a peering
    that ARM reported as Connected-with-forwarded-traffic-OFF produced NO diagnosis at
    all. The report then said "No diagnostic results available" for a run that had a
    FAILED check, and the chat filled the vacuum by promoting the check's recommendation
    string to a confident "Root cause" of its own invention. The engine's silence was the
    defect, so the state gets its own appropriately-tiered finding.

    Deliberately MEDIUM, not CRITICAL: with 'Allow forwarded traffic' off, traffic to
    hosts INSIDE the directly-peered VNet still flows (the peering itself carries it) —
    what breaks is anything the peer FORWARDS on your behalf, i.e. an NVA/firewall or
    gateway hop in that VNet. So this is a latent best-practice gap that becomes an
    outage the moment egress is forced through an appliance over this peering, not a
    present outage.
    """
    peering = _find(checks, "peering")
    if not _has_status(peering, Status.FAIL):
        return None
    no_forwarding = _meta(peering, "no_forwarding")
    if not isinstance(no_forwarding, list) or not no_forwarding:
        return None
    # If TCP failed, the CRITICAL sibling rule owns this (it can claim causation).
    if _has_status(_find(checks, "tcp"), Status.FAIL):
        return None
    names = [d.get("name", "") for d in no_forwarding if isinstance(d, dict) and d.get("name")]
    remotes = [d.get("remote", "") for d in no_forwarding if isinstance(d, dict) and d.get("remote")]
    named = ", ".join(f"'{n}'" for n in names) or "the VNet peering"
    remote_clause = f" (remote VNet: {', '.join(sorted(set(remotes)))})" if remotes else ""
    # Is a forced tunnel already pointing at an appliance? Then it is much closer to live.
    _se = _find(checks, "subnet_egress")
    _dr = ((_se.metadata or {}).get("default_route") or {}) if _se is not None else {}
    forced = _dr.get("next_hop_type") == "VirtualAppliance"
    return Diagnosis(
        pattern_id="peering_no_forwarding_latent",
        title="VNet Peering Has 'Allow Forwarded Traffic' Disabled (latent — not blocking this target)",
        severity=Severity.MEDIUM,
        confidence="high",
        needs_confirmation=False,
        root_cause=(
            f"VNet peering {named}{remote_clause} is Connected, but 'Allow forwarded traffic' is "
            "disabled. Connectivity to this target is currently working, so this is NOT the cause "
            "of the reported symptom: a peering carries traffic addressed to the peered VNet "
            "itself regardless of this setting. What it blocks is traffic the peer FORWARDS on "
            "your behalf — an NVA, Azure Firewall or gateway hop living in that VNet."
            + (" This matters here: the data-plane subnet's default route already forces "
               f"0.0.0.0/0 through an appliance at {_dr.get('next_hop_ip') or 'the peer'}, so any "
               "flow that has to be forwarded by it will be dropped at the peering boundary even "
               "though the appliance's own rules are correct."
               if forced else
               " It becomes an outage the moment egress is forced through an appliance in that "
               "peered VNet (a 0.0.0.0/0 UDR to a hub firewall is the common trigger).")
        ),
        evidence=[("peering", peering.message)],
        prescription=[
            "Azure Portal > Virtual networks > Databricks VNet > Peerings > "
            + (names[0] if names else "the peering") + " > enable 'Allow forwarded traffic'.",
            "Enable it on BOTH sides of the peering — the setting is per-direction.",
            "Also confirm 'Use remote gateways' / 'Allow gateway transit' if a gateway or "
            "firewall in the hub is meant to serve this VNet.",
        ],
        fix_order=3,
        layer="classic-vnet",
    )


def _rule_ncc_missing(checks):
    """NCC not attached on serverless."""
    ncc = _find(checks, "ncc_attach")
    if not _has_status(ncc, Status.FAIL):
        return None
    return Diagnosis(
        pattern_id="ncc_missing",
        title="No Network Connectivity Configuration (NCC) Attached",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            "The workspace has no NCC attached. Serverless compute therefore has no PRIVATE network "
            "path — it can only reach PUBLIC endpoints (and even those are still subject to the "
            "account-level Network policy egress rules)."
        ),
        evidence=[("ncc_attach", ncc.message)],
        prescription=[
            "Only needed for PRIVATE-LINKED targets — a public destination is governed by the "
            "Network policy (Security > Context based ingress and egress > Egress), not the NCC:",
            "1. Account Console > Cloud resources > Network Connectivity Configurations > create an "
            "NCC for the workspace's region and attach it to this workspace.",
            "2. In the NCC > Private endpoint rules > add a rule for each private target resource.",
            "3. Approve the pending private endpoint on the target side and wait for ESTABLISHED.",
        ],
        fix_order=1,
    )


def _rule_ncc_pe_pending(checks):
    """NCC PE rule PENDING."""
    ncc_pe = _find(checks, "ncc_pe")
    if ncc_pe is None:
        return None
    if not _msg_contains(ncc_pe, "PENDING"):
        return None
    return Diagnosis(
        pattern_id="ncc_pe_pending",
        title="NCC Private Endpoint Rule Pending Approval",
        severity=Severity.HIGH,
        confidence="high",
        root_cause="NCC PE rule exists but is pending approval on the target resource.",
        evidence=[("ncc_pe", ncc_pe.message)],
        prescription=[
            "Azure Portal > target resource > Networking > Private endpoint connections.",
            "Find the pending connection and approve it.",
            "Wait 2-5 minutes, then re-run diagnostics.",
        ],
        fix_order=1,
    )


def _rule_egress_policy_blocks(checks):
    """Serverless egress network policy is hard-blocking the target FQDN/storage."""
    ep = _find(checks, "egress_policy")
    if not _has_status(ep, Status.FAIL):
        return None
    md = ep.metadata or {}
    policy_id = md.get("network_policy_id", "?")
    kind = md.get("target_kind", "")
    if kind == "azure_storage":
        missing = (
            f"{md.get('target_storage_account','?')}/{md.get('target_storage_service','?')}"
        )
        cause = (
            f"Serverless egress is blocked by the account Network policy '{policy_id}' "
            f"(Network access = 'Restricted access to specific destinations', Policy enforcement mode "
            f"= 'Enforced'). The storage destination '{missing}' is not in the policy's Egress rules "
            f"(Allowed storage destinations), so serverless cannot reach it."
        )
        add_step = (
            "Egress rules > storage destinations > Add destination > add the missing storage account "
            f"+ service ({missing})."
        )
    else:
        cause = (
            f"Serverless egress is blocked by the account Network policy '{policy_id}' "
            f"(Network access = 'Restricted access to specific destinations', Policy enforcement mode "
            f"= 'Enforced'). The target's DNS name is not covered by any entry in the policy's Egress "
            f"rules (Allowed internet destinations), so serverless cannot reach it."
        )
        _companion = companion_egress_clause(md.get("target_host", ""))
        add_step = (
            "Egress rules > Allowed domains > Add destination > add the target (Type = DNS_NAME; use "
            "its registrable parent suffix to cover related hosts). Leave 'Network access' on "
            "'Restricted access to specific destinations' — you are adding one destination, not "
            "opening the policy up."
            + (f" {_companion}" if _companion else "")
        )
    return Diagnosis(
        pattern_id="egress_policy_blocks",
        title="Serverless Egress Blocked by the Network Policy (Egress Rules)",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=cause,
        evidence=[("egress_policy", ep.message)],
        prescription=[
            f"Account Console > Security > Context based ingress and egress > open the workspace "
            f"network policy '{policy_id}' (the one attached to this workspace) > Egress tab.",
            add_step,
            "Save. Egress changes propagate to serverless within a few minutes (not instantaneous).",
            "Re-run the diagnostic; the same failing target should now PASS.",
        ],
        follow_up_questions=[
            "Are other destinations from the same provider (same parent domain) also failing?",
        ],
        fix_order=1,
    )


def _rule_egress_policy_dry_run(checks):
    """Egress policy would block but is in DRY_RUN — surface as HIGH, not CRITICAL."""
    ep = _find(checks, "egress_policy")
    if not _has_status(ep, Status.WARN):
        return None
    md = ep.metadata or {}
    if md.get("enforcement_mode") != "DRY_RUN":
        return None
    policy_id = md.get("network_policy_id", "?")
    filt = md.get("dry_run_product_filter", []) or []
    scope = f"products: {','.join(filt)}" if filt else "all products"
    return Diagnosis(
        pattern_id="egress_policy_dry_run_violation",
        title="Egress Network Policy Violation (Dry-Run — Logged, Not Blocked)",
        severity=Severity.HIGH,
        confidence="high",
        root_cause=(
            f"Account network policy '{policy_id}' would block this destination, but enforcement_mode=DRY_RUN "
            f"for {scope}. Traffic is currently passing AND being logged in "
            f"system.access.network_outbound. If serverless compute still cannot reach the target, the cause "
            f"is not this policy (it is only logging) — look at the target's OWN firewall / "
            f"publicNetworkAccess or the account Network policy's Egress rules (Allowed internet "
            f"destinations). Serverless does NOT use the workspace VNet's NSG or DNS, so those are the wrong "
            f"plane here."
        ),
        evidence=[("egress_policy", ep.message)],
        prescription=[
            f"Account Console > Security > Context based ingress and egress > '{policy_id}' > Egress > "
            "Egress rules > Allowed domains > Add destination (Type = DNS_NAME) — add the target BEFORE "
            "switching Policy enforcement mode from 'Dry run' to 'Enforced for all products'."
            + (f" {companion_egress_clause(md.get('target_host', ''))}"
               if companion_egress_clause(md.get("target_host", "")) else ""),
            "Query system.access.network_outbound (filter on workspace_id and the target's DNS name) to "
            "confirm the violation log.",
            "If the customer expects blocking behavior, set Policy enforcement mode = 'Enforced' after "
            "the allow-list is complete.",
        ],
        fix_order=1,
    )


def _rule_ncc_pe_missing(checks):
    """NCC attached + no PE rule."""
    ncc = _find(checks, "ncc_attach")
    ncc_pe = _find(checks, "ncc_pe")
    if not _has_status(ncc, Status.PASS):
        return None
    if not _has_status(ncc_pe, Status.FAIL):
        return None
    return Diagnosis(
        pattern_id="ncc_pe_missing",
        title="NCC Missing Private Endpoint Rule for Target",
        severity=Severity.HIGH,
        confidence="medium",
        root_cause="NCC is attached but has no private endpoint rule for this target resource.",
        evidence=[
            ("ncc_attach", ncc.message),
            ("ncc_pe", ncc_pe.message),
        ],
        follow_up_questions=[
            "What Azure resource type is the target? (SQL Server, Storage, Cosmos DB, etc.)",
            "Which Azure subscription and resource group contain the target resource?",
        ],
        fix_order=2,
    )


# ---------------------------------------------------------------------------
# NHC / Cluster-start failure rules
# ---------------------------------------------------------------------------

def _nhc_signals(checks):
    nhc_check = _find(checks, "nhc_parse")
    if nhc_check is None:
        return None
    md = nhc_check.metadata or {}
    if not md.get("is_nhc"):
        return None
    return md.get("signals", {}) or {}


def _rule_nhc_private_link_only_no_pe(checks):
    """NHC 401 + publicNetworkAccess=Disabled with no in-VNet PE."""
    sig = _nhc_signals(checks)
    if sig is None or not sig.get("workspace_401"):
        return None
    pl = _find(checks, "ws_private_link")
    if not _has_status(pl, Status.FAIL):
        return None
    return Diagnosis(
        pattern_id="nhc_private_link_only_no_pe",
        title="Workspace is Private-Link-Only but No PE Reaches the Data-Plane VNet",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            "The workspace has publicNetworkAccess=Disabled but no front-end Private Endpoint is "
            "reachable from the data-plane VNet. NHC bootstrap hits the public front door and gets "
            "401 'privacy settings disallow access'."
        ),
        evidence=[
            ("nhc_parse", "Workspace front door returned 401"),
            ("ws_private_link", pl.message),
        ],
        prescription=[
            pl.recommendation or
            "Create a front-end Private Endpoint for the workspace in (or peered to) the data-plane "
            "VNet, approve it, and link the privatelink.azuredatabricks.net Private DNS zone to that "
            "VNet.",
            "Alternatively re-enable publicNetworkAccess if Private Link is not actually required.",
        ],
        fix_order=1,
    )


def make_forced_tunnel_firewall_diagnosis(fw, check_name, extra_evidence=None,
                                          missing_pattern_id="nhc_firewall_missing_egress",
                                          missing_title="Forced-Tunnel Firewall Is Missing "
                                                        "Required Databricks Egress"):
    """CRITICAL headline for a check_forced_tunnel_firewall_egress FAIL.

    ONE builder shared by the cluster-start (NHC) path and the connectivity path, so
    both emit the same wording, the same rule-level pattern discrimination and the same
    prescription. Writing a second copy for the connectivity path is exactly how the
    back-end-Private-Link guard regressed once already — don't.

    Returns None when `fw` is not a FAIL.
    """
    if not _has_status(fw, Status.FAIL):
        return None
    md = fw.metadata or {}
    # Distinguish the rule-level cause: an explicit Deny rule winning, or an FQDN
    # network rule that can't resolve because DNS proxy is off, vs. a plain missing
    # allow. (meta keys set by check_forced_tunnel_firewall_egress.)
    if md.get("denied"):
        pattern_id = "firewall_rule_denies_egress"
        title = "Forced-Tunnel Firewall Has a Deny Rule Blocking Required Databricks Egress"
    elif md.get("dns_proxy_blocked"):
        pattern_id = "firewall_dns_proxy_disabled"
        title = "Firewall FQDN Network Rule Needs DNS Proxy for Databricks Egress"
    else:
        pattern_id = missing_pattern_id
        title = missing_title
    return Diagnosis(
        pattern_id=pattern_id,
        title=title,
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=fw.message,
        evidence=[(check_name, fw.message)] + list(extra_evidence or []),
        prescription=([fw.recommendation] if fw.recommendation else [
            "Add the missing Databricks egress (Storage service tag / *.blob.core.windows.net and "
            "AzureDatabricks / *.azuredatabricks.net on TCP 443) to the firewall in the forced-tunnel path.",
        ]),
        fix_order=1,
    )


def _rule_nhc_firewall_missing_egress(checks):
    """Forced-tunnel UDR -> Azure Firewall whose allow-list is MISSING the
    Databricks egress the bootstrap NHC failed on.

    The UDR wins over the NSG: every packet is forced to the firewall regardless
    of NSG rules, so THIS firewall gap — not the NSG 'missing rules' — is the real
    root cause. This rule consumes check_forced_tunnel_firewall_egress (which read
    the firewall's actual rule collections and cross-checked them against the
    failed NHC destinations) and emits it as the CRITICAL headline, ahead of the
    NSG/back-end-PL diagnosis."""
    sig = _nhc_signals(checks)
    if sig is None:
        return None
    fw = _find(checks, "forced_tunnel_firewall")
    failed_hosts = ((fw.metadata or {}).get("failed_hosts") if fw else None) or []
    # evidence must be something a check actually produced. This tuple used to read
    # "NHC failed reaching: the Databricks bootstrap endpoints" whenever failed_hosts was
    # empty, i.e. it CREDITED nhc_parse with a sentence nhc_parse never emitted, on a run
    # whose signals were entirely empty. Cite the host list only when it exists; otherwise
    # fall back to the nhc_parse check's own message, and if there is nothing to cite,
    # cite nothing.
    nhc_check = _find(checks, "nhc_parse")
    if failed_hosts:
        extra = [("nhc_parse", "NHC failed reaching: " + ", ".join(failed_hosts[:4]))]
    elif nhc_check is not None and nhc_check.message:
        extra = [("nhc_parse", nhc_check.message)]
    else:
        extra = []
    return make_forced_tunnel_firewall_diagnosis(
        fw, "forced_tunnel_firewall", extra_evidence=extra,
    )


def _rule_connectivity_forced_tunnel_firewall(checks):
    """CONNECTIVITY path (no NHC): the data-plane subnet forced-tunnels to an appliance
    that does NOT permit the egress this target needs.

    Without this rule the `subnet_egress_firewall` FAIL added for an earlier defect would
    suppress `all_healthy` but name no cause, leaving the customer with a red run and no
    answer. Defers to the topology-graph headline when that already pinpointed the gap,
    so only ONE firewall card is ever emitted."""
    if _nhc_signals(checks) is not None:
        return None          # cluster-start path: _rule_nhc_firewall_missing_egress owns it
    if _has_status(_find(checks, "topology_egress_path"), Status.FAIL):
        return None          # the unified topology headline is already precise
    fw = _find(checks, "subnet_egress_firewall")
    se = _find(checks, "subnet_egress")
    return make_forced_tunnel_firewall_diagnosis(
        fw, "subnet_egress_firewall",
        extra_evidence=([("subnet_egress", se.message)] if se is not None else None),
        missing_pattern_id="egress_firewall_missing",
        missing_title="Forced-Tunnel Firewall Is Missing Required Databricks Egress",
    )


def _rule_nhc_forced_tunneling_blackhole(checks):
    """Forced-tunnel / blackhole UDR drops the bootstrap egress (storage SSL or
    www.databricks.com 403). FALLBACK to nhc_firewall_missing_egress: only fires
    when the precise firewall check did NOT already pinpoint the gap (e.g. a
    3rd-party NVA we couldn't read, or a blackhole next-hop=None)."""
    sig = _nhc_signals(checks)
    if sig is None:
        return None
    # If the firewall check pinpointed the missing rule, that CRITICAL diagnosis
    # is the headline — don't also emit this generic one.
    fw = _find(checks, "forced_tunnel_firewall")
    if _has_status(fw, Status.FAIL):
        return None
    if not (sig.get("databricks_com_403") or sig.get("databricks_com_failure")
            or sig.get("storage_ssl_error")):
        return None
    routes = _find(checks, "private_subnet_routes") or _find(checks, "public_subnet_routes")
    if routes is None:
        return None
    default_route = (routes.metadata or {}).get("default_route")
    if not default_route:
        return None
    hop = default_route.get("next_hop_type")
    if hop not in ("VirtualAppliance", "None"):
        return None
    nva_ip = default_route.get("next_hop_ip", "")
    failed_hosts = sig.get("failed_hosts", []) or []
    # Every branch below corresponds to a signal the guard above already proved present,
    # so `what` always describes an OBSERVED failure. The bare default is kept only as a
    # structural fallback and must never appear in the evidence line.
    what = ""
    if sig.get("storage_ssl_error"):
        what = "the Databricks artifact/blob STORAGE endpoints (X_NHC_STORAGE_SSL_ERROR)"
    elif sig.get("databricks_com_403") or sig.get("databricks_com_failure"):
        what = "www.databricks.com / the Databricks control plane"
    if not what:
        return None
    return Diagnosis(
        pattern_id="nhc_forced_tunneling_blackhole",
        title="Forced Tunnel / Blackhole Drops Databricks Bootstrap Egress",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            "The data-plane subnet's default route 0.0.0.0/0 sends traffic to "
            f"{('NVA/firewall at ' + nva_ip) if hop == 'VirtualAppliance' else 'a blackhole (next-hop=None)'}. "
            f"NHC failed reaching {what}"
            + (f" ({', '.join(failed_hosts[:4])})" if failed_hosts else "")
            + " — consistent with the appliance dropping/intercepting this outbound HTTPS. "
            "(Could not read the appliance's rules directly — verify the allow-list manually.)"
        ),
        evidence=[
            ("nhc_parse", "NHC egress failure: " + what),
            (("private_subnet_routes" if "private_subnet_routes" in checks else "public_subnet_routes"),
             routes.message),
        ],
        prescription=(
            [
                f"Remove or repoint the blackhole route in route table {(routes.metadata or {}).get('route_table_id', '').split('/')[-1]}.",
                "Allow default Internet routing for the bootstrap endpoints, or send 0.0.0.0/0 to a "
                "VirtualAppliance that explicitly permits outbound HTTPS to the Databricks Storage "
                "(*.blob.core.windows.net), *.azuredatabricks.net, *.databricks.com and www.databricks.com.",
            ] if hop == "None" else
            [
                f"On the NVA / firewall at {nva_ip}, allow outbound HTTPS (443) to: the Storage service "
                "tag / *.blob.core.windows.net (artifact/log/DBFS), the AzureDatabricks service tag / "
                "*.azuredatabricks.net, *.databricks.com, and www.databricks.com.",
                "Disable any TLS interception for these destinations or trust the NVA's CA on the cluster.",
            ]
        ),
        fix_order=1,
    )


def _rule_nhc_dns_private_zone_misconfigured(checks):
    """NHC 401 + private DNS zone for workspace missing or unlinked."""
    sig = _nhc_signals(checks)
    if sig is None or not sig.get("workspace_401"):
        return None
    pdns = _find(checks, "ws_private_dns")
    if not _has_status(pdns, Status.FAIL):
        return None
    return Diagnosis(
        pattern_id="nhc_dns_private_zone_misconfigured",
        title="Private DNS Zone for Workspace Missing / Unlinked",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            "Workspace runs Private-Link-only but the privatelink.azuredatabricks.net Private DNS "
            "zone is not properly linked to the data-plane VNet (or the workspace A record is "
            "missing). The cluster resolves the workspace URL to a public IP and the front door "
            "rejects the request with 401."
        ),
        evidence=[
            ("nhc_parse", "Workspace front door returned 401 over the public path"),
            ("ws_private_dns", pdns.message),
        ],
        prescription=[
            pdns.recommendation or
            "Link the privatelink.azuredatabricks.net Private DNS zone to the data-plane VNet and "
            "add an A record for the workspace pointing to the front-end PE's private IP.",
        ],
        fix_order=1,
    )


def _rule_nhc_subnet_nsg_missing_databricks_rules(checks):
    """Either subnet's NSG missing the AzureDatabricks service-tag rules during NHC."""
    nhc = _find(checks, "nhc_parse")
    if nhc is None or not (nhc.metadata or {}).get("is_nhc"):
        return None
    pub = _find(checks, "public_subnet_nsg")
    priv = _find(checks, "private_subnet_nsg")
    failed = [c for c in (pub, priv) if _has_status(c, Status.FAIL)]
    # the NSG check now returns PASS when the missing AzureDatabricks rules are the
    # documented-correct back-end-Private-Link posture, so this rule can no longer key on
    # FAIL alone — otherwise the (still useful) "look at the PL path instead" guidance
    # would vanish with the red row. Key on the posture the CHECK reported.
    expected_pl = [c for c in (pub, priv)
                   if c is not None and (c.metadata or {}).get("expected_absent_tags")]
    relevant = failed or expected_pl
    if not relevant:
        return None
    subnets = [(c.metadata or {}).get("subnet", "?") for c in relevant]
    setting = ""
    for c in relevant:
        s = (c.metadata or {}).get("required_nsg_rules_setting", "")
        if s:
            setting = s
            break

    _DOC = "https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/private-link-standard"

    # Back-end (classic compute plane) Private Link detection. When NoAzureDatabricksRules
    # is set, the missing public AzureDatabricks NSG rules can be EXPECTED rather than a
    # misconfiguration — back-end Private Link routes data-plane→control-plane traffic over
    # a databricks_ui_api private endpoint, and Microsoft documents NoAzureDatabricksRules
    # as the correct setting in that design.
    backend = _find(checks, "ws_backend_private_link")
    bmd = (backend.metadata or {}) if backend else {}
    has_backend_pe = bool(bmd.get("has_backend_pe"))
    ui_api_states = bmd.get("ui_api_pe_states") or []
    backend_pe_intended = bool(ui_api_states)  # a databricks_ui_api PE exists (any state)

    # CASE 1 — NoAzureDatabricksRules AND an Approved back-end databricks_ui_api PE exists.
    # The missing public NSG rules are EXPECTED. Do NOT recommend AllRules.
    # If the forced-tunnel firewall check already pinpointed a missing-egress root
    # cause, this NSG finding is NOT the cause and must DEFER to it (drop to INFO and
    # stop claiming "root cause is elsewhere on the PL path" — the cause is the
    # firewall). Otherwise keep the original HIGH "look at the PL path" guidance.
    if setting == "NoAzureDatabricksRules" and has_backend_pe:
        fw_egress = _find(checks, "forced_tunnel_firewall")
        firewall_is_root = _has_status(fw_egress, Status.FAIL)
        if firewall_is_root:
            return Diagnosis(
                pattern_id="nhc_subnet_nsg_backend_pl_expected",
                title="NSG 'Missing' AzureDatabricks Rules Is EXPECTED (Not the Cause — See Firewall Finding)",
                severity=Severity.INFO,
                confidence="high",
                root_cause=(
                    f"Subnet(s) {subnets} have no public AzureDatabricks service-tag NSG rules AND "
                    f"requiredNsgRules='NoAzureDatabricksRules' — but an Approved back-end Private Link "
                    f"endpoint ({', '.join(bmd.get('backend_pe_names', [])) or 'databricks_ui_api'}) is present, so "
                    "this is the DOCUMENTED-CORRECT configuration, NOT the cause. Do NOT flip to AllRules. "
                    "The actual root cause is the forced-tunnel FIREWALL missing required egress (see the "
                    "'Forced-Tunnel Firewall' finding) — the UDR forces egress through it regardless of the NSG."
                ),
                evidence=[(c.check_name, c.message) for c in relevant]
                         + ([(backend.check_name, backend.message)] if backend else []),
                prescription=[
                    "Do NOT change requiredNsgRules — NoAzureDatabricksRules is correct here.",
                    "Fix the firewall egress (the headline finding), not the NSG.",
                ],
                fix_order=2,
            )
        return Diagnosis(
            pattern_id="nhc_subnet_nsg_backend_pl_expected",
            title="NSG 'Missing' AzureDatabricks Rules Is EXPECTED (Back-end Private Link Is Configured)",
            severity=Severity.HIGH,
            confidence="high",
            root_cause=(
                f"Subnet(s) {subnets} have no public AzureDatabricks service-tag NSG rules AND "
                f"requiredNsgRules='NoAzureDatabricksRules' — but the workspace HAS an Approved back-end "
                f"(classic compute plane) Private Link endpoint ({', '.join(bmd.get('backend_pe_names', [])) or 'databricks_ui_api'}). "
                "In that design the data plane reaches the control plane (SCC relay + workspace REST API) "
                "over the private endpoint, so NoAzureDatabricksRules and the absence of those public NSG "
                "rules is the DOCUMENTED-CORRECT configuration, NOT the cause. Do NOT flip to AllRules. "
                # scoped to THIS REPORT. Stated unconditionally, this sentence told a
                # customer to go audit the Private Link path even when another card had
                # already named the real cause (a blackhole route). _supersede_correct_
                # posture_diagnoses removes it entirely in that case; the wording here is
                # for the standalone case, where the list below genuinely is the next step.
                "If nothing else in this report explains the launch failure, then the cause is "
                "further along the back-end Private Link path — check the items below."
            ),
            evidence=[(c.check_name, c.message) for c in relevant]
                     + ([(backend.check_name, backend.message)] if backend else []),
            prescription=[
                "Do NOT change requiredNsgRules — NoAzureDatabricksRules is correct here.",
                "Verify the back-end Private Link path instead:",
                "1. The databricks_ui_api private endpoint connection is Approved (it is, per this scan) "
                "and its NIC is healthy in the dedicated PE subnet of the workspace VNet.",
                "2. The privatelink.azuredatabricks.net Private DNS zone is linked to the workspace VNet "
                "(or DNS forwarding is in place for hub-spoke) and the workspace URL resolves to the PE "
                "PRIVATE IP, not a public IP — see the ws_private_dns check.",
                "3. Secure Cluster Connectivity (No Public IP) = Yes and the workspace is Premium.",
                "4. If a browser_authentication PE is also in use (front-end private UI), confirm it is "
                "Approved and DNS-integrated.",
                f"Reference: {_DOC}",
            ],
            fix_order=1,
        )

    # Past CASE 1, every remaining branch describes a REAL failure and reads `failed`.
    # If nothing actually failed we have nothing to report (defensive: CASE 1 already
    # returns for the expected-posture path, so this is unreachable today).
    if not failed:
        return None

    # CASE 2 — NoAzureDatabricksRules and NO Approved back-end PE: present three options.
    if setting == "NoAzureDatabricksRules":
        intended_note = ""
        if backend_pe_intended:
            intended_note = (
                f" NOTE: a databricks_ui_api private endpoint exists but is NOT Approved (states: "
                f"{', '.join(ui_api_states)}) — back-end Private Link appears intended but is not active; "
                "completing Option B (approve the PE + DNS integration) is likely the real fix."
            )
        frontend_names = bmd.get("frontend_pe_names") or []
        unverified_names = bmd.get("unverified_pe_names") or []
        if frontend_names:
            intended_note += (
                f" NOTE: Approved databricks_ui_api PE(s) ({', '.join(frontend_names)}) exist but OUTSIDE "
                "the data-plane VNet — likely FRONT-END (inbound) Private Link; they do NOT provide the "
                "back-end compute-plane path, so the three options below still apply."
            )
        if unverified_names:
            intended_note += (
                f" NOTE: could not verify the subnet/VNet of Approved databricks_ui_api PE(s) "
                f"({', '.join(unverified_names)}) — ARM read failed (permissions/404). If back-end Private "
                "Link IS already configured, verify the PE subnet and the privatelink.azuredatabricks.net "
                "DNS integration instead of flipping to AllRules."
            )
        option_a_caveat = (
            " (only if back-end Private Link is confirmed absent — see note above)"
            if unverified_names else ""
        )
        prescription = [
            "There are THREE legitimate ways to resolve this. Pick based on the workspace's intended design:",
            f"OPTION A (simplest, most common){option_a_caveat} — if you are NOT using or planning back-end (classic compute "
            "plane) Private Link, flip requiredNsgRules from 'NoAzureDatabricksRules' to 'AllRules' so "
            "Azure Databricks redeploys the canonical rule set (intra-VNet, AzureDatabricks 443/3306/"
            "8443-8451, Storage 443, EventHub 9093, Sql 3306, plus inbound rules if SCC is disabled):\n"
            "  az databricks workspace update -g <rg> -n <workspace> --required-nsg-rules AllRules\n"
            "Wait ~60s for redeploy + NSG propagation, then retry the cluster.",
            "OPTION B (for customers who intentionally keep NoAzureDatabricksRules / lock down public "
            "egress) — configure back-end (classic compute plane) Private Link. Create a databricks_ui_api "
            "private endpoint in a DEDICATED private-endpoint subnet of the workspace (data-plane) VNet, "
            "and integrate it with the privatelink.azuredatabricks.net Private DNS zone (link the zone to "
            "the workspace VNet, or use DNS forwarding in hub-spoke) so compute resolves the workspace URL "
            "to the PE private IP. Requires Premium + Secure Cluster Connectivity (No Public IP)=Yes + VNet "
            "injection. For an EXISTING workspace: stop all compute, set Required NSG rules to "
            "NoAzureDatabricksRules, create the databricks_ui_api PE, integrate the private DNS zone (the "
            "network update can take >15 min). With back-end Private Link in place, NoAzureDatabricksRules "
            "is CORRECT and the public AzureDatabricks NSG rules are intentionally not needed.\n"
            f"  Doc: {_DOC}",
            "OPTION C (advanced) — if you must keep NoAzureDatabricksRules WITHOUT back-end Private Link, "
            "add the AzureDatabricks service-tag outbound NSG rules manually to BOTH the host (public) and "
            "container (private) subnets per "
            "https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/vnet-inject. "
            "Rule names, priorities, ports, and source/destination service tags must all match; drift here "
            "is the most common reason the launch keeps failing after a manual fix.",
        ]
        return Diagnosis(
            pattern_id="nhc_subnet_nsg_missing_databricks_rules",
            title="Data-Plane Subnet NSG Missing Required Databricks Rules",
            severity=Severity.CRITICAL,
            confidence="high",
            root_cause=(
                f"NSG attached to subnet(s) {subnets} is missing the AzureDatabricks service-tag rules "
                "required for VNet-injected clusters, and requiredNsgRules='NoAzureDatabricksRules' with no "
                "Approved back-end (databricks_ui_api) Private Link endpoint. So the data plane has neither "
                "the public NSG egress rules NOR a private path to the control plane — the bootstrap probe "
                "is dropped and the cluster fails to launch." + intended_note
            ),
            evidence=[(c.check_name, c.message) for c in failed]
                     + ([(backend.check_name, backend.message)] if backend else []),
            prescription=prescription,
            fix_order=1,
        )

    # CASE 3 — requiredNsgRules=AllRules but rules still missing => unusual state.
    prescription = [
        "Workspace requiredNsgRules is 'AllRules' but the NSG is still missing required rules — "
        "this is unusual. Most likely cause: someone edited the NSG outside of Databricks's "
        "management OR a redeployment is in flight. Try toggling the workspace property: set "
        "requiredNsgRules to NoAzureDatabricksRules then back to AllRules to force a redeploy:\n"
        "  az databricks workspace update -g <rg> -n <workspace> --required-nsg-rules NoAzureDatabricksRules\n"
        "  az databricks workspace update -g <rg> -n <workspace> --required-nsg-rules AllRules\n"
        "If the rules still don't appear after ~2 minutes, open a Databricks support ticket — "
        "the workspace's NSG management may need manual intervention.",
        "Apply to BOTH the host (public) and container (private) subnets.",
    ]
    return Diagnosis(
        pattern_id="nhc_subnet_nsg_missing_databricks_rules",
        title="Data-Plane Subnet NSG Missing Required Databricks Rules",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            f"NSG attached to subnet(s) {subnets} is missing the AzureDatabricks service-tag rules "
            f"required for VNet-injected clusters. Workspace requiredNsgRules='{setting or 'unknown'}'. "
            "Without these rules the NHC control-plane probe is dropped at the NSG, which surfaces as "
            "a generic X_NHC_CONTROL_PLANE_HTTP_ERROR and the cluster terminates with 'Network "
            "configuration failure' before bootstrap."
        ),
        evidence=[(c.check_name, c.message) for c in failed],
        prescription=prescription,
        fix_order=1,
    )


def _rule_nhc_subnet_delegation_missing(checks):
    """Either subnet missing the Microsoft.Databricks/workspaces delegation."""
    nhc = _find(checks, "nhc_parse")
    if nhc is None or not (nhc.metadata or {}).get("is_nhc"):
        return None
    pub = _find(checks, "public_subnet_delegation")
    priv = _find(checks, "private_subnet_delegation")
    failed = [c for c in (pub, priv) if _has_status(c, Status.FAIL)]
    if not failed:
        return None
    names = [c.metadata.get("subnet", "?") for c in failed]
    return Diagnosis(
        pattern_id="nhc_subnet_delegation_missing",
        title="Data-Plane Subnet Missing Databricks Delegation",
        severity=Severity.CRITICAL,
        confidence="high",
        root_cause=(
            f"Subnet(s) {names} are not delegated to Microsoft.Databricks/workspaces. The data plane "
            "cannot place NICs and NHC fails before bootstrap."
        ),
        evidence=[(c.check_name, c.message) for c in failed],
        prescription=[
            "Azure Portal > VNet > Subnets > each Databricks subnet > Delegate subnet to a service > "
            "Microsoft.Databricks/workspaces.",
            "Save and retry the cluster start.",
        ],
        fix_order=1,
    )


def _rule_launch_failure_arm_clean(checks):
    """Recognised classic launch failure, but every ARM check PASSed.

    Fires only on the cluster-start path for a non-NHC launch failure
    (X_UnexpectedLaunchFailure / UNEXPECTED_LAUNCH_FAILURE / SERVICE_FAULT /
    "No such workerEnvironment") when the deep Azure-infra checks all came back
    clean. We must NOT silently emit "Connectivity Healthy" here — the cluster
    did fail to launch. Report honestly: the ARM checks we can run did not find a
    customer-side misconfiguration, so the next step is a closer look / escalation
    — not a confident "it's a Databricks bug" (we only assert that after the ARM
    checks actually ran, which they now have).
    """
    nhc = _find(checks, "nhc_parse")
    md = (nhc.metadata or {}) if nhc else {}
    if not md.get("is_launch_failure"):
        return None
    # Only when no infra check failed (otherwise a specific rule owns the cause).
    for name, check in checks.items():
        if name == "nhc_parse":
            continue
        if check.is_failure():
            return None
    # This card asserts "no customer-side network misconfiguration". It must be
    # UNREACHABLE while an unexplained blackhole on a required destination is present —
    # independently of the status a check happened to return, so a future re-tiering of
    # that row from FAIL to WARN cannot silently resurrect the wrong conclusion.
    for name, check in checks.items():
        for bh in ((getattr(check, "metadata", None) or {}).get("blackholes") or []):
            if bh.get("verdict") in ("required", "unverified"):
                return None
    sigs = md.get("launch_failure_signatures") or []
    # Say what actually came back clean, and name what did NOT reach a verdict. The old
    # wording listed "subnet delegation, required NSG rules, route tables / forced-tunnel,
    # egress IP, private link, DNS" unconditionally — a fixed sentence, not a fact about
    # this run — and in the field it certified the routing as clean on a run where only
    # ONE of the route table's routes had been evaluated.
    _passed = sorted(n for n, c in checks.items()
                     if n != "nhc_parse" and c.status == Status.PASS)
    _unresolved = sorted(n for n, c in checks.items()
                         if n != "nhc_parse" and (c.status in (Status.WARN, Status.SKIP)
                                                  or (c.metadata or {}).get("inconclusive")))
    _routes_seen = sorted({str((c.metadata or {}).get("routes_evaluated"))
                           for c in checks.values()
                           if (c.metadata or {}).get("routes_evaluated") is not None})
    return Diagnosis(
        pattern_id="launch_failure_arm_clean",
        title="Cluster Launch Failure — Azure Infra Checks Passed",
        severity=Severity.HIGH,
        confidence="medium",
        root_cause=(
            "The cluster failed to launch (signatures: "
            f"{', '.join(sigs) or 'launch failure'}), and no Azure-infra check reported a failure. "
            f"Checks that returned a clean verdict: {', '.join(_passed) or 'none'}."
            + (f" Checks that could NOT reach a verdict (warning / skipped / inconclusive) — these "
               f"are NOT evidence of health: {', '.join(_unresolved)}." if _unresolved else "")
            + (f" Route tables: {', '.join(_routes_seen)} route(s) were individually evaluated for "
               "blackhole / misdirected next hops." if _routes_seen else
               " No route table was evaluated in this run, so the routing layer is UNVERIFIED.")
            + " A SERVICE_FAULT / launch-failure classification does NOT by itself prove a "
              "Databricks-side bug; equally, this card does NOT claim every layer was proven "
              "healthy — only that the checks listed above came back clean in the resources "
              "visible to the Reader SP."
        ),
        evidence=[(name, check.message) for name, check in checks.items()
                  if name != "nhc_parse" and check.status == Status.PASS][:6],
        prescription=[
            "Confirm the Reader SP covers ALL relevant scopes (workspace RG, managed RG, data-plane "
            "VNet RG, and any RGs holding route tables / NSGs / NAT / Private DNS / front-end PEs) — a "
            "missing scope means a real misconfig could be invisible here. Re-run with subscription-level "
            "Reader if any check was SKIPPED.",
            "Recheck recently-changed Azure resources on the data-plane VNet (NSG edits, UDR/route-table "
            "changes, subnet delegation, NAT gateway) that may have triggered the launch failure.",
            "Open the route table(s) associated with the data-plane subnets and read EVERY route, not "
            "just 0.0.0.0/0: a route on a service tag (Storage, AzureDatabricks, AzureActiveDirectory, "
            "EventHub, Sql) or on a public CIDR wins over the default route under longest-prefix match, "
            "and a next hop of 'None' on any of them drops that destination silently (a timeout, not a "
            "TLS or HTTP error).",
            "Only after the ARM checks have run clean against complete scope: open a Databricks support "
            "ticket and include this report, the cluster id, and the full launch-error text.",
        ],
        fix_order=1,
    )


def _rule_all_healthy(checks, context=None):
    """All checks PASS => healthy.

    Guard against the cluster-start path: if an nhc_parse check is present the run
    is a launch-failure diagnosis (NHC or X_UnexpectedLaunchFailure). Even when
    every ARM check PASSed the cluster still failed to launch, so _rule_launch_
    failure_arm_clean (or a specific nhc_* rule) owns it — emitting "Connectivity
    Healthy" alongside a launch-failure card is contradictory. S6 (genuinely
    healthy serverless) has no nhc_parse check, so it still returns the healthy card.
    """
    if not checks:
        return None
    if checks.get("nhc_parse") is not None:
        return None
    for name, check in checks.items():
        if check.is_failure():
            return None
    # A check that could not reach a verdict must not be laundered into "healthy".
    # Checks self-report this with metadata["inconclusive"] (e.g. the routing/egress
    # checks when no route table could be read or none is associated). Absence of
    # evidence is not evidence of health — an earlier defect, root #3.
    # Human names, not dict keys: this sentence is quoted verbatim into the chat guide,
    # and a raw key like "arm_reachability" is not a string the customer can find
    # anywhere. Keep the (key, row) pairs so `evidence` below still resolves — mapping
    # names back through `checks[...]` would KeyError, and correlate() swallows rule
    # exceptions, so the card would have vanished silently.
    _unknown = sorted(((n, c) for n, c in checks.items()
                       if (c.metadata or {}).get("inconclusive")),
                      key=lambda kv: (kv[1].check_name or kv[0]))
    unknown = [(c.check_name or n) for n, c in _unknown]
    if unknown:
        return Diagnosis(
            pattern_id="all_healthy",
            title="No Fault Found — but Some Checks Were Inconclusive",
            severity=Severity.INFO,
            confidence="low",
            root_cause=(
                "No diagnostic check reported a failure, but these checks could NOT reach a "
                f"verdict: {', '.join(unknown)}. Their layers are therefore UNVERIFIED — this is "
                "not a confirmation that the path is healthy. Read each inconclusive check's "
                "recommendation (usually a missing Reader scope, or a fact only Network Watcher's "
                "effective routes can settle) and re-run."),
            evidence=[((c.check_name or n), c.message) for n, c in _unknown],
            fix_order=99,
        )
    # this card's own root_cause used to read "All diagnostic checks passed" even
    # when several checks had been SKIPPED (no Reader SP), i.e. it asserted a category was
    # clean while rows in it had never run. State the counts instead of the claim; the
    # verdict is unchanged (a declared skip is not a fault), but the sentence is now true.
    #
    # the replacement wording, "Every check that ran passed (10 of 10)", was still
    # false in the same way: this rule fires when nothing FAILED, and a WARN row both ran
    # and did not pass. Caught offline on the two healthy-baseline reports (three WARN rows
    # each: ping, routes, peering) by the guide's own audit, because the card's text goes
    # to the customer verbatim inside the chat guide. Count the three outcomes separately
    # and never fold WARN into "passed".
    #
    # The third source of the same skip-accounting bug. This card is handed the
    # checks that RAN (rules need to see a check's ABSENCE, so gate skips are not
    # materialised into the rule input), which meant the sentence below counted "7 of 7
    # returned a clean pass" on a run where ELEVEN checks had been gate-skipped, and its
    # "NOT tested, and therefore unverified" clause listed nothing. The skips arrive as
    # DATA on the context instead, so this card names them without making absence
    # unrepresentable for every other rule.
    #
    # One level up from the skip-accounting bug above. Counting the
    # skips correctly made this sentence list ALL of them as "NOT tested, and therefore
    # unverified", including six rows whose own reason said "not applicable to a
    # serverless-only problem". The customer read the same six layers described two
    # opposite ways and could not tell which to act on, while the single genuine
    # can't-check (the NCC rules — the layer serverless egress actually depends on) had
    # no more prominence than the six that did not matter. Split by skip CLASS, which
    # the gates now declare, so only a real gap is called unverified.
    _passed = sorted((c.check_name or n) for n, c in checks.items() if c.status == Status.PASS)
    _warned = sorted((c.check_name or n) for n, c in checks.items() if c.status == Status.WARN)
    _unver = sorted(c.check_name or n for n, c in checks.items()
                    if c.status == Status.SKIP and skip_kind(c) == SKIP_UNVERIFIED)
    _declared = sorted(c.check_name or n for n, c in checks.items()
                       if c.status == Status.SKIP and skip_kind(c) != SKIP_UNVERIFIED)
    _gate_skips = [s for s in ((context or {}).get("gate_skipped") or [])
                   if s and str(s[0]) not in checks]
    for _s in _gate_skips:
        _title = gate_skip_title(_s[0])
        _kind = _s[2] if (not isinstance(_s, str) and len(_s) > 2) else skip_kind(
            _s[1] if (not isinstance(_s, str) and len(_s) > 1) else "")
        (_unver if _kind == SKIP_UNVERIFIED else _declared).append(_title)
    _unver, _declared = sorted(set(_unver)), sorted(set(_declared))
    _total = len(checks) + len(_gate_skips)
    _skipped = sorted(set(_unver) | set(_declared))
    _rc = (f"No check reported a failure, and {len(_passed)} of {_total} returned a clean "
           "pass — nothing here identifies a customer-side network fault on this path.")
    if _warned:
        _rc += (f" {len(_warned)} check(s) returned a WARNING and are NOT proven healthy: "
                f"{', '.join(_warned)} — read those before treating this as a clean result.")
    if _unver:
        _rc += (f" NOT tested, and therefore unverified: {', '.join(_unver)} — "
                "this report says nothing about those layers.")
    if _declared:
        _rc += (f" Deliberately not run because they do not apply to this problem, or a "
                f"result above made them unnecessary (these are NOT gaps): "
                f"{', '.join(_declared)}.")
    return Diagnosis(
        pattern_id="all_healthy",
        title=("No Fault Found — Not Every Layer Was Proven Healthy"
               if (_warned or _skipped) else "Connectivity Healthy"),
        severity=Severity.INFO,
        confidence="high",
        root_cause=_rc,
        evidence=[(name, check.message) for name, check in checks.items() if check.status == Status.PASS],
        fix_order=99,
    )


# ---------------------------------------------------------------------------
# Rule Registry
# ---------------------------------------------------------------------------

_RULES = [
    _rule_nsg_deny,
    _rule_blackhole_route,
    _rule_subnet_egress_blackhole,
    _rule_udr_blackhole_required_destination,
    _rule_internet_route_private_target,
    _rule_nva_tls_interception,
    _rule_dns_pe_misalignment,
    _rule_dns_zone_unlinked,
    _rule_serverless_egress_ncc,
    _rule_dns_fail_needs_dns_type,
    _rule_peering_broken,
    _rule_peering_no_forwarding,
    _rule_peering_no_forwarding_latent,
    _rule_ncc_missing,
    _rule_ncc_pe_pending,
    _rule_ncc_pe_missing,
    _rule_egress_policy_blocks,
    _rule_egress_policy_dry_run,
    _rule_nva_firewall,
    _rule_dns_fail_no_azure,
    _rule_nsg_pass_eliminates,
    # NHC / cluster-start rules
    _rule_nhc_private_link_only_no_pe,
    _rule_nhc_firewall_missing_egress,
    _rule_nhc_forced_tunneling_blackhole,
    _rule_nhc_dns_private_zone_misconfigured,
    _rule_nhc_subnet_nsg_missing_databricks_rules,
    _rule_nhc_subnet_delegation_missing,
    _rule_launch_failure_arm_clean,
    # Reachability outranks the firewall's allow-list: if the packets can't reach the
    # appliance, its rules are irrelevant and must not become the headline.
    _rule_egress_peering_unreachable,
    _rule_egress_firewall_missing,
    _rule_connectivity_forced_tunnel_firewall,
    _rule_all_healthy,
]

# Severity ordering for fix_order assignment
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Deterministic tie-break for co-occurring diagnoses of EQUAL severity + fix_order
# (M2 consistency contract): a multi-fault diagnosis can fire several rules at the
# same severity/fix_order at once (e.g. a Path C cluster with forced-tunnel
# blackhole + missing NSG rules + missing delegation). Without an explicit order
# the headline #1 falls back to _RULES insertion order, which is fragile. The
# precedence below pins a FIXED causal order — "what blocks first on the path" —
# so a given set of failing checks ALWAYS yields the same primary diagnosis, every
# run, regardless of rule registration order. The GOAL is general determinism; the
# specific ordering is a defensible causal default (a misconfig that stops the
# resource from functioning at all ranks above one that degrades a single path).
# Lower number = ranked higher (more primary). Patterns absent here sort last
# among their (severity, fix_order) tier, then by pattern_id for full stability.
_PATTERN_PRECEDENCE = {
    # Path C — classic cluster bootstrap, in causal order of what fails first:
    "nhc_subnet_delegation_missing": 10,          # subnet can't host workers at all
    "egress_firewall_missing": 12,                # UNIFIED forced-tunnel firewall egress gap (Path A/B/C)
    "firewall_rule_denies_egress": 13,            # an explicit Deny rule wins over the Allow (rule-level)
    "firewall_dns_proxy_disabled": 14,            # FQDN network rule can't resolve — DNS proxy off (rule-level)
    "nhc_firewall_missing_egress": 15,            # forced-tunnel firewall drops required egress (UDR wins over NSG)
    "nhc_subnet_nsg_missing_databricks_rules": 20,  # control-plane auth blocked (AllRules fix)
    "nhc_subnet_nsg_backend_pl_expected": 21,
    "nhc_forced_tunneling_blackhole": 30,         # egress path broken (UDR/NVA/blackhole)
    "nhc_private_link_only_no_pe": 40,            # private-link topology incomplete
    "nhc_dns_private_zone_misconfigured": 50,     # name resolution for control plane
    "launch_failure_arm_clean": 90,              # ARM clean — honest "no infra cause found"
    # Path A — connectivity, causal order DNS -> route -> NSG -> peering:
    "dns_fail_no_azure": 110,
    "dns_zone_unlinked": 120,
    "dns_wrong_private_target": 125,   # every downstream infra finding targeted the wrong address
    "dns_pe_misalignment": 130,
    "blackhole_route": 140,
    "internet_route_private_target": 150,
    "nsg_deny": 160,
    "nva_tls_interception": 170,
    "nva_firewall": 180,
    "peering_no_forwarding": 190,
    "peering_no_forwarding_latent": 195,
    "peering_broken": 200,
    # Serverless / NCC layer:
    "serverless_egress_ncc": 210,
    "ncc_pe_missing": 220,
    "ncc_pe_pending": 230,
    "ncc_missing": 240,
    "egress_policy_blocks": 250,
    "egress_policy_dry_run": 260,            # legacy id kept for safety
    "egress_policy_dry_run_violation": 260,  # actual pattern_id emitted by the rule
}
_PRECEDENCE_DEFAULT = 500  # unlisted patterns sort after listed ones, before pattern_id tiebreak

# Layer tag per pattern (M2): so the report/chat can label which network plane a
# diagnosis lives at and never mix planes. serverless=NCC, classic/cluster-start=VNet.
_NCC_SERVERLESS_PATTERNS = {
    "serverless_egress_ncc", "ncc_missing", "ncc_pe_pending", "ncc_pe_missing",
    "egress_policy_blocks", "egress_policy_dry_run", "egress_policy_dry_run_violation",
}
_STORAGE_PATTERNS = {
    "storage_nsp_not_enforced", "storage_no_network_path",
    "storage_ac_missing_from_firewall", "storage_rbac_missing", "storage_needs_sp",
}


def _layer_for(pattern_id):
    """Map a pattern_id to its network layer label (best-effort, by prefix/set)."""
    if pattern_id in _NCC_SERVERLESS_PATTERNS:
        return "ncc-serverless"
    if pattern_id in _STORAGE_PATTERNS or pattern_id.startswith("storage_"):
        return "storage"
    if pattern_id.startswith("nhc_") or pattern_id.startswith("launch_failure"):
        return "classic-vnet"
    if pattern_id in ("all_healthy", "nsg_pass_eliminates"):
        return ""
    # Remaining Path A connectivity patterns (dns_*, *_route, nsg_deny, nva_*,
    # peering_*) are classic-VNet plane.
    return "classic-vnet"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Producers of evidence that are legitimately NOT checks in the checks dict. Keep this
# set tiny and explicit: every entry is a licence to attribute a sentence to something
# the evidence filter cannot verify.
_NON_CHECK_EVIDENCE_SOURCES = {
    "topology_trace",       # topology.trace() result carried in context (Path B)
}


def _strip_unsourced_evidence(diag, checks_dict):
    """Drop any evidence entry attributed to a check that did not run.

    A Diagnosis.evidence entry is a PROVENANCE claim: "check X reported this". On
    In the field the headline diagnosis carried ("nhc_parse", "NHC failed reaching: the
    Databricks bootstrap endpoints") on a run where nhc_parse's signals were entirely
    empty — a fabricated attribution, in a product whose whole premise is diagnosing from
    real infrastructure rather than guessed error text. Per-rule fixes are necessary but
    not sufficient; this is the backstop that makes the whole class impossible to ship.

    Only drops entries whose SOURCE did not run. It cannot judge whether a sentence
    faithfully summarises a check that DID run — that stays the individual rule's duty.

    Rules cite sources in three forms, all accepted: the checks dict KEY
    ("public_subnet_nsg"), the CheckResult's display check_name ("Subnet NSG (Databricks
    rules)"), and a small allowlist of non-check producers (a topology trace carried in
    the context rather than as a check).
    """
    ev = getattr(diag, "evidence", None)
    if not ev:
        return
    valid = set(checks_dict or {}) | _NON_CHECK_EVIDENCE_SOURCES
    for c in (checks_dict or {}).values():
        nm = getattr(c, "check_name", "")
        if nm:
            valid.add(nm)
    kept = []
    for item in ev:
        if isinstance(item, (tuple, list)) and len(item) == 2:
            name = item[0]
            if name and name not in valid:
                continue
        kept.append(item)
    diag.evidence = kept


def correlate(checks_dict, context=None):
    """Run all correlation rules against check results.

    Args:
        checks_dict: dict of check_name -> CheckResult
        context: optional dict with compute_type, etc.

    Returns:
        list of Diagnosis objects sorted by severity then fix_order.
    """
    diagnoses = []
    for rule_fn in _RULES:
        try:
            # Rules that declare a second positional arg receive the context
            # (compute_type matters: serverless vs classic select different
            # diagnostic LAYERS — field feedback).
            if rule_fn.__code__.co_argcount >= 2:
                diag = rule_fn(checks_dict, context or {})
            else:
                diag = rule_fn(checks_dict)
            if diag is not None:
                # Tag the network layer (M2) when the rule didn't set it, so the
                # report/chat can label the plane and never mix serverless/classic.
                if not getattr(diag, "layer", ""):
                    diag.layer = _layer_for(diag.pattern_id)
                _strip_unsourced_evidence(diag, checks_dict)
                diagnoses.append(diag)
        except Exception as e:
            print(f"[Doctor] correlation rule {getattr(rule_fn, '__name__', '?')} "
                  f"raised {e.__class__.__name__}: {e} — skipping that rule, not the pipeline.")

    # Sort deterministically: severity, then the rule's own fix_order, then the
    # fixed causal precedence (so co-occurring equal-severity faults always rank
    # the same way), then pattern_id as a final stable tiebreak. The last two keys
    # are what make a multi-fault Path C cluster produce the SAME headline #1 on
    # every pass (M2 / ROUND #1 determinism fix) regardless of _RULES order or
    # minor run-to-run check noise.
    diagnoses.sort(key=lambda d: (
        _SEVERITY_RANK.get(d.severity, 9),
        d.fix_order,
        _PATTERN_PRECEDENCE.get(d.pattern_id, _PRECEDENCE_DEFAULT),
        d.pattern_id,
    ))

    # a card that asserts "this configuration is correct, do not change it" must
    # not send anyone hunting once another card has named the cause, and must not be
    # tiered or counted as an issue. Runs BEFORE the fix_order renumbering so a demoted
    # card does not consume a fix-order slot.
    _supersede_correct_posture_diagnoses(diagnoses)
    diagnoses.sort(key=lambda d: (
        _SEVERITY_RANK.get(d.severity, 9),
        d.fix_order,
        _PATTERN_PRECEDENCE.get(d.pattern_id, _PRECEDENCE_DEFAULT),
        d.pattern_id,
    ))

    # Re-assign fix_order sequentially
    for i, d in enumerate(diagnoses):
        if d.severity != Severity.INFO:
            d.fix_order = i + 1

    # an "go audit the appliance's rule set" instruction must stop being an
    # instruction once this same report has inspected that appliance and cleared it.
    _restate_redundant_appliance_recommendations(checks_dict, diagnoses)

    return diagnoses


# ---------------------------------------------------------------------------
# stop instructing an audit this report already performed
# ---------------------------------------------------------------------------
# Observed in the field on the blackhole report. `Outbound to www.databricks.com` was
# the SOLE entry under "Warnings that still need an action", and its recommendation sent
# the customer to go verify the NVA rule set — in a report whose established cause is a
# packet dropped BEFORE it reaches the appliance, and whose forced-tunnel firewall row had
# PASSED at rule level in the same deliverable. Not a must_NOT hit, and the row's own
# message even disclaims attribution ("nothing is attributed to the appliance") — but the
# RECOMMENDATION contradicts that hedge and points the platform team in the one direction
# the case exists to rule out.
#
# This is the mirror image of the firewall-PASS caveat that worked: there, a green row had
# to stop reassuring ("this does NOT mean the egress works — fix the route first"); here an
# amber row has to stop instructing. Restated rather than suppressed, so the information
# survives without being work to do.
#
# The join is STRUCTURAL, on ARM data, not on wording: the appliance is identified by IP.
# A PASS row that carries `nva_ip` in its metadata is a row that inspected the appliance at
# that address; any other row whose recommendation asks the customer to verify an appliance
# AND whose own metadata points at the same address is asking for an audit this report has
# already done. Conservative on purpose: with no blocking cause established, "look harder at
# the appliance" is still the honest next step, so nothing is restated.

# Generic wording by which a recommendation asks for an appliance/firewall rule audit. Any
# check writing one of these is making the same ask; no resource or scenario literal here.
_APPLIANCE_AUDIT_MARKERS = (
    "verify the nva", "verify the firewall", "verify the nva / firewall",
    "check the nva", "check the firewall", "confirm the nva", "confirm the firewall",
    "allows outbound", "allow-list", "rule set explicitly allows",
)


def _appliance_ips(md):
    """Appliance addresses a check's metadata points at, however it recorded them."""
    md = md or {}
    ips = {md.get("nva_ip"), md.get("firewall_private_ip"), md.get("next_hop_ip")}
    for key in ("default_route", "route", "forced_tunnel"):
        sub = md.get(key)
        if isinstance(sub, dict):
            ips.add(sub.get("next_hop_ip"))
    return {str(ip) for ip in ips if ip}


def established_blocking_causes(diagnoses):
    """The diagnoses that have actually ESTABLISHED a blocking cause for this run.

    Reuses the SAME two predicates as the an earlier defect supersession pass, deliberately: a card that
    says "this is correct, change nothing" is not a cause, and a card that admits it found
    no fault cannot tell another row the cause is known. Without that filter the an earlier defect
    restatement named a posture card as "the blocking cause", which is worse than the
    instruction it replaced. Exported so the guide's audit tests the same condition the fix
    enforces rather than a second approximation of it.
    """
    return [d for d in actionable_diagnoses(diagnoses)
            if severity_value(d) in ("critical", "high")
            and not asserts_correct_posture(d)
            and identifies_a_cause(d)]


def cleared_appliances(checks_dict):
    """{appliance ip -> the PASSED check that inspected it}."""
    cleared = {}
    for name, c in (checks_dict or {}).items():
        if status_value(c) != "pass":
            continue
        for ip in _appliance_ips(getattr(c, "metadata", None)):
            cleared.setdefault(ip, getattr(c, "check_name", "") or name)
    return cleared


def _restate_redundant_appliance_recommendations(checks_dict, diagnoses):
    """Turn "go audit the appliance" into "already audited" when this report cleared it."""
    checks = checks_dict or {}
    blocking = established_blocking_causes(diagnoses)
    if not blocking:
        return                      # nothing established: auditing the appliance is honest
    top = blocking[0]

    cleared = cleared_appliances(checks)
    if not cleared:
        return

    for name, c in checks.items():
        md0 = getattr(c, "metadata", None) or {}
        # Idempotent: a second correlate() pass over the same rows must not bury the
        # original instruction under its own restatement.
        rec = (md0.get("original_recommendation")
               or (getattr(c, "recommendation", "") or "")).strip()
        if not rec or status_value(c) == "pass":
            continue
        low = rec.lower()
        if not any(m in low for m in _APPLIANCE_AUDIT_MARKERS):
            continue
        hits = sorted(_appliance_ips(getattr(c, "metadata", None)) & set(cleared))
        if not hits:
            continue
        ip = hits[0]
        md = getattr(c, "metadata", None)
        if isinstance(md, dict):
            # The original instruction is preserved verbatim, so the report still carries
            # it and nothing is lost — it just stops being presented as the next action.
            md["original_recommendation"] = rec
            md["appliance_audit_restated"] = ip
        c.recommendation = (
            f"No action needed from this row yet. The appliance at {ip} was inspected at rule "
            f"level in this same report ('{cleared[ip]}' passed), and a blocking cause has "
            f"already been identified: {top.title} (fix order {top.fix_order}) — fix that first. "
            "Audit the appliance's rule set only if fixing it does not resolve the failure; the "
            "original wording of this recommendation is kept in the report's raw data."
        )


# Generic English assertions by which a diagnosis declares "the thing I am looking at is
# CORRECT — this is not your fault". No pattern ids, no resource names: any rule that
# writes one of these is making the same claim, and the claim has consequences.
# TWO independent signals are required, so an ordinary actionable diagnosis that happens
# to contain one of these phrases is not demoted by accident:
#   (1) it claims the thing it examined is not at fault, AND
#   (2) it tells the customer to change nothing about it.
_NOT_THE_CAUSE_MARKERS = (
    "not the cause", "is expected", "documented-correct", "is correct here",
    "correctly configured", "expected configuration",
)
_NO_CHANGE_MARKERS = (
    "do not change", "do not flip", "don't change", "no change is needed",
    "nothing to change", "leave it as is", "leave this as is",
)

# Sentences whose only content is "go look somewhere else". True when a card is the ONLY
# thing in the report; actively harmful once another card has named the cause (the
# tester's read was "someone reading card #2 without card #1 would go audit Private DNS
# zones for nothing").
_LOOK_ELSEWHERE_MARKERS = (
    "root cause is elsewhere", "cause is elsewhere", "is elsewhere on",
    "look further", "cause lies elsewhere", "further along the",
    # The conditional form ("if nothing else in this report explains it, look at X") is
    # the honest way to write this when the card stands alone — and is exactly the
    # sentence to delete once something else HAS explained it.
    "if nothing else in this report",
)


def asserts_correct_posture(d):
    """Does this diagnosis say "what I examined is CORRECT — change nothing about it"?

    Such a card asks for no action of its own, so it must not be badged or counted as an
    issue. Requires both signals; one alone is too easy to hit by accident.
    """
    text = ((getattr(d, "title", "") or "") + " " + (getattr(d, "root_cause", "") or "")).lower()
    presc = " ".join(getattr(d, "prescription", None) or []).lower()
    return (any(m in text for m in _NOT_THE_CAUSE_MARKERS)
            and any(m in text + " " + presc for m in _NO_CHANGE_MARKERS))


# A card that ADMITS it found no fault does not supersede anything — it cannot tell
# another card "the cause is already known". Generic admissions our rules write; a false
# negative here is harmless (the pass simply does not run), a false positive would put a
# wrong sentence in front of a customer, so this list stays deliberately blunt.
_NO_CAUSE_FOUND_MARKERS = (
    "reported a failure", "no fault found", "no diagnosis rule matched",
    "checks passed", "does not by itself prove", "could not reach a verdict",
    "cannot determine", "won't guess", "will not claim",
)


def identifies_a_cause(d):
    """Does this diagnosis actually NAME the cause (as opposed to reporting that it
    could not find one)?"""
    text = ((getattr(d, "title", "") or "") + " " + (getattr(d, "root_cause", "") or "")).lower()
    return not any(m in text for m in _NO_CAUSE_FOUND_MARKERS)


def _supersede_correct_posture_diagnoses(diagnoses):
    """Demote and re-point "this is correct, not the cause" cards once the cause is known.

    Field experience: `nhc_subnet_nsg_backend_pl_expected` rendered second,
    badged HIGH, counted in "2 Issues Found", under a CRITICAL card that had already
    named a blackhole route — and its root_cause still ended "The launch failure's root
    cause is elsewhere on the back-end Private Link path", followed by four Private
    Link / Private DNS items to go verify. That sentence is true only while nothing else
    explains the failure.

    So, generically (no pattern ids, no scenario literals):
      * a card that ASSERTS CORRECTNESS (`asserts_correct_posture`) while a higher-ranked
        ACTIONABLE card exists carries no action of its own -> severity INFO, so it is not
        counted or badged as an issue (models.actionable_diagnoses excludes INFO);
      * its "look elsewhere" sentences are removed and replaced with a pointer to the card
        that did find the cause;
      * its prescription is reduced to the "do not change this" instruction, with the
        investigation steps left in the dashboard's context section rather than presented
        as work to do.
    Left completely alone when it is the only explanation in the report — then the
    verification list IS the next step and its severity is earned.
    """
    real = [d for d in diagnoses
            if severity_value(d) not in ("info", "")
            and not asserts_correct_posture(d)
            and identifies_a_cause(d)]
    if not real:
        # Nothing in this report actually names a cause, so "look further along the PL
        # path" is still the honest next step: leave the card exactly as its rule wrote
        # it. Being conservative here matters — the failure mode of guessing wrong is a
        # confidently false sentence ("the cause has already been identified") on a run
        # where it has not.
        return
    top = real[0]
    for d in diagnoses:
        if d is top or not asserts_correct_posture(d):
            continue
        if severity_value(d) in ("info", ""):
            continue
        keep = []
        for sentence in _re.split(r"(?<=[.])\s+", str(getattr(d, "root_cause", "") or "")):
            if any(m in sentence.lower() for m in _LOOK_ELSEWHERE_MARKERS):
                continue
            keep.append(sentence)
        d.root_cause = (" ".join(s for s in keep if s.strip()).strip()
                        + f" The cause has already been identified in this report: {top.title} "
                          f"(fix order {top.fix_order}) — fix that. Nothing here needs changing; "
                          "this note exists so nobody 'fixes' a setting that is already correct.")
        d.severity = Severity.INFO
        d.fix_order = max(90, getattr(d, "fix_order", 90))
        no_change = [p for p in (getattr(d, "prescription", None) or [])
                     if any(m in p.lower() for m in ("do not change", "do not flip",
                                                     "no change is needed", "leave it as is"))]
        rest = [p for p in (getattr(d, "prescription", None) or []) if p not in no_change]
        d.prescription = no_change + [
            f"Apply the fix from '{top.title}' instead — that is the finding that explains the "
            "failure.",
        ] + ([f"(Only if that fix does not resolve it, the deeper checks are: "
              + " ".join(rest) + ")"] if rest else [])


def generate_summary(diagnoses, checks_dict):
    """Produce a 2-3 sentence plain-English summary."""
    # `report.summary` is a SECOND customer-visible surface (the dashboard renders
    # it under the headline "AI Physician Diagnosis"), and its branches keyed only on the
    # diagnosis list: an `all_healthy` card sits happily next to WARN, SKIP or
    # inconclusive rows, so the summary could assert "All diagnostic checks passed" on a
    # report where several had not. State the counts instead of a claim.
    counts = check_verdict_counts(checks_dict)

    if not diagnoses:
        # REUSE 2. This used to read "No diagnostic results available." — a string
        # _rule_peering_no_forwarding_latent's docstring already flagged as known-bad.
        # An empty diagnoses list is NOT an absence of results: the checks ran and no
        # diagnosis rule matched them. In the field that was the CORRECT outcome (the
        # run could read nothing from Azure and refused to invent a cause), and this
        # sentence presented the product's best behaviour as a malfunction. Say what
        # happened, with this run's numbers, and never let it read as a clean result.
        if not counts["total"]:
            return ("No check produced a result, so nothing was diagnosed. This report "
                    "establishes nothing about this target — treat it as a failed run, "
                    "not as a clean one.")
        if counts["fail"] or counts["error"]:
            return (f"{counts['fail'] + counts['error']} of {counts['total']} checks did not "
                    "pass and NO diagnosis rule matched them, so the cause is not "
                    "identified. Read the failing row(s) below; a failing check with no "
                    "matching diagnosis is itself worth reporting to this tool's "
                    "maintainers.")
        if counts["not_passed"] or counts["inconclusive"]:
            return (f"No diagnosis rule matched, so no cause was identified — and this is "
                    f"NOT a clean bill of health: {counts['pass']} of {counts['total']} "
                    f"checks passed ({counts['warn']} warning, {counts['skip']} skipped, "
                    f"{counts['inconclusive']} inconclusive). Those layers are UNVERIFIED, "
                    "not proven healthy.")
        return (f"All {counts['total']} checks that ran passed and no diagnosis rule "
                "matched, so nothing in this report identifies a fault on this target.")

    # Separate actionable from informational (one shared definition — models)
    actionable = actionable_diagnoses(diagnoses)
    healthy = [d for d in diagnoses if d.pattern_id == "all_healthy"]
    if healthy and not actionable:
        if counts["not_passed"] or counts["inconclusive"]:
            return (f"No blocking fault found, but this is not a clean bill of health: "
                    f"{counts['pass']} of {counts['total']} checks passed — "
                    f"{counts['warn']} warning, {counts['fail'] + counts['error']} failed, "
                    f"{counts['skip']} skipped, {counts['inconclusive']} inconclusive. "
                    "Those layers are UNVERIFIED, not proven healthy.")
        return (f"All {counts['total']} diagnostic checks passed. Network connectivity to this "
                "target is healthy.")

    parts = []
    # Summarize what works
    dns = checks_dict.get("dns")
    tcp = checks_dict.get("tcp")
    if dns and dns.status == Status.PASS:
        parts.append("DNS resolution succeeded")
    elif dns and dns.status == Status.FAIL:
        parts.append("DNS resolution failed")

    if tcp and tcp.status == Status.PASS:
        parts.append("TCP connectivity is working")
    elif tcp and tcp.status == Status.FAIL:
        if "timed out" in tcp.message.lower():
            parts.append("TCP connection timed out")
        elif "refused" in tcp.message.lower():
            parts.append("TCP connection was refused")
        else:
            parts.append("TCP connectivity failed")

    summary = ". ".join(parts) + "." if parts else ""

    # Add top diagnosis. If the top finding is a topology-assumption hypothesis
    # (needs_confirmation), phrase it as a question to answer — never assert it as
    # a confirmed root cause.
    if actionable:
        top = actionable[0]
        if getattr(top, "needs_confirmation", False):
            # Lead with an explicit HYPOTHESIS label so the narrative can never read as
            # an asserted root cause — even when a remote VNet name looks suggestive or
            # the failure looks obvious. The diagnostic cannot verify topology/DNS
            # architecture from probes/ARM alone, so it must be confirmed first.
            summary += f" HYPOTHESIS (not yet confirmed — needs your confirmation): {top.root_cause}"
            q = top.follow_up_questions[0] if top.follow_up_questions else ""
            if q:
                summary += f" Before I treat this as the root cause, confirm: {q}"
        else:
            summary += f" {top.root_cause}"
        confirm_pending = [d for d in actionable if getattr(d, "needs_confirmation", False)]
        if len(actionable) > 1:
            summary += f" ({len(actionable)} issues found total"
            if confirm_pending:
                summary += f"; {len(confirm_pending)} need customer confirmation before a final root cause"
            summary += ".)"

    return summary.strip()


def consolidate_multi_target(reports):
    """When multiple targets share the same failure pattern, consolidate."""
    if len(reports) < 2:
        return []

    # Group diagnoses by pattern_id across reports
    pattern_targets = {}
    for report in reports:
        for diag in report.diagnoses:
            if diag.pattern_id not in pattern_targets:
                pattern_targets[diag.pattern_id] = {"diag": diag, "targets": []}
            pattern_targets[diag.pattern_id]["targets"].append(report.target)

    consolidated = []
    for pid, info in pattern_targets.items():
        if len(info["targets"]) > 1:
            diag = info["diag"]
            consolidated.append(Diagnosis(
                pattern_id=f"{pid}_consolidated",
                title=f"{diag.title} (affects {len(info['targets'])} targets)",
                severity=diag.severity,
                confidence=diag.confidence,
                root_cause=f"{diag.root_cause} Affects targets: {', '.join(info['targets'])}.",
                evidence=diag.evidence,
                prescription=diag.prescription,
                follow_up_questions=diag.follow_up_questions,
                needs_confirmation=getattr(diag, "needs_confirmation", False),
                fix_order=diag.fix_order,
            ))
    return consolidated
