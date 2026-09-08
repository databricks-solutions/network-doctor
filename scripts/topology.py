"""Topology-first discovery for the Network Connectivity Doctor.

Phase 0 of any network diagnosis (when ARM/SP is available): discover the
customer's Azure network topology ONCE and build a graph, then let the path
checks reason against it. "Understand where we are before suggesting a fix."

COMPUTE-PLANE GATE (the first thing build_topology decides):
  - CLASSIC / VNet-injected -> build the full VNet graph (subnets -> UDR/effective
    route -> peering -> hub Azure Firewall, across readable subscriptions) and
    enable trace() + the egress_firewall_missing diagnosis.
  - SERVERLESS -> there is NO customer VNet/UDR/hub firewall in the data path;
    egress is governed by account-level NCC + auto-config. We do NOT build a
    VNet/firewall graph and trace() is a no-op SKIP — serverless egress problems
    belong to the NCC layer (serverless_ncc_checks), never to a customer firewall.

Reuses the existing ARM primitives so LIVE/OFFLINE behave identically and there
is no second ARM-access idiom: _arm_get + the offline cache, _parse_resource_id,
get_workspace_network_config, and the firewall allow-list helpers
(_fw_collect_allows / _fw_covers / _REQUIRED_EGRESS) from cluster_start_checks.

This module is live in Path A/B/C (orchestrator phase-0 + Path B hub-firewall
trace). Importing it and calling build_topology/trace is side-effect free beyond
read-only ARM GETs.
"""

import ipaddress as _ip

from models import Topology
from cluster_start_checks import (
    _arm_get,
    _parse_resource_id,
    _fw_collect_allows,
    _fw_covers,
    _fw_normalize_rules,
    _fw_dns_proxy_enabled,
    _fw_evaluate_category,
    _FW_ALLOWED,
    _FW_DENIED,
    _FW_DNS_PROXY,
    _REQUIRED_EGRESS,
    blackhole_routes_covering as _blackhole_routes_covering,
    check_backend_private_link,
    get_workspace_network_config,
)

_M = "https://management.azure.com"
_AV_NET = "2023-02-01"      # matches get_workspace_network_config + the ARM dump template
_AV_FW = "2023-09-01"       # matches check_forced_tunnel_firewall_egress
_AV_SUB = "2022-12-01"      # matches probe_arm_reachability


# ---------------------------------------------------------------------------
# Graph helpers
# ---------------------------------------------------------------------------

def _node(topo, nid, kind, name="", **props):
    if not nid:
        return None
    topo.nodes[nid] = {
        "id": nid, "kind": kind,
        "name": name or nid.split("/")[-1],
        "props": props,
    }
    return topo.nodes[nid]


def _edge(topo, src, kind, dst):
    if src and dst:
        topo.edges.append((src, kind, dst))


def _err(topo, msg):
    topo.discovery.setdefault("errors", []).append(msg)
    topo.discovery["partial"] = True


def _infer_category(fqdn):
    """Map a destination FQDN to a required-egress category (storage|control_plane)."""
    f = (fqdn or "").lower()
    if f.endswith(".blob.core.windows.net") or f.endswith(".dfs.core.windows.net"):
        return "storage"
    if f.endswith(".azuredatabricks.net") or f.endswith(".databricks.com") or f == "www.databricks.com":
        return "control_plane"
    return None


# ---------------------------------------------------------------------------
# Discovery (build the graph)
# ---------------------------------------------------------------------------

def build_topology(arm_token, workspace_resource_id, compute_type=""):
    """Discover the reachable Azure network topology for a workspace.

    Scoped "spine" walk (~10-15 GETs): workspace -> VNet -> data-plane subnets ->
    route tables / NSGs -> Connected peerings -> remote (hub) VNets -> forced-tunnel
    Azure Firewall (matched by next-hop private IP across every readable
    subscription) -> firewall policy allow-list. Returns a Topology.

    Compute-plane gate: serverless (or no customer VNet) short-circuits with a
    serverless environment and NO VNet/firewall graph.
    """
    topo = Topology(
        environment={}, nodes={}, edges=[], roots={},
        discovery={"scopes_read": [], "errors": [], "partial": False},
    )
    ws = get_workspace_network_config(arm_token, workspace_resource_id)
    if not ws.get("ok"):
        _err(topo, f"workspace read failed: {ws.get('error')}")
        topo.environment = {"plane": "unknown", "vnet_injected": False, "hub_spoke": False}
        return topo

    sub = _parse_resource_id(workspace_resource_id).get("subscription_id", "")
    if sub:
        topo.discovery["scopes_read"].append(sub)
    vnet_id = ws.get("vnet_id") or ""
    serverless = (compute_type or "").lower() == "serverless" or not vnet_id
    plane = "serverless" if serverless else "classic"

    topo.roots = {"workspace_id": workspace_resource_id, "data_plane_vnet_id": vnet_id, "subnet_ids": []}
    _node(topo, workspace_resource_id, "workspace", ws.get("workspace_url", ""),
          public_network_access=ws.get("public_network_access"),
          required_nsg_rules=ws.get("required_nsg_rules"),
          location=ws.get("location"))
    topo.environment = {"plane": plane, "vnet_injected": bool(vnet_id), "hub_spoke": False}

    # Back-end Private Link serves the CONTROL PLANE without any firewall egress rule.
    # Detect it here (reusing the Path C detector — a second implementation is exactly how
    # this regressed: the guard added in 20a8109 lived only in the cluster-start check, and
    # when Path A became topology-first it started routing through trace(), which had no
    # such awareness and re-emitted a CRITICAL egress_firewall_missing on healthy
    # back-end-PL workspaces). Live-caught on a healthy SRA.
    if not serverless:
        try:
            _bpl = check_backend_private_link(ws, vnet_id, arm_token=arm_token)
            _bpl_md = getattr(_bpl, "metadata", None) or {}
            topo.environment["backend_private_link"] = bool(_bpl_md.get("has_backend_pe"))
            topo.environment["backend_pe_names"] = _bpl_md.get("backend_pe_names") or []
        except Exception as _e:  # detection is best-effort; never break discovery
            topo.environment["backend_private_link"] = False
            _err(topo, f"back-end Private Link detection failed: {_e}")

    # COMPUTE-PLANE GATE: serverless egress is account-level NCC, not a customer
    # VNet/firewall concern. Do not build a VNet/firewall graph.
    if serverless:
        topo.environment["note"] = (
            "serverless: egress governed by account-level NCC + auto-config; "
            "customer VNet/UDR/firewall topology is N/A"
        )
        return topo

    # ---- CLASSIC / VNet-injected: build the VNet graph ----
    # Record the data-plane VNet's own address space: trace() needs it to tell whether a
    # forced-tunnel next hop lives INSIDE this VNet (no peering required) or in another
    # VNet (reachable only over a Connected peering).
    _spoke_prefixes = []
    _vnet_body = _arm_get(arm_token, f"{_M}{vnet_id}?api-version={_AV_NET}")
    if "_error" not in _vnet_body:
        _spoke_prefixes = (((_vnet_body.get("properties") or {}).get("addressSpace") or {})
                           .get("addressPrefixes") or [])
    _node(topo, vnet_id, "vnet", ws.get("vnet_id", "").split("/")[-1], role="spoke",
          address_prefixes=_spoke_prefixes)

    for sname in [s for s in (ws.get("public_subnet"), ws.get("private_subnet")) if s]:
        s = _arm_get(arm_token, f"{_M}{vnet_id}/subnets/{sname}?api-version={_AV_NET}")
        if "_error" in s:
            _err(topo, f"subnet {sname} unreadable: {s['_error']}")
            continue
        sp = s.get("properties", {}) or {}
        sid = s.get("id") or f"{vnet_id}/subnets/{sname}"
        rt_id = (sp.get("routeTable") or {}).get("id", "")
        nsg_id = (sp.get("networkSecurityGroup") or {}).get("id", "")
        topo.roots["subnet_ids"].append(sid)
        _node(topo, sid, "subnet", sname, address_prefix=sp.get("addressPrefix", ""),
              vnet_id=vnet_id, route_table_id=rt_id, nsg_id=nsg_id)
        _edge(topo, vnet_id, "contains", sid)
        if rt_id:
            rt = _arm_get(arm_token, f"{_M}{rt_id}?api-version={_AV_NET}")
            if "_error" in rt:
                _err(topo, f"route table {rt_id.split('/')[-1]} unreadable: {rt['_error']}")
            else:
                routes = []
                for r in (rt.get("properties", {}) or {}).get("routes", []) or []:
                    rp = r.get("properties", {}) or {}
                    routes.append({
                        "name": r.get("name"), "address_prefix": rp.get("addressPrefix"),
                        "next_hop_type": rp.get("nextHopType"),
                        "next_hop_ip": rp.get("nextHopIpAddress", ""),
                    })
                _node(topo, rt_id, "route_table", rt.get("name", ""), routes=routes)
                _edge(topo, sid, "applies_rt", rt_id)
        if nsg_id:
            _node(topo, nsg_id, "nsg", nsg_id.split("/")[-1])
            _edge(topo, sid, "applies_nsg", nsg_id)

    # Peerings -> remote (hub) VNets (may live in another RG/subscription)
    connected_remotes = []
    peers = _arm_get(arm_token, f"{_M}{vnet_id}/virtualNetworkPeerings?api-version={_AV_NET}")
    if "_error" in peers:
        _err(topo, f"VNet peerings unreadable: {peers['_error']}")
    else:
        for p in peers.get("value", []):
            pp = p.get("properties", {}) or {}
            rv = (pp.get("remoteVirtualNetwork") or {}).get("id", "")
            state = pp.get("peeringState")
            fwd = pp.get("allowForwardedTraffic")
            pid = p.get("id") or f"{vnet_id}/peer/{p.get('name')}"
            _node(topo, pid, "peering", p.get("name", ""), remote_vnet_id=rv,
                  peering_state=state, allow_forwarded_traffic=fwd)
            _edge(topo, vnet_id, "peers_with", rv)
            if state == "Connected" and rv:
                connected_remotes.append(rv)
                if not fwd:
                    _err(topo, f"peering '{p.get('name')}' has allowForwardedTraffic=OFF "
                               "— firewall-forwarded packets are dropped even if the allow-list is correct")
    for rv in connected_remotes:
        rvd = _arm_get(arm_token, f"{_M}{rv}?api-version={_AV_NET}")
        if "_error" in rvd:
            _err(topo, f"hub VNet {rv.split('/')[-1]} unreadable: {rvd['_error']}")
            continue
        prefixes = ((rvd.get("properties", {}) or {}).get("addressSpace") or {}).get("addressPrefixes", []) or []
        _node(topo, rv, "vnet", rvd.get("name", ""), address_prefixes=prefixes, role="hub")
        topo.environment["hub_spoke"] = True

    # Resolve forced-tunnel next-hops to Azure Firewalls across readable subscriptions
    _resolve_firewalls(topo, arm_token, default_sub=sub)
    return topo


def _resolve_firewalls(topo, arm_token, default_sub=""):
    """Find every 0.0.0.0/0 VirtualAppliance next-hop in the graph and resolve it to
    an Azure Firewall (+ its policy allow-list) across all readable subscriptions."""
    nva_ips = set()
    for node in topo.nodes.values():
        if node["kind"] == "route_table":
            for r in node["props"].get("routes", []):
                if (r.get("address_prefix") == "0.0.0.0/0"
                        and r.get("next_hop_type") == "VirtualAppliance" and r.get("next_hop_ip")):
                    nva_ips.add(r["next_hop_ip"])
    if not nva_ips:
        return

    subs = _arm_get(arm_token, f"{_M}/subscriptions?api-version={_AV_SUB}")
    if "_error" in subs:
        sub_ids = [default_sub] if default_sub else []
        _err(topo, f"could not list subscriptions ({subs['_error']}); limited firewall search to {sub_ids}")
    else:
        sub_ids = [s.get("subscriptionId") for s in subs.get("value", []) if s.get("subscriptionId")]

    resolved = set()
    for s_id in sub_ids:
        fwl = _arm_get(arm_token, f"{_M}/subscriptions/{s_id}/providers/Microsoft.Network/azureFirewalls?api-version={_AV_FW}")
        if "_error" in fwl:
            _err(topo, f"subscription {s_id}: azureFirewalls unreadable ({fwl['_error']}) "
                       "— grant the SP Reader on the hub firewall's subscription")
            continue
        if s_id not in topo.discovery["scopes_read"]:
            topo.discovery["scopes_read"].append(s_id)
        for fw in fwl.get("value", []):
            fwp = fw.get("properties", {}) or {}
            fw_ips = [(ic.get("properties") or {}).get("privateIPAddress")
                      for ic in (fwp.get("ipConfigurations") or [])]
            match = [ip for ip in fw_ips if ip and ip in nva_ips]
            if not match:
                continue
            policy_id = (fwp.get("firewallPolicy") or {}).get("id", "")
            tags, fqdns = set(), set()
            entries = []
            dns_proxy = True
            if policy_id:
                rcgs = _arm_get(arm_token, f"{_M}{policy_id}/ruleCollectionGroups?api-version={_AV_FW}")
                if "_error" in rcgs:
                    _err(topo, f"firewall policy {policy_id.split('/')[-1]} rules unreadable: {rcgs['_error']}")
                else:
                    rcs = []
                    for g in rcgs.get("value", []):
                        gp = (g.get("properties", {}) or {}).get("priority", 0) or 0
                        gcols = (g.get("properties", {}) or {}).get("ruleCollections") or []
                        rcs.extend(gcols)
                        entries.extend(_fw_normalize_rules(gcols, rcg_priority=gp))
                    tags, fqdns = _fw_collect_allows(rcs)
                # DNS Proxy lives on the policy resource, not the rule groups.
                pol = _arm_get(arm_token, f"{_M}{policy_id}?api-version={_AV_FW}")
                dns_proxy = _fw_dns_proxy_enabled(pol.get("properties")) if "_error" not in pol else True
            else:
                rcs = []
                for key in ("networkRuleCollections", "applicationRuleCollections"):
                    rcs.extend(fwp.get(key) or [])
                tags, fqdns = _fw_collect_allows(rcs)
                entries = _fw_normalize_rules(rcs, rcg_priority=0)
                dns_proxy = True        # classic legacy firewall — don't false-positive on DNS proxy
            fid = fw.get("id", "")
            _node(topo, fid, "firewall", fw.get("name", ""),
                  private_ips=[ip for ip in fw_ips if ip], policy_id=policy_id,
                  allowed_tags=sorted(tags), allowed_fqdns=sorted(fqdns), nva_ip=match[0],
                  rule_entries=entries, dns_proxy_enabled=dns_proxy,
                  subscription_id=s_id)
            # link the route tables that point here
            for node in topo.nodes.values():
                if node["kind"] == "route_table" and any(
                        r.get("next_hop_ip") == match[0] for r in node["props"].get("routes", [])):
                    _edge(topo, node["id"], "routes_via", fid)
            resolved.update(match)

    for ip in nva_ips - resolved:
        _err(topo, f"forced-tunnel next hop {ip} could not be resolved to a readable Azure Firewall "
                   "(3rd-party NVA, or its subscription is not readable by the SP)")


# ---------------------------------------------------------------------------
# Query (trace an egress path)
# ---------------------------------------------------------------------------

def locate_ip_owning_vnet(topology, ip):
    """Return the vnet node whose address space contains ip, or None."""
    try:
        addr = _ip.ip_address(ip)
    except ValueError:
        return None
    for node in topology.nodes.values():
        if node["kind"] != "vnet":
            continue
        for pfx in node["props"].get("address_prefixes", []) or []:
            try:
                if addr in _ip.ip_network(pfx, strict=False):
                    return node
            except ValueError:
                continue
    return None


def _nva_reachability(topology, nva_ip):
    """Can the data plane even REACH a forced-tunnel next hop at `nva_ip`?

    A 0.0.0.0/0 route to a VirtualAppliance is only useful if that appliance is
    routable: either it sits inside this VNet, or it sits in another VNet joined by a
    **Connected** peering. Delete the peering and the next hop becomes a black hole —
    every packet is dropped while the firewall's own rules remain perfectly correct.

    This mattered in the field: the spoke→hub peering was deleted, yet
    _resolve_firewalls still located the hub firewall (it matches the IP across every
    readable subscription, independent of peering state), trace() credited its allow
    rules, and the Doctor told the customer "connectivity is healthy" while nothing in
    the workspace worked.

    Returns (reachable: bool, reason: str, gate_kind: str). Fails OPEN when address
    spaces are unknown, so a discovery gap degrades instead of inventing a fault.
    `gate_kind` disambiguates the not-reachable outcomes for the caller:
      ""                     reachable (or unproven-and-failing-open)
      "peering"              PROVEN unreachable — no Connected peering carries the next hop
      "peer_vnet_unreadable" UNPROVEN — a Connected peering EXISTS but the peer (hub) VNet's
                             address space was never read (the SP likely lacks Reader on the
                             hub's subscription/RG). Telling the customer to "recreate the
                             peering" here is wrong: the peering is Connected, merely unread.
    """
    if not nva_ip:
        return True, "", ""
    try:
        ip = _ip.ip_address(nva_ip)
    except ValueError:
        return True, "", ""

    def _in(prefixes):
        for p in prefixes or []:
            try:
                if ip in _ip.ip_network(p, strict=False):
                    return True
            except ValueError:
                continue
        return False

    local, connected_remotes, any_prefix_known = [], [], False
    for n in topology.nodes.values():
        if n.get("kind") != "vnet":
            continue
        pref = (n.get("props") or {}).get("address_prefixes") or []
        if pref:
            any_prefix_known = True
        (local if (n.get("props") or {}).get("role") == "spoke" else connected_remotes).append(pref)

    if _in([p for pl in local for p in pl]):
        return True, "next hop is inside the data-plane VNet", ""
    if _in([p for pl in connected_remotes for p in pl]):
        return True, "next hop is in a VNet joined by a Connected peering", ""

    # Only a peering could carry us out of this VNet. Is any peering Connected at all?
    peerings = [n for n in topology.nodes.values() if n.get("kind") == "peering"]
    connected = [n for n in peerings
                 if ((n.get("props") or {}).get("peering_state") == "Connected")]
    if not connected:
        detail = (f"{len(peerings)} peering(s) exist but none is Connected"
                  if peerings else "the VNet has no peerings at all")
        return False, (f"forced-tunnel next hop {nva_ip} is outside this VNet and "
                       f"{detail}, so the appliance is unreachable and all egress is black-holed"), "peering"

    # A Connected peering exists. Before asserting the next hop is "outside every peer",
    # confirm we actually READ each Connected peer's VNet: if the remote (hub) VNet was
    # unreadable (no vnet node with prefixes for that remote id), its address space is
    # unknown and we CANNOT prove the next hop is outside it. Degrade to unproven rather
    # than accusing a Connected peering of being missing (field hazard: the Reader SP can
    # see the spoke but not the hub subscription — the common hub-and-spoke split).
    known_vnet_ids = {nid for nid, n in topology.nodes.items()
                      if n.get("kind") == "vnet" and (n.get("props") or {}).get("address_prefixes")}
    if any(((n.get("props") or {}).get("remote_vnet_id") or "") not in known_vnet_ids
           for n in connected):
        return False, (f"the workspace VNet has a Connected peering, but the peer (hub) VNet's "
                       f"address space could not be read, so whether the forced-tunnel next hop "
                       f"{nva_ip} is reachable is UNPROVEN — the Reader SP likely lacks access to "
                       "the hub VNet's subscription/resource group. The peering IS Connected; it "
                       "is not missing or disconnected."), "peer_vnet_unreadable"

    if not any_prefix_known:
        return True, "", ""   # unknown address spaces — do not invent a fault
    return False, (f"forced-tunnel next hop {nva_ip} does not fall inside this VNet or any "
                   "Connected peer's address space, so the appliance is unreachable"), "peering"


def trace(topology, subnet_id, fqdn, port, category=None):
    """Walk the effective egress path from subnet_id to fqdn:port and return a verdict.

    Returns {status, hops, blocking_gate, missing, reason, recommendation}.
    For service tags / FQDNs the route only picks the next hop; the firewall
    allow-list decides reachability (reuse _fw_covers). SKIP for serverless.
    """
    out = {"status": "pass", "hops": [], "blocking_gate": None, "missing": [],
           "reason": "", "recommendation": ""}
    if (topology.environment or {}).get("plane") == "serverless":
        out["status"] = "skip"
        out["reason"] = "serverless: egress governed by account-level NCC, not a VNet/firewall path"
        return out

    cat = category or _infer_category(fqdn)
    subnet = topology.nodes.get(subnet_id) or {}
    hops = [{"kind": "subnet", "label": subnet.get("name", subnet_id or "subnet")}]

    # Control plane over back-end Private Link never traverses the hub firewall, so a
    # missing control-plane allow rule is NOT a finding. Demanding one produced a
    # CRITICAL false positive on a correctly-built SRA (workspace resolved to its
    # private PE address and TCP/TLS succeeded in the same run) — the kind of
    # confident-wrong answer that makes a customer edit a working firewall.
    if cat == "control_plane" and (topology.environment or {}).get("backend_private_link"):
        pe_names = (topology.environment or {}).get("backend_pe_names") or []
        out["reason"] = (
            "control plane is served by back-end Private Link"
            + (f" ({', '.join(pe_names)})" if pe_names else "")
            + " — it does not egress through the hub firewall, so no control-plane "
              "allow rule is required"
        )
        hops.append({"kind": "private_link", "label": "back-end Private Link (databricks_ui_api)"})
        hops.append({"kind": "target", "label": f"{fqdn}:{port}"})
        out["hops"] = hops
        return out

    rt_id = (subnet.get("props", {}) or {}).get("route_table_id", "")
    rt_routes = []
    if rt_id and rt_id in topology.nodes:
        rt_routes = topology.nodes[rt_id]["props"].get("routes", []) or []
    default_route = None
    for r in rt_routes:
        if r.get("address_prefix") == "0.0.0.0/0":
            default_route = r
            break

    # A blackhole on a MORE SPECIFIC prefix than 0.0.0.0/0 wins under longest-prefix
    # match, so it must be evaluated BEFORE the default route — and before the firewall's
    # allow-list, which is irrelevant to packets that are dropped in the routing table.
    # This trace used to read only the 0.0.0.0/0 entry, so a `Storage -> None` route left
    # it reporting "egress uses default Azure Internet routing" (when there was no default
    # route) or crediting the hub firewall's correct Storage allow rule. Same detector as
    # the cluster-start path — no second implementation.
    _bh = _blackhole_routes_covering(rt_routes, cat)
    if _bh:
        _b = _bh[0]
        rt_name = topology.nodes.get(rt_id, {}).get("name", "") or "the route table"
        out["status"] = "fail"
        out["reason"] = (
            "route '%s' in route table '%s' blackholes %s (next hop 'None')%s — packets to "
            "%s are discarded in the routing table and never reach a firewall/NVA, so no "
            "firewall allow rule can compensate"
            % (_b.get("name"), rt_name, _b.get("covers_category"),
               (", and under longest-prefix match it wins over the subnet's 0.0.0.0/0 route"
                if default_route else ""),
               fqdn))
        out["blocking_gate"] = {"kind": "blackhole", "route": _b.get("name"),
                                "prefix": _b.get("prefix"), "route_table": rt_name}
        out["recommendation"] = (
            "Azure Portal > Route tables > %s > Routes > '%s' (%s): delete the route, or set its "
            "next hop to the path this traffic should take ('Internet' for direct egress, or "
            "'Virtual appliance' + the hub firewall's private IP). A next hop of 'None' discards "
            "packets silently, which surfaces as a connection timeout rather than a TLS or HTTP "
            "error." % (rt_name, _b.get("name"), _b.get("prefix")))
        hops.append({"kind": "udr", "label": "%s -> None (blackhole)" % _b.get("prefix")})
        hops.append({"kind": "target", "label": f"{fqdn}:{port}"})
        out["hops"] = hops
        return out

    if not default_route or default_route.get("next_hop_type") == "Internet":
        out["reason"] = "egress uses default Azure Internet routing; firewall allow-list is not the gate"
        hops.append({"kind": "target", "label": f"{fqdn}:{port}"})
        out["hops"] = hops
        return out

    nh = default_route.get("next_hop_type")
    hops.append({"kind": "udr", "label": f"0.0.0.0/0 -> {nh}"})

    if nh == "None":
        out["status"] = "fail"
        out["reason"] = "blackhole route (next-hop None) silently drops all egress"
        out["blocking_gate"] = {"kind": "blackhole", "route": default_route.get("name")}
        hops.append({"kind": "target", "label": f"{fqdn}:{port}"})
        out["hops"] = hops
        return out

    if nh != "VirtualAppliance":
        out["status"] = "warn"
        out["reason"] = f"forced-tunnel next-hop is {nh} (gateway/other); not a firewall allow-list question"
        hops.append({"kind": "target", "label": f"{fqdn}:{port}"})
        out["hops"] = hops
        return out

    nva_ip = default_route.get("next_hop_ip", "")

    # REACHABILITY BEFORE RULES. The firewall's allow-list is irrelevant if the packets
    # cannot get to the firewall. _resolve_firewalls locates it by IP across every
    # readable subscription, independent of peering state, so it can hand us a firewall
    # the data plane can no longer route to.
    _reach_ok, _reach_why, _reach_kind = _nva_reachability(topology, nva_ip)
    if not _reach_ok and _reach_kind == "peer_vnet_unreadable":
        # UNPROVEN, not failed: a Connected peering exists but the hub VNet was unreadable.
        # Surface it as a WARN so the leg is not silent, but never assert "peering missing"
        # or prescribe recreating a peering that is Connected.
        out["status"] = "warn"
        out["reason"] = _reach_why
        out["blocking_gate"] = {"kind": "peer_vnet_unreadable", "nva_ip": nva_ip,
                                "detail": _reach_why}
        out["recommendation"] = (
            "Grant the read-only (Reader) Service Principal access to the hub VNet's "
            f"subscription/resource group so the forced-tunnel next hop {nva_ip} can be "
            "confirmed reachable, then re-run. Do NOT recreate the peering — it is Connected; "
            "this leg is UNPROVEN (hub VNet unreadable), not failed.")
        hops.append({"kind": "nva", "label": f"{nva_ip} (reachability unproven — hub VNet unreadable)"})
        hops.append({"kind": "target", "label": f"{fqdn}:{port}"})
        out["hops"] = hops
        return out
    if not _reach_ok:
        out["status"] = "fail"
        out["reason"] = _reach_why
        out["blocking_gate"] = {"kind": "peering", "nva_ip": nva_ip,
                                "detail": _reach_why}
        out["recommendation"] = (
            "Recreate/reconnect the VNet peering between the workspace VNet and the VNet that "
            f"hosts the forced-tunnel appliance {nva_ip}, in BOTH directions (allow virtual "
            "network access, and 'Allow forwarded traffic' on the workspace side so the "
            "appliance's forwarded packets are accepted). Until that peering is Connected, "
            "every 0.0.0.0/0 packet is dropped regardless of the firewall's rules.")
        hops.append({"kind": "unreachable_nva", "label": f"{nva_ip} (no route — peering missing)"})
        hops.append({"kind": "target", "label": f"{fqdn}:{port}"})
        out["hops"] = hops
        return out

    fw = next((n for n in topology.nodes.values()
               if n["kind"] == "firewall" and n["props"].get("nva_ip") == nva_ip), None)
    if fw is None:
        out["status"] = "warn"
        out["reason"] = (f"forced tunnel to NVA {nva_ip}, not resolved to a readable Azure Firewall "
                         "(3rd-party NVA or its subscription is unreadable)")
        out["blocking_gate"] = {"kind": "nva", "ip": nva_ip}
        out["recommendation"] = ("Verify the NVA allows the required Databricks egress, or grant the SP "
                                 "Reader on the hub firewall's subscription and re-run.")
        hops.append({"kind": "nva", "label": f"NVA {nva_ip} (unresolved)"})
        hops.append({"kind": "target", "label": f"{fqdn}:{port}"})
        out["hops"] = hops
        return out

    entries = fw["props"].get("rule_entries", [])
    dns_proxy = bool(fw["props"].get("dns_proxy_enabled", True))
    tags = set(fw["props"].get("allowed_tags", []))
    fqdns = set(fw["props"].get("allowed_fqdns", []))
    if cat in _REQUIRED_EGRESS:
        v = _fw_evaluate_category(entries, cat, dns_proxy)
    else:
        v = {"decision": _FW_ALLOWED, "rule_name": "", "collection_name": "", "priority": None}
    decision = v["decision"]
    policy_label = (fw['props'].get('policy_id') or '').split('/')[-1] or 'classic rules'
    if decision == _FW_ALLOWED:
        out["reason"] = f"firewall '{fw['name']}' allows the required egress for {fqdn} (rule-level verified)"
        hops.append({"kind": "firewall", "label": fw["name"], "verdict": "allow"})
    else:
        label = _REQUIRED_EGRESS[cat]["label"]
        out["status"] = "fail"
        out["missing"] = [cat]
        out["blocking_gate"] = {
            "kind": "firewall", "name": fw["name"], "id": fw["id"],
            "ip": nva_ip, "policy_id": fw["props"].get("policy_id", ""),
            "missing": [cat], "allowed_tags": sorted(tags), "allowed_fqdns": sorted(fqdns),
            "decision": decision, "rule_name": v.get("rule_name", ""),
            "collection_name": v.get("collection_name", ""), "rule_priority": v.get("priority"),
            "rule_type": v.get("rule_type", ""), "dns_proxy_enabled": dns_proxy,
        }
        if decision == _FW_DENIED:
            out["reason"] = (f"firewall '{fw['name']}' BLOCKS egress for {label} via Deny rule "
                             f"'{v['rule_name']}' (collection '{v['collection_name']}', priority {v['priority']}) "
                             f"— it wins over any Allow, so {fqdn} is dropped")
            out["recommendation"] = (f"Remove or re-scope Deny rule '{v['rule_name']}' on policy '{policy_label}', "
                                     f"or add a higher-precedence Allow (lower priority, network rule) for {label}.")
            block_reason = f"Deny '{v['rule_name']}' wins"
        elif decision == _FW_DNS_PROXY:
            out["reason"] = (f"firewall '{fw['name']}' matches {label} via an FQDN in a NETWORK rule "
                             f"('{v['rule_name']}') but DNS Proxy is DISABLED — the FQDN never resolves, "
                             f"so {fqdn} is silently dropped")
            out["recommendation"] = (f"Enable DNS Proxy on policy '{policy_label}' "
                                     "(dnsSettings.enableProxy=true), move the FQDN to an application rule, or "
                                     "use the 'Storage'/'AzureDatabricks' service tag (no DNS proxy needed).")
            block_reason = "FQDN net-rule needs DNS proxy"
        else:
            out["reason"] = (f"firewall '{fw['name']}' is in the forced-tunnel path and is MISSING egress for "
                             f"{label} — {fqdn} is dropped")
            out["recommendation"] = (f"Add an ALLOW rule on firewall policy '{policy_label}' "
                                     f"for {label} from the Databricks subnets (TCP 443).")
            block_reason = f"no Allow for {cat}"
        hops.append({"kind": "firewall", "label": fw["name"], "verdict": "block", "reason": block_reason})
    hops.append({"kind": "target", "label": f"{fqdn}:{port}"})
    out["hops"] = hops
    return out


def render_path_line(trace_result):
    """One-line ASCII egress path for chat + dashboard (kept identical in both)."""
    parts = []
    for h in trace_result.get("hops", []):
        label = h.get("label", "")
        if h.get("verdict") == "block":
            parts.append(f"{label} ✗")
        elif h.get("verdict") == "allow":
            parts.append(f"{label} ✓")
        else:
            parts.append(label)
    line = " → ".join(parts)
    gate = trace_result.get("blocking_gate") or {}
    if gate.get("missing"):
        line += f"  [missing: {', '.join(gate['missing'])}]"
    return "egress path: " + line
