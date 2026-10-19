"""Azure infrastructure checks for the Network Connectivity Doctor.

Importable module: sibling scripts resolve via sys.path (the skill dir is
inserted by SKILL.md Step 1). Also works exec-loaded for back-compat.
No pip dependencies beyond 'requests' (already available everywhere) — all Azure
reads go through the ARM REST API directly, the same way storage_access_checks
and cluster_start_checks do. No %pip install / restartPython step is needed.
"""

import ipaddress as _ipaddress
import time

from models import CheckResult, Status
from serverless_ncc_checks import infer_resource_type
from storage_access_checks import get_arm_token
# REUSE, don't re-implement: the cluster-start path already follows a subnet's own
# routeTable association correctly and already resolves a VirtualAppliance next hop
# to its Azure Firewall with precedence-aware, service-tag-crediting rule evaluation.
# The connectivity path was structurally blind to that layer because it had its
# own, weaker route lookup. Import the detectors instead of growing a second pair.
from cluster_start_checks import (
    _REQUIRED_EGRESS,
    _route_prefix_net,
    check_forced_tunnel_firewall_egress,
    check_subnet_route_table,
    service_tag_prefix_containing,
)


def auto_discover_azure_context(client_id, client_secret, tenant_id="", resource_group="", vnet_name="", subscription_id="", workspace_arm_id=""):
    """Auto-discover Azure tenant, subscription, resource group, and VNet from within a Databricks cluster.

    On classic compute (IMDS available): only requires client_id and client_secret.
    On serverless (no IMDS): also requires tenant_id as a fallback.

    Args:
        client_id: Azure SP client/application ID
        client_secret: Azure SP client secret
        tenant_id: Optional. Required if running on serverless (IMDS unavailable).
                   On classic compute this is auto-discovered.
        resource_group: Optional. Fallback RG if auto-discovery fails.
        vnet_name: Optional. Fallback VNet name if auto-discovery fails.

    Returns:
        dict with keys: tenant_id, subscription_id, client_id, client_secret,
                        resource_group, vnet_name, workspace_id, imds_available,
                        discovery_log
    """
    import requests as _req

    log = []
    result = {
        "tenant_id": tenant_id or "",
        "subscription_id": subscription_id or "",
        "client_id": client_id,
        "client_secret": client_secret,
        "resource_group": "",
        "vnet_name": "",
        # The workspace's own ARM resource id, when discovery managed to match this
        # workspace in ARM. Lets the caller run the TOPOLOGY-first discovery (which
        # follows subnet route-table associations across resource groups and resolves a
        # forced-tunnel firewall in a peered hub SUBSCRIPTION) even when the customer
        # declined to paste the ARM id by hand.
        "workspace_id": "",
        "imds_available": False,
        "discovery_log": log,
    }

    # Step 1: Try IMDS (available on classic compute Azure VMs, NOT on serverless)
    imds_ok = False
    cluster_private_ip = ""
    managed_rg = ""
    try:
        imds = _req.get(
            "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
            headers={"Metadata": "true"}, timeout=3
        ).json()
        result["subscription_id"] = imds.get("subscriptionId", "")
        location = imds.get("location", "")
        managed_rg = imds.get("resourceGroupName", "")
        imds_ok = bool(result["subscription_id"])
        result["imds_available"] = imds_ok
        if imds_ok:
            log.append(f"IMDS: subscription_id={result['subscription_id']}, location={location}")
            if managed_rg:
                log.append(f"IMDS: managed resource group={managed_rg}")
        # Also get the cluster's private IP for VNet matching
        try:
            net_meta = _req.get(
                "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
                headers={"Metadata": "true"}, timeout=3
            ).json()
            interfaces = net_meta.get("interface", [])
            if interfaces:
                ips = interfaces[0].get("ipv4", {}).get("ipAddress", [])
                if ips:
                    cluster_private_ip = ips[0].get("privateIpAddress", "")
                    if cluster_private_ip:
                        log.append(f"IMDS: cluster private IP={cluster_private_ip}")
        except Exception:
            pass
    except Exception:
        log.append("IMDS unavailable (expected on serverless compute)")

    # Step 2: Discover tenant_id
    if imds_ok and not result["tenant_id"]:
        # Classic compute path: discover tenant from Azure management API (401 trick)
        try:
            mgmt_resp = _req.get(
                f"https://management.azure.com/subscriptions/{result['subscription_id']}?api-version=2020-01-01",
                timeout=5
            )
            auth_header = mgmt_resp.headers.get("WWW-Authenticate", "")
            if "login.microsoftonline.com/" in auth_header:
                result["tenant_id"] = auth_header.split("login.microsoftonline.com/")[1].split('"')[0].rstrip("/")
                log.append(f"Tenant discovered: {result['tenant_id']}")
            else:
                log.append("Could not parse tenant_id from management API response")
        except Exception as e:
            log.append(f"Tenant discovery via IMDS path failed: {e}")
    elif not imds_ok and result["tenant_id"]:
        # Serverless path: tenant_id was provided by the user
        log.append(f"Using provided tenant_id: {result['tenant_id']}")
    elif not imds_ok and not result["tenant_id"]:
        log.append("IMDS unavailable and no tenant_id provided. Cannot authenticate SP.")
        log.append("HINT: On serverless compute, load tenant_id, client_id, and client_secret from Databricks Secrets before calling Azure checks.")
        return result

    if not result["tenant_id"]:
        log.append("Could not determine tenant_id. Cannot proceed with Azure checks.")
        return result

    # Step 3: Get ARM token using SP values already loaded from Databricks Secrets.
    # get_arm_token (storage_access_checks) brings retry + JWT-validation robustness
    # (guards against the intermittent empty/short token that 401s on first use).
    try:
        tok_result = get_arm_token(result["tenant_id"], client_id, client_secret)
        if tok_result["error"]:
            log.append(f"SP authentication failed: {tok_result['error']}")
            return result
        arm_token = tok_result["token"]
        log.append("SP authenticated successfully")
    except Exception as e:
        log.append(f"SP authentication error: {e}")
        return result

    # Step 4: Find this Databricks workspace in ARM to get VNet details
    # On serverless (no IMDS), we don't have subscription_id yet -- list all subscriptions first
    try:
        try:
            from pyspark.sql import SparkSession
            _spark = SparkSession.getActiveSession() or SparkSession.builder.getOrCreate()
            workspace_url = _spark.conf.get("spark.databricks.workspaceUrl", "")
        except Exception:
            workspace_url = ""
        headers = {"Authorization": f"Bearer {arm_token}"}

        # DIRECT PATH — the caller handed us the exact workspace ARM resource id. It pins the
        # subscription, and ONE read of the workspace by id yields its data-plane VNet (name +
        # RG) — no subscription listing, no spark workspaceUrl, no IMDS. This is the only
        # reliable path when the diagnosis runs somewhere without IMDS/spark (headless or
        # serverless-executed), where the listing/URL-match discovery below cannot identify
        # the workspace even with a perfectly valid Reader SP + the exact resource id in hand.
        if workspace_arm_id and workspace_arm_id.startswith("/subscriptions/"):
            try:
                result["subscription_id"] = workspace_arm_id.split("/")[2] or result["subscription_id"]
                wsb = _req.get(
                    f"https://management.azure.com{workspace_arm_id}?api-version=2023-02-01",
                    headers=headers, timeout=15,
                )
                if wsb.status_code == 200:
                    wsj = wsb.json()
                    result["workspace_id"] = wsj.get("id", workspace_arm_id)
                    params = (wsj.get("properties", {}) or {}).get("parameters", {}) or {}
                    vnet_id = (params.get("customVirtualNetworkId") or {}).get("value", "")
                    if vnet_id:
                        result["vnet_name"] = vnet_id.split("/")[-1]
                        if "/resourceGroups/" in vnet_id:
                            result["resource_group"] = vnet_id.split("/resourceGroups/")[1].split("/")[0]
                        log.append(f"Resolved from workspace ARM id: VNet '{result['vnet_name']}' "
                                   f"in RG '{result['resource_group']}' (no listing needed)")
                    elif "/resourceGroups/" in workspace_arm_id:
                        result["resource_group"] = workspace_arm_id.split("/resourceGroups/")[1].split("/")[0]
                        log.append("Workspace ARM id resolved; no custom VNet (default networking)")
                    return result
                log.append(f"Workspace-by-id read returned HTTP {wsb.status_code}; "
                           "falling back to listing-based discovery")
            except Exception as e:
                log.append(f"Workspace-by-id resolution error: {e}; falling back to listing-based discovery")

        if not result["subscription_id"]:
            # Serverless path: discover subscription by listing all subscriptions
            subs_resp = _req.get(
                "https://management.azure.com/subscriptions?api-version=2020-01-01",
                headers=headers, timeout=15
            )
            subscriptions = subs_resp.json().get("value", [])
            log.append(f"SP has access to {len(subscriptions)} subscription(s)")

            # Search each subscription for our workspace
            for sub in subscriptions:
                sub_id = sub.get("subscriptionId", "")
                ws_resp = _req.get(
                    f"https://management.azure.com/subscriptions/{sub_id}"
                    f"/providers/Microsoft.Databricks/workspaces?api-version=2023-02-01",
                    headers=headers, timeout=15
                )
                if ws_resp.status_code != 200:
                    continue
                for ws in ws_resp.json().get("value", []):
                    ws_url = ws.get("properties", {}).get("workspaceUrl", "")
                    if workspace_url and ws_url and (workspace_url in ws_url or ws_url in workspace_url):
                        result["subscription_id"] = sub_id
                        log.append(f"Found workspace in subscription: {sub_id}")
                        break
                if result["subscription_id"]:
                    break

            if not result["subscription_id"]:
                log.append("Could not find workspace in any accessible subscription")
                # If SP has access to exactly 1 subscription, use it anyway
                if len(subscriptions) == 1:
                    result["subscription_id"] = subscriptions[0].get("subscriptionId", "")
                    log.append(f"Using the only accessible subscription: {result['subscription_id']}")

        # Paths A/B/C only run when subscription_id is known.
        # If subscription_id is empty (serverless path failed), skip to fallback params.
        if not result["subscription_id"]:
            log.append("No subscription_id available. Skipping ARM-based discovery.")
        else:
            # Path A: Try listing Databricks workspaces to find VNet config
            ws_resp = _req.get(
                f"https://management.azure.com/subscriptions/{result['subscription_id']}"
                f"/providers/Microsoft.Databricks/workspaces?api-version=2023-02-01",
                headers=headers, timeout=15
            )
            if ws_resp.status_code == 200:
                workspaces = ws_resp.json().get("value", [])
                log.append(f"Found {len(workspaces)} Databricks workspace(s) in subscription")

                for ws in workspaces:
                    ws_url = ws.get("properties", {}).get("workspaceUrl", "")
                    if workspace_url and ws_url and (workspace_url in ws_url or ws_url in workspace_url):
                        ws_id = ws.get("id", "")
                        result["workspace_id"] = ws_id
                        ws_rg = ""
                        if "/resourceGroups/" in ws_id:
                            ws_rg = ws_id.split("/resourceGroups/")[1].split("/")[0]
                            log.append(f"Workspace resource group: {ws_rg}")

                        params = ws.get("properties", {}).get("parameters", {})
                        vnet_id = params.get("customVirtualNetworkId", {}).get("value", "")
                        if vnet_id:
                            result["vnet_name"] = vnet_id.split("/")[-1]
                            if "/resourceGroups/" in vnet_id:
                                result["resource_group"] = vnet_id.split("/resourceGroups/")[1].split("/")[0]
                            log.append(f"VNet discovered: {result['vnet_name']} in RG {result['resource_group']}")
                        else:
                            if ws_rg:
                                result["resource_group"] = ws_rg
                                log.append("No custom VNet found (workspace may use default networking)")
                        break
                else:
                    log.append(f"Could not match workspace URL '{workspace_url}' to any ARM workspace")
            else:
                log.append(f"Could not list workspaces: HTTP {ws_resp.status_code} (SP may lack Microsoft.Databricks/workspaces/read)")

            # Path B: If workspace listing failed, try discovering VNet via Network API
            if not result["resource_group"] and imds_ok and cluster_private_ip:
                log.append("Falling back to VNet discovery via Network API...")
                try:
                    vnets_resp = _req.get(
                        f"https://management.azure.com/subscriptions/{result['subscription_id']}"
                        f"/providers/Microsoft.Network/virtualNetworks?api-version=2023-02-01",
                        headers=headers, timeout=15
                    )
                    if vnets_resp.status_code == 200:
                        vnets = vnets_resp.json().get("value", [])
                        log.append(f"Found {len(vnets)} VNet(s) accessible to SP")
                        target_ip = _ipaddress.ip_address(cluster_private_ip)
                        for vnet in vnets:
                            vnet_id = vnet.get("id", "")
                            for subnet in vnet.get("properties", {}).get("subnets", []):
                                prefix = subnet.get("properties", {}).get("addressPrefix", "")
                                if prefix:
                                    try:
                                        if target_ip in _ipaddress.ip_network(prefix, strict=False):
                                            result["vnet_name"] = vnet.get("name", "")
                                            if "/resourceGroups/" in vnet_id:
                                                result["resource_group"] = vnet_id.split("/resourceGroups/")[1].split("/")[0]
                                            log.append(f"VNet matched by IP: {result['vnet_name']} in RG {result['resource_group']} (subnet {prefix} contains {cluster_private_ip})")
                                            break
                                    except ValueError:
                                        continue
                            if result["resource_group"]:
                                break
                        if not result["resource_group"]:
                            log.append("No VNet subnet matched the cluster's private IP")
                    else:
                        log.append(f"Could not list VNets: HTTP {vnets_resp.status_code}")
                except Exception as e:
                    log.append(f"VNet fallback discovery error: {e}")

            # Path C: If both Path A and B failed, try listing NICs in the managed resource group.
            if not result["resource_group"] and imds_ok and managed_rg:
                log.append(f"Falling back to NIC discovery in managed RG '{managed_rg}'...")
                try:
                    nics_resp = _req.get(
                        f"https://management.azure.com/subscriptions/{result['subscription_id']}"
                        f"/resourceGroups/{managed_rg}/providers/Microsoft.Network"
                        f"/networkInterfaces?api-version=2023-02-01",
                        headers=headers, timeout=15
                    )
                    if nics_resp.status_code == 200:
                        nics = nics_resp.json().get("value", [])
                        log.append(f"Found {len(nics)} NIC(s) in managed RG")
                        for nic in nics:
                            ip_configs = nic.get("properties", {}).get("ipConfigurations", [])
                            if ip_configs:
                                subnet_id = ip_configs[0].get("properties", {}).get("subnet", {}).get("id", "")
                                if subnet_id and "/resourceGroups/" in subnet_id and "/virtualNetworks/" in subnet_id:
                                    result["resource_group"] = subnet_id.split("/resourceGroups/")[1].split("/")[0]
                                    result["vnet_name"] = subnet_id.split("/virtualNetworks/")[1].split("/")[0]
                                    log.append(f"VNet discovered via NIC subnet: {result['vnet_name']} in RG {result['resource_group']}")
                                    break
                        if not result["resource_group"]:
                            log.append("Could not parse VNet info from NIC subnet IDs")
                    else:
                        log.append(f"Could not list NICs in managed RG: HTTP {nics_resp.status_code}")
                except Exception as e:
                    log.append(f"NIC discovery error: {e}")
    except Exception as e:
        log.append(f"Workspace discovery error: {e}")

    # Fallback: use caller-provided resource_group / vnet_name if discovery failed
    if not result["subscription_id"] and subscription_id:
        result["subscription_id"] = subscription_id
        log.append(f"Using provided subscription_id: {subscription_id}")
    if not result["resource_group"] and resource_group:
        result["resource_group"] = resource_group
        log.append(f"Using provided resource_group: {resource_group}")
    if not result["vnet_name"] and vnet_name:
        result["vnet_name"] = vnet_name
        log.append(f"Using provided vnet_name: {vnet_name}")

    return result


class AzureInfraChecker:
    """Checks NSG rules, route tables, VNet peering, private endpoints, and DNS zones.

    Usage (auto-discover):
        ctx = auto_discover_azure_context(client_id, client_secret)
        checker = AzureInfraChecker(**{k: ctx[k] for k in ['tenant_id', 'client_id', 'client_secret', 'subscription_id', 'resource_group', 'vnet_name']})

    Usage (manual):
        checker = AzureInfraChecker(tenant_id, client_id, client_secret, subscription_id, resource_group, vnet_name)
        result = checker.check_nsg(target_ip, target_port)
    """

    _NETWORK_API = "2023-02-01"
    _PRIVATE_DNS_API = "2020-06-01"

    _DATABRICKS_DELEGATION = "Microsoft.Databricks/workspaces"

    def __init__(self, tenant_id, client_id, client_secret, subscription_id, resource_group, vnet_name=""):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.vnet_name = vnet_name
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._token = self._mint_token()
        self._subnet_cache = None

    def _mint_token(self):
        # get_arm_token (storage_access_checks) brings retry + JWT validation.
        tok = get_arm_token(self._tenant_id, self._client_id, self._client_secret)
        if tok["error"]:
            raise RuntimeError(f"ARM token mint failed: {tok['error']}")
        return tok["token"]

    def _get(self, url):
        """GET an ARM URL, re-minting the token once on 401. Raises on failure."""
        import requests as _req
        for attempt in (1, 2):
            resp = _req.get(url, headers={"Authorization": f"Bearer {self._token}"}, timeout=15)
            if resp.status_code == 401 and attempt == 1:
                self._token = self._mint_token()
                continue
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
            return resp.json()
        raise RuntimeError("unreachable")

    def _list(self, path, api_version):
        """List an ARM collection (relative to the subscription), following nextLink pages."""
        url = f"https://management.azure.com{path}?api-version={api_version}"
        items = []
        while url:
            data = self._get(url)
            items.extend(data.get("value", []))
            url = data.get("nextLink", "")
        return items

    def _rg_path(self, provider_suffix):
        return (f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}"
                f"/providers/{provider_suffix}")

    # -----------------------------------------------------------------------
    # VNet / subnet / effective-routing discovery
    # -----------------------------------------------------------------------
    # Finding root #2: route tables were enumerated per RESOURCE GROUP
    # (`_rg_path("Microsoft.Network/routeTables")`). In a hub-spoke topology routing is
    # normally managed centrally, so the spoke RG holds ZERO route tables while the
    # data-plane subnets point at a table in the HUB RG (verified live). The per-RG scan
    # therefore returned an empty set and the real routing — including any blackhole
    # route parked in the hub table — was completely invisible. Follow the SUBNET's own
    # routeTable.id instead: it is an absolute ARM id, so it crosses resource groups and
    # subscriptions for free.

    @property
    def arm_token(self):
        """The SP's current ARM bearer token (re-minted on 401 by _get)."""
        return self._token

    def vnet_id(self):
        """ARM id of the data-plane VNet, or "" when discovery could not determine it."""
        if not (self.subscription_id and self.resource_group and self.vnet_name):
            return ""
        return self._rg_path(f"Microsoft.Network/virtualNetworks/{self.vnet_name}")

    def discover_subnets(self, refresh=False):
        """Read the data-plane VNet once and return its address space + subnets.

        Returns {vnet_id, address_prefixes, subnets, error}. Each subnet:
        {name, id, address_prefix, route_table_id, nsg_id, databricks_delegated}.
        `error` is non-empty when the VNet could not be read AT ALL — callers must
        treat that as UNKNOWN, never as "nothing configured".
        """
        if self._subnet_cache is not None and not refresh:
            return self._subnet_cache
        out = {"vnet_id": self.vnet_id(), "address_prefixes": [], "subnets": [], "error": ""}
        if not out["vnet_id"]:
            out["error"] = ("the data-plane VNet is unknown (Azure discovery could not determine "
                            "subscription / resource group / VNet name)")
            self._subnet_cache = out
            return out
        try:
            body = self._get(f"https://management.azure.com{out['vnet_id']}"
                             f"?api-version={self._NETWORK_API}")
        except Exception as e:
            out["error"] = f"VNet '{self.vnet_name}' could not be read: {e}"
            self._subnet_cache = out
            return out
        props = body.get("properties", {}) or {}
        out["address_prefixes"] = ((props.get("addressSpace") or {}).get("addressPrefixes") or [])
        for sn in (props.get("subnets") or []):
            sp = sn.get("properties", {}) or {}
            delegated = any(
                ((d.get("properties") or {}).get("serviceName") == self._DATABRICKS_DELEGATION)
                for d in (sp.get("delegations") or []))
            out["subnets"].append({
                "name": sn.get("name", ""),
                "id": sn.get("id", "") or f"{out['vnet_id']}/subnets/{sn.get('name', '')}",
                "address_prefix": sp.get("addressPrefix", ""),
                "route_table_id": ((sp.get("routeTable") or {}).get("id") or ""),
                "nsg_id": ((sp.get("networkSecurityGroup") or {}).get("id") or ""),
                "databricks_delegated": delegated,
            })
        self._subnet_cache = out
        return out

    def data_plane_subnets(self):
        """The Databricks-delegated subnets (host/container), or every subnet when no
        delegation is visible — a delegation-less VNet is still worth tracing."""
        d = self.discover_subnets()
        delegated = [sn for sn in d["subnets"] if sn["databricks_delegated"]]
        return delegated or d["subnets"]

    def _target_in_vnet(self, target_ip):
        """Is target_ip inside the data-plane VNet address space? Returns
        (bool_or_None, matching_prefix). None means "unknown" (VNet unreadable or the
        address space is empty) — callers must not turn that into a verdict."""
        prefixes = self.discover_subnets().get("address_prefixes") or []
        if not prefixes:
            return None, ""
        try:
            addr = _ipaddress.ip_address(target_ip)
        except ValueError:
            return None, ""
        for pfx in prefixes:
            try:
                if addr in _ipaddress.ip_network(pfx, strict=False):
                    return True, pfx
            except ValueError:
                continue
        return False, ""

    def _effective_route_tables(self):
        """Route tables that ACTUALLY govern the data-plane subnets.

        Resolved by following each subnet's routeTable.id (any RG / any subscription).
        Falls back to the legacy per-resource-group scan ONLY when the VNet itself could
        not be read, and then marks the set `unverified` so no caller can present it as
        the effective routing.

        Returns {tables, source, unverified, associations, subnets, vnet_error, errors}.
        """
        d = self.discover_subnets()
        out = {"tables": [], "source": "subnet_association", "unverified": False,
               "associations": [], "subnets": d["subnets"], "vnet_error": d["error"],
               "errors": []}
        if d["error"]:
            out["source"] = "resource_group_scan"
            out["unverified"] = True
            try:
                out["tables"] = self._list(self._rg_path("Microsoft.Network/routeTables"),
                                           self._NETWORK_API)
            except Exception as e:
                out["errors"].append(f"resource-group route-table scan failed: {e}")
            return out
        seen = set()
        for sn in self.data_plane_subnets():
            rt_id = sn["route_table_id"]
            out["associations"].append({"subnet": sn["name"], "route_table_id": rt_id})
            if not rt_id or rt_id in seen:
                continue
            seen.add(rt_id)
            try:
                out["tables"].append(self._get(f"https://management.azure.com{rt_id}"
                                               f"?api-version={self._NETWORK_API}"))
            except Exception as e:
                out["errors"].append(
                    f"route table '{rt_id.split('/')[-1]}' (associated with subnet "
                    f"'{sn['name']}', resource group "
                    f"'{rt_id.split('/resourceGroups/')[-1].split('/')[0] if '/resourceGroups/' in rt_id else '?'}') "
                    f"could not be read: {e}")
        return out

    def _effective_nsgs(self):
        """The NSGs actually ATTACHED to the data-plane subnets, followed by their own ids.

        Field experience: check_nsg used to enumerate
        `self._rg_path("networkSecurityGroups")` and return on the FIRST rule that matched,
        without ever establishing that the NSG it read was attached to the source subnet.
        It happened to be right on this fixture only because the spoke resource group holds
        exactly one NSG. Real customers commonly keep several (per subnet, per tier) in one
        group, or have the platform team own the NSG in a different group entirely — and
        then the check renders a confident verdict about the wrong NSG, or finds none at all
        while one is attached. This is the same defect shape root #2, one resource type over:
        discovery by resource-group enumeration instead of by following the association.

        Returns {nsgs, names, source, subnets, unverified, errors}. `unverified` is True when
        the association could not be read and the resource-group scan was used instead, so no
        caller can present that verdict as the effective NSG.
        """
        out = {"nsgs": [], "names": [], "source": "subnet_association", "subnets": [],
               "unverified": False, "errors": []}
        d = self.discover_subnets()
        planes = self.data_plane_subnets() or d.get("subnets") or []
        seen = set()
        for sn in planes:
            out["subnets"].append(sn.get("name"))
            nsg_id = sn.get("nsg_id")
            if not nsg_id or nsg_id in seen:
                continue
            seen.add(nsg_id)
            try:
                body = self._get(f"https://management.azure.com{nsg_id}"
                                 f"?api-version={self._NETWORK_API}")
                out["nsgs"].append(body)
                out["names"].append(nsg_id.split("/")[-1])
            except Exception as e:
                out["errors"].append(f"{nsg_id.split('/')[-1]}: {e}")
        if out["nsgs"]:
            return out
        # Nothing followed. Only now fall back, and label it so it cannot be presented as fact.
        if d.get("error") or out["errors"]:
            out["source"] = "resource_group_scan"
            out["unverified"] = True
            try:
                scanned = self._list(self._rg_path("Microsoft.Network/networkSecurityGroups"),
                                     self._NETWORK_API)
                out["nsgs"] = scanned
                out["names"] = [n.get("name") for n in scanned]
            except Exception as e:
                out["errors"].append(f"resource-group scan failed: {e}")
        return out

    def check_nsg(self, target_ip, target_port):
        """Check NSG rules for outbound traffic to target."""
        start = time.time()
        try:
            eff = self._effective_nsgs()
            nsgs = eff["nsgs"]
            _scope = (f" NSG(s) read by subnet association: {', '.join(eff['names'])}."
                      if eff["source"] == "subnet_association" and eff["names"]
                      else (f" WARNING: the subnet -> NSG association could not be read, so these "
                            f"NSG(s) were found by scanning resource group "
                            f"'{self.resource_group}' and are NOT confirmed to apply to the "
                            f"data-plane subnets: {', '.join(str(x) for x in eff['names'])}."
                            if eff["names"] else
                            " No NSG could be resolved for the data-plane subnets."))
            if not nsgs:
                return CheckResult("NSG Rules", f"{target_ip}:{target_port}", Status.WARN,
                    "INCONCLUSIVE — no NSG could be resolved for the data-plane subnet(s) "
                    f"{', '.join(str(x) for x in eff['subnets'])}. This is NOT evidence that "
                    "traffic is permitted: an NSG may exist and be unreadable."
                    + (f" Errors: {'; '.join(eff['errors'])}" if eff["errors"] else ""),
                    duration_ms=(time.time()-start)*1000,
                    metadata={"inconclusive": True, "nsg_source": eff["source"],
                              "nsg_names": eff["names"], "subnets": eff["subnets"]},
                    recommendation=("Grant the Service Principal Reader on the data-plane VNet's "
                                    "resource group so the subnet -> NSG association can be "
                                    "followed, then re-run."))
            for nsg in nsgs:
                props = nsg.get("properties", {}) or {}
                all_rules = sorted(
                    (props.get("securityRules") or []) + (props.get("defaultSecurityRules") or []),
                    key=lambda r: (r.get("properties", {}) or {}).get("priority", 0))
                for rule in all_rules:
                    rp = rule.get("properties", {}) or {}
                    if rp.get("direction") != "Outbound":
                        continue
                    port_match = False
                    dp = rp.get("destinationPortRange") or ""
                    if dp == "*" or dp == str(target_port):
                        port_match = True
                    elif "-" in dp:
                        parts = dp.split("-")
                        try:
                            port_match = int(parts[0]) <= target_port <= int(parts[1])
                        except ValueError:
                            pass
                    for pr in (rp.get("destinationPortRanges") or []):
                        if pr == "*" or pr == str(target_port):
                            port_match = True
                    if not port_match:
                        continue
                    dest = rp.get("destinationAddressPrefix") or ""
                    if dest in ("*", "0.0.0.0/0", "Internet", "VirtualNetwork") or dest == target_ip:
                        priority = rp.get("priority", 0)
                        if rp.get("access") == "Deny":
                            # A verdict built on the resource-group fallback must never read as
                            # fact — an earlier defect root #3, one resource type over. Downgrade it and say so.
                            _st = Status.WARN if eff["unverified"] else Status.FAIL
                            _pre = ("INCONCLUSIVE — " if eff["unverified"] else "")
                            return CheckResult("NSG Rules", f"{target_ip}:{target_port}", _st,
                                f"{_pre}NSG '{nsg.get('name')}' rule '{rule.get('name')}' "
                                f"(priority {priority}) DENIES outbound to port {target_port}." + _scope,
                                duration_ms=(time.time()-start)*1000,
                                metadata={"nsg_source": eff["source"], "nsg_names": eff["names"],
                                          "unverified": eff["unverified"],
                                          "inconclusive": eff["unverified"],
                                          "subnets": eff["subnets"], "rule": rule.get("name"),
                                          "priority": priority},
                                recommendation=(
                                    ("Confirm which NSG is actually attached to the data-plane subnets "
                                     "before changing anything — this rule was found by scanning the "
                                     "resource group, not by following the subnet association. ")
                                    if eff["unverified"] else "")
                                + (f"An NSG rule is blocking traffic.\nFix: Azure Portal > NSG "
                                   f"'{nsg.get('name')}' > Outbound rules > Add Allow rule for "
                                   f"{target_ip}:{target_port} with priority LOWER than {priority}"))
                        else:
                            _st = Status.WARN if eff["unverified"] else Status.PASS
                            _pre = ("INCONCLUSIVE — " if eff["unverified"] else "")
                            return CheckResult("NSG Rules", f"{target_ip}:{target_port}", _st,
                                f"{_pre}NSG '{nsg.get('name')}' rule '{rule.get('name')}' "
                                f"(priority {priority}) ALLOWS outbound to port {target_port}." + _scope,
                                duration_ms=(time.time()-start)*1000,
                                metadata={"nsg_source": eff["source"], "nsg_names": eff["names"],
                                          "unverified": eff["unverified"],
                                          "inconclusive": eff["unverified"],
                                          "subnets": eff["subnets"], "rule": rule.get("name"),
                                          "priority": priority})
            return CheckResult("NSG Rules", f"{target_ip}:{target_port}", Status.WARN,
                "No explicit NSG rule found matching this target; the platform default rules "
                "apply." + _scope,
                duration_ms=(time.time()-start)*1000,
                metadata={"nsg_source": eff["source"], "nsg_names": eff["names"],
                          "unverified": eff["unverified"], "subnets": eff["subnets"]})
        except Exception as e:
            return CheckResult("NSG Rules", f"{target_ip}:{target_port}", Status.ERROR,
                f"Could not read NSG rules: {e}", duration_ms=(time.time()-start)*1000)

    def check_routes(self, target_ip, target_host=""):
        """Question 1 of 2: is there a UDR entry that governs traffic to THIS target?

        SCOPE. This answers ONLY the target question. It cannot
        answer "does egress from this workspace work", and it must never be read that
        way: on a back-end-Private-Link workspace the diagnostic target resolves to an
        in-VNet private-endpoint address, which matches the VNet system route and never
        touches the 0.0.0.0/0 UDR. Asking the routing question about that address left
        the forced-tunnel path untraced in exactly the topology where the hub firewall
        matters most. Question 2 — "where does internet-bound traffic from the data-plane
        subnet go, and does that appliance allow what Databricks needs?" — is a property
        of the SUBNET, not of the destination, and lives in check_subnet_egress().

        Route tables come from the subnet associations (_effective_route_tables), so a
        table managed centrally in the hub resource group is found (root #2), and an
        empty input set is reported as UNKNOWN instead of as "default routing applies"
        (root #3).
        """
        start = time.time()
        name = "Route Table"
        try:
            target_addr = _ipaddress.ip_address(target_ip)
        except ValueError:
            return CheckResult(name, target_ip, Status.ERROR,
                f"'{target_ip}' is not an IP address — cannot evaluate routes for it.",
                duration_ms=(time.time()-start)*1000)
        try:
            eff = self._effective_route_tables()
        except Exception as e:
            return CheckResult(name, target_ip, Status.ERROR,
                f"Could not read route tables: {e}", duration_ms=(time.time()-start)*1000)

        in_vnet, vnet_pfx = self._target_in_vnet(target_ip)
        assoc = [a for a in eff["associations"] if a["route_table_id"]]
        table_names = [rt.get("name", "") for rt in eff["tables"]]
        base_md = {
            "route_source": eff["source"],
            "route_tables_inspected": table_names,
            "subnet_associations": eff["associations"],
            "read_errors": eff["errors"],
            "target_in_vnet": in_vnet,
            "vnet_prefix_matched": vnet_pfx,
            "inconclusive": False,
        }
        subnet_list = ", ".join(f"'{a['subnet']}'" for a in eff["associations"]) or "(none found)"

        # --- INCONCLUSIVE branches: no route table to reason about -----------------
        # A confident negative from an empty input set is the defect this check was
        # caught committing. Distinguish "I could not read the routing" and "ARM shows
        # no UDR, which is not the same as no forced tunnel" from a real verdict.
        if not eff["tables"]:
            md = dict(base_md, inconclusive=True)
            reasons = list(eff["errors"])
            if eff["vnet_error"]:
                reasons.insert(0, eff["vnet_error"])
            if reasons:
                return CheckResult(name, target_ip, Status.WARN,
                    "INCONCLUSIVE — could not determine the effective routing for this VNet: "
                    + "; ".join(reasons)
                    + ". No routing verdict is possible; this is NOT evidence that default "
                      "Azure routing applies.",
                    duration_ms=(time.time()-start)*1000, metadata=md,
                    recommendation=(
                        "Grant the diagnostic Service Principal Reader on the resource group that "
                        "OWNS the route tables (in hub-spoke topologies routing is usually managed "
                        "centrally in the hub RG, not in the workspace RG), then re-run. To settle "
                        "it without ARM: Azure Portal > Network Watcher > Effective routes > pick a "
                        "NIC in a data-plane subnet."))
            return CheckResult(name, target_ip, Status.WARN,
                f"INCONCLUSIVE — no route table is associated with the data-plane subnet(s) "
                f"{subnet_list}, so ARM shows no user-defined route. That is not proof that "
                "egress is un-tunnelled: effective routes can still be overridden by BGP "
                "advertisements from an ExpressRoute/VPN gateway or an Azure Route Server, "
                "which route tables do not reveal.",
                duration_ms=(time.time()-start)*1000, metadata=md,
                recommendation=(
                    "Read the EFFECTIVE routes to settle it: Azure Portal > Network Watcher > "
                    "Effective routes > pick a NIC in a data-plane subnet (or `az network nic "
                    "show-effective-route-table -g <managed-rg> -n <nic>`), and look for a "
                    "0.0.0.0/0 entry whose source is 'VirtualNetworkGateway'."))

        # --- Longest-prefix match over the tables that actually apply -------------
        # The same shape, elsewhere. This loop used to `continue` on any addressPrefix that
        # `ip_network` could not parse — which is EVERY SERVICE TAG. Azure accepts
        # `Storage`, `Storage.Southcentralus`, `AzureCloud`, `Internet`, `VirtualNetwork`
        # as UDR prefixes, and a tag route is normally MORE specific than 0.0.0.0/0, so
        # the route that actually governs the target was dropped from the match and the
        # check then reported the default route as if it were the governing one. Tags are
        # now expanded to their published prefixes via ARM so the longest-prefix match is
        # real; when a tag cannot be expanded it is recorded and the verdict says so
        # instead of reading as complete.
        best_match = None
        best_prefix_len = -1
        unexpanded_tags = []
        for rt in eff["tables"]:
            rt_loc = rt.get("location", "") or ""
            for route in ((rt.get("properties", {}) or {}).get("routes") or []):
                rp = route.get("properties", {}) or {}
                raw_prefix = rp.get("addressPrefix", "")
                cand = {"table": rt.get("name"), "route": route.get("name"),
                        "prefix": raw_prefix,
                        "next_hop": rp.get("nextHopType"),
                        "next_hop_ip": rp.get("nextHopIpAddress")}
                prefix = _route_prefix_net(raw_prefix)
                if prefix is None:
                    tag = str(raw_prefix).split(".")[0].lower()
                    if tag == "virtualnetwork":
                        # The VNet's own address space. Decidable without ARM.
                        if not in_vnet or not vnet_pfx:
                            continue
                        prefix = _route_prefix_net(vnet_pfx)
                        if prefix is None:
                            continue
                        cand["prefix"] = f"{raw_prefix} (VNet address space {vnet_pfx})"
                    elif tag == "internet":
                        # "Everything not in the VNet" — least specific, like 0.0.0.0/0.
                        if in_vnet:
                            continue
                        prefix = _ipaddress.ip_network("0.0.0.0/0")
                        cand["prefix"] = f"{raw_prefix} (all off-VNet destinations)"
                    else:
                        matched = service_tag_prefix_containing(
                            self._token, self.subscription_id, rt_loc, raw_prefix, target_ip)
                        if matched is None:
                            unexpanded_tags.append(cand)
                            continue
                        if not matched:
                            continue
                        prefix = _route_prefix_net(matched)
                        if prefix is None:
                            continue
                        cand["prefix"] = f"{raw_prefix} (service tag; matched prefix {matched})"
                    cand["service_tag"] = raw_prefix
                if target_addr in prefix and prefix.prefixlen > best_prefix_len:
                    best_match = cand
                    best_prefix_len = prefix.prefixlen

        tag_note = ""
        if unexpanded_tags:
            _t_items = "; ".join("'%s' %s -> %s" % (t["route"], t["prefix"], t["next_hop"])
                                 for t in unexpanded_tags)
            tag_note = (" NOTE: %d route(s) in the effective table(s) use SERVICE TAG address "
                        "prefixes that could not be expanded to address ranges from ARM (%s), so "
                        "they were NOT evaluated. A service-tag route is normally MORE specific "
                        "than 0.0.0.0/0 and would win over the route reported here, so this "
                        "verdict may be incomplete — read those routes by hand (or grant the SP "
                        "Reader so serviceTagDetails can be read) before treating it as final."
                        % (len(unexpanded_tags), _t_items))
            base_md["unexpanded_service_tag_routes"] = unexpanded_tags
            base_md["inconclusive"] = True

        scope_note = ("This check covers the TARGET only — the subnet's internet-bound "
                      "(0.0.0.0/0) egress path is reported separately by the 'Subnet Egress "
                      "Route' check.") + tag_note

        if best_match is None:
            md = dict(base_md)
            if eff["unverified"]:
                md["inconclusive"] = True
                return CheckResult(name, target_ip, Status.WARN,
                    f"INCONCLUSIVE — no UDR entry matches {target_ip} in the {len(eff['tables'])} "
                    f"route table(s) found by scanning resource group '{self.resource_group}' "
                    f"({', '.join(table_names)}), but the data-plane VNet could not be read, so "
                    "these tables are NOT confirmed to be the ones associated with the "
                    f"workspace subnets. {scope_note}",
                    duration_ms=(time.time()-start)*1000, metadata=md,
                    recommendation=(
                        "Grant the Service Principal Reader on the data-plane VNet's resource "
                        "group so the subnet -> route-table association can be followed, then "
                        "re-run."))
            if in_vnet:
                return CheckResult(name, target_ip, Status.PASS,
                    f"{target_ip} falls inside the data-plane VNet address space ({vnet_pfx}), so "
                    f"the VNet system route carries it directly (typically a private endpoint) — "
                    f"no UDR entry in {', '.join(table_names)} applies to it, and none is needed. "
                    f"This target therefore does NOT exercise the 0.0.0.0/0 forced-tunnel route. "
                    f"{scope_note}",
                    duration_ms=(time.time()-start)*1000, metadata=md)
            return CheckResult(name, target_ip, Status.WARN,
                f"No UDR entry matches {target_ip} in the route table(s) associated with the "
                f"data-plane subnet(s) {subnet_list} ({', '.join(table_names)}), and the address is "
                f"outside the VNet address space — traffic to it follows Azure system routing. "
                f"{scope_note}",
                duration_ms=(time.time()-start)*1000, metadata=md,
                recommendation=(
                    f"If {target_ip} is an on-premises address it needs an explicit route: Azure "
                    "Portal > Route tables > the table associated with the data-plane subnets > "
                    "Add route: prefix=<on-prem CIDR>, next hop=Virtual Network Gateway (or the "
                    "hub firewall's private IP)."))

        md = dict(base_md, **best_match)
        is_default_route = best_prefix_len == 0
        route_label = (f"Route '{best_match['route']}' in table '{best_match['table']}' "
                       f"({best_match['prefix']})")
        hop = best_match["next_hop"]
        if hop in ("VirtualNetworkGateway", "VnetLocal"):
            return CheckResult(name, target_ip, Status.PASS,
                f"{route_label} sends {target_ip} to {hop}. {scope_note}",
                duration_ms=(time.time()-start)*1000, metadata=md)
        if hop == "VirtualAppliance":
            nva_ip = best_match.get("next_hop_ip") or "unknown"
            if in_vnet and is_default_route:
                # Field experience: the same reasoning the Internet branch below already
                # applies. A 0.0.0.0/0 UDR "matches" an in-VNet address only because it is the
                # longest prefix among ROUTE-TABLE entries — the VNet system route for the VNet
                # prefix is more specific and wins, so the appliance is NOT on this path.
                # Without this guard the row told the customer to "confirm the appliance permits
                # TCP to 10.40.6.8, that IP forwarding is enabled on its NIC", while the sibling
                # firewall check correctly said the target "does not traverse the appliance. No
                # allow rule is required". Two amber rows sent them to a hub they had explicitly
                # said they do not administer, to fix something that was never broken.
                return CheckResult(name, target_ip, Status.PASS,
                    f"{route_label} is the subnet's default route to an NVA/firewall at {nva_ip}, "
                    f"but {target_ip} is inside the data-plane VNet address space ({vnet_pfx}), so "
                    f"the more specific VNet system route wins and this target does NOT traverse "
                    f"the appliance — typically a private endpoint. No rule on the appliance is "
                    f"required for it. The subnet's internet-bound egress through {nva_ip} is "
                    f"reported separately by the 'Subnet Egress Route' check. {scope_note}",
                    duration_ms=(time.time()-start)*1000, metadata=md)
            return CheckResult(name, target_ip, Status.WARN,
                f"{route_label} sends {target_ip} through an NVA/firewall at {nva_ip}"
                + (" (this is the subnet's DEFAULT route)" if is_default_route else "")
                + f". Reachability depends on that appliance. {scope_note}",
                duration_ms=(time.time()-start)*1000, metadata=md,
                recommendation=(
                    f"Traffic to {target_ip} is forced through the appliance at {nva_ip}. Confirm "
                    f"it permits TCP to {target_ip}, that IP forwarding is enabled on its NIC, and "
                    "that a Connected VNet peering actually carries packets to it (see the "
                    "'Subnet Egress Route' / firewall findings)."))
        if hop == "Internet":
            if in_vnet:
                # A /0 -> Internet route does not break an in-VNet destination: the system
                # route for the VNet prefix is more specific and wins. Calling this a
                # CRITICAL misroute would be a confident-wrong answer.
                return CheckResult(name, target_ip, Status.PASS,
                    f"{route_label} points at the Internet, but {target_ip} is inside the VNet "
                    f"address space ({vnet_pfx}) and the more specific VNet system route wins, so "
                    f"this target is unaffected. {scope_note}",
                    duration_ms=(time.time()-start)*1000, metadata=md)
            if target_addr.is_private and not is_default_route:
                return CheckResult(name, target_ip, Status.FAIL,
                    f"{route_label} sends traffic for the PRIVATE address {target_ip} to the "
                    f"Internet — private addresses are not routable there, so the packets are "
                    f"dropped. {scope_note}",
                    duration_ms=(time.time()-start)*1000, metadata=md,
                    recommendation=(
                        f"Azure Portal > Route tables > '{best_match['table']}' > Routes > "
                        f"'{best_match['route']}': change the next hop to 'Virtual Network "
                        "Gateway' (on-prem via ExpressRoute/VPN) or to the hub appliance's "
                        "private IP."))
            return CheckResult(name, target_ip, Status.PASS,
                f"{route_label} sends {target_ip} to the Internet (direct Azure egress). "
                f"{scope_note}",
                duration_ms=(time.time()-start)*1000, metadata=md)
        if hop == "None":
            return CheckResult(name, target_ip, Status.FAIL,
                f"{route_label} is a BLACKHOLE (next-hop 'None') — all traffic to "
                f"{best_match['prefix']}, including {target_ip}, is silently dropped."
                + (f" This route lives in resource group "
                   f"'{self._rt_resource_group(best_match['table'], eff)}'."
                   if self._rt_resource_group(best_match['table'], eff) else ""),
                duration_ms=(time.time()-start)*1000, metadata=md,
                recommendation=(
                    f"Azure Portal > Route tables > '{best_match['table']}' > Routes > "
                    f"'{best_match['route']}': delete it, or change the next hop to the correct "
                    "one ('Virtual Network Gateway', 'Virtual appliance' + the firewall's private "
                    "IP, or 'Internet'). Then wait 1-2 minutes for propagation and re-run."))
        return CheckResult(name, target_ip, Status.WARN,
            f"{route_label} has next-hop type '{hop}'. {scope_note}",
            duration_ms=(time.time()-start)*1000, metadata=md,
            recommendation=f"Unexpected route next hop type '{hop}'. Verify this route is intentional.")

    def _rt_resource_group(self, table_name, eff):
        """Resource group of a matched route table, so the customer is told WHERE to go
        (in hub-spoke it is normally not the workspace's own RG)."""
        for a in eff.get("associations", []):
            rt_id = a.get("route_table_id") or ""
            if rt_id.split("/")[-1] == table_name and "/resourceGroups/" in rt_id:
                return rt_id.split("/resourceGroups/")[1].split("/")[0]
        return ""

    # -----------------------------------------------------------------------
    # Question 2: the subnet's internet-bound egress path
    # -----------------------------------------------------------------------

    def check_subnet_egress(self):
        """Question 2 of 2: where does INTERNET-BOUND traffic from the data-plane
        subnet(s) go? This is a property of the SUBNET, not of the diagnostic target, so
        it is asked separately and unconditionally — including when the target resolves
        to an in-VNet private endpoint that never touches the default route.

        Delegates to cluster_start_checks.check_subnet_route_table, which already follows
        the subnet's own routeTable association correctly. One detector, two paths.
        """
        start = time.time()
        name = "Subnet Egress Route"
        d = self.discover_subnets()
        subnets = self.data_plane_subnets()
        if d["error"] or not subnets:
            return CheckResult(name, self.vnet_name or "(unknown VNet)", Status.WARN,
                "INCONCLUSIVE — could not determine the data-plane subnets: "
                + (d["error"] or f"VNet '{self.vnet_name}' reported no subnets")
                + ". The internet-bound egress path is therefore UNKNOWN; do not read this "
                  "as 'egress is fine'.",
                duration_ms=(time.time()-start)*1000,
                metadata={"inconclusive": True, "reason": d["error"], "default_route": None},
                recommendation=("Grant the diagnostic Service Principal Reader on the data-plane "
                                "VNet's resource group and re-run, or read Azure Portal > Network "
                                "Watcher > Effective routes for a NIC in a data-plane subnet."))
        per_subnet = []
        results = []
        for sn in subnets:
            r = check_subnet_route_table(self._token, d["vnet_id"], sn["name"])
            results.append((sn, r))
            per_subnet.append({"subnet": sn["name"], "status": r.status.value,
                               "default_route": (r.metadata or {}).get("default_route"),
                               "route_table_id": (r.metadata or {}).get("route_table_id", "")})

        # Report the most consequential subnet: a blackhole/forced tunnel on ANY
        # data-plane subnet breaks the workspace, so it must not be averaged away.
        def _rank(item):
            sn, r = item
            dr = (r.metadata or {}).get("default_route") or {}
            hop = dr.get("next_hop_type")
            if r.status == Status.FAIL or hop == "None":
                return 0
            if hop == "VirtualAppliance":
                return 1
            if r.status in (Status.ERROR, Status.WARN):
                return 2
            return 3
        sn, primary = sorted(results, key=_rank)[0]
        md = dict(primary.metadata or {})
        md["per_subnet"] = per_subnet
        md["subnet_name"] = sn["name"]
        md["vnet_id"] = d["vnet_id"]
        return CheckResult(name, f"{self.vnet_name}/{sn['name']}", primary.status,
            primary.message, recommendation=primary.recommendation,
            raw_output=primary.raw_output, metadata=md,
            duration_ms=(time.time()-start)*1000)

    def check_subnet_egress_firewall(self, subnet_egress_check, target_host="",
                                     target_ip="", topology=None):
        """Does the forced-tunnel appliance actually permit what this target needs?

        Pure delegation to cluster_start_checks.check_forced_tunnel_firewall_egress —
        same firewall resolution, same precedence-aware rule evaluation, same
        service-tag crediting (so a healthy tag-based policy is NOT reported as
        missing). The only thing added here is deciding WHICH egress category the
        connectivity target implies, because this path has no bootstrap NHC to infer
        it from, and refusing to demand anything at all when the answer would be a
        guess.
        """
        start = time.time()
        name = "Forced-Tunnel Firewall Egress"
        md = (subnet_egress_check.metadata or {}) if subnet_egress_check is not None else {}
        dr = md.get("default_route") or {}
        if dr.get("next_hop_type") != "VirtualAppliance":
            return CheckResult(name, "(no forced tunnel)", Status.SKIP,
                "The data-plane subnet has no 0.0.0.0/0 -> VirtualAppliance route, so no "
                "appliance allow-list is in the egress path.",
                duration_ms=(time.time()-start)*1000)
        nva_ip = dr.get("next_hop_ip", "") or "unknown"

        # The appliance is only the gate for traffic that actually leaves the VNet. A
        # target inside the VNet address space is served in-VNet (private endpoint, or
        # the workspace's own back-end Private Link) and never reaches the firewall, so
        # demanding an allow rule for it would be a false positive — this is the general
        # form of the back-end-Private-Link guard.
        in_vnet, vnet_pfx = self._target_in_vnet(target_ip) if target_ip else (None, "")
        if in_vnet:
            return CheckResult(name, f"NVA {nva_ip}", Status.SKIP,
                f"The subnet forced-tunnels 0.0.0.0/0 to the appliance at {nva_ip}, but the "
                f"target {target_ip} is inside the VNet address space ({vnet_pfx}) and is served "
                "in-VNet (private endpoint / back-end Private Link), so it does not traverse the "
                "appliance. No allow rule is required for this target.",
                metadata={"nva_ip": nva_ip, "target_in_vnet": True, "needed": []},
                duration_ms=(time.time()-start)*1000)

        from topology import _infer_category
        category = _infer_category(target_host)
        if category not in _REQUIRED_EGRESS:
            # No Databricks-required egress category applies to this destination, so we
            # cannot assert an allow-list gap without inventing a requirement. Report the
            # forced tunnel as the gate and say what to verify — honest, and it cannot
            # produce a CRITICAL false positive.
            return CheckResult(name, f"NVA {nva_ip}", Status.WARN,
                f"Internet-bound traffic from the data-plane subnet is forced to the appliance at "
                f"{nva_ip}, so that appliance — not the NSG — decides whether "
                f"{target_host or target_ip or 'this target'} is reachable. Its rule set was not "
                f"evaluated for this destination because {target_host or 'the target'} is not one "
                "of the Databricks-required egress categories with a known service tag / FQDN set.",
                metadata={"nva_ip": nva_ip, "needed": [], "target_host": target_host,
                          "inconclusive": True},
                duration_ms=(time.time()-start)*1000,
                recommendation=(
                    f"On the firewall/NVA at {nva_ip}, confirm an Allow rule covers the "
                    f"data-plane subnet CIDRs -> {target_host or target_ip} on the required port, "
                    "and that no higher-precedence Deny matches it. Also confirm a Connected VNet "
                    "peering carries packets to the appliance and that IP forwarding is on."))

        # Back-end Private Link carries the control plane over the databricks_ui_api
        # private endpoint, NOT through this firewall — demanding a control-plane allow
        # rule anyway is the documented CRITICAL false positive on a correctly-built SRA
        #. Reuse the topology graph's verdict; when there is no graph the answer is
        # UNKNOWN, so degrade to a WARN instead of asserting a gap (same fail-open
        # principle as topology._nva_reachability).
        backend_pl = None
        if topology is not None:
            backend_pl = bool((getattr(topology, "environment", None) or {}).get("backend_private_link"))
        if category == "control_plane" and backend_pl is None:
            return CheckResult(name, f"NVA {nva_ip}", Status.WARN,
                f"Internet-bound traffic from the data-plane subnet is forced to the appliance at "
                f"{nva_ip}. Whether the control plane actually traverses it could NOT be "
                "determined: a back-end Private Link (databricks_ui_api private endpoint) carries "
                "control-plane traffic outside the firewall, and the workspace's private-link "
                "posture is unknown here. No allow-list verdict is asserted for the control plane.",
                metadata={"nva_ip": nva_ip, "needed": [], "inconclusive": True,
                          "backend_pl_present": None},
                duration_ms=(time.time()-start)*1000,
                recommendation=(
                    "Supply the workspace ARM resource id so the topology graph can resolve the "
                    "back-end Private Link posture, then re-run. Meanwhile verify manually: if the "
                    "workspace has NO databricks_ui_api private endpoint, the firewall at "
                    f"{nva_ip} must allow the 'AzureDatabricks' service tag (or "
                    "*.azuredatabricks.net / *.databricks.com / www.databricks.com) on TCP 443."))

        return check_forced_tunnel_firewall_egress(
            self._token, subnet_egress_check, None,
            f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}",
            topology=topology,
            backend_pl_present=bool(backend_pl),
            categories=[category],
            evidence_note=(
                f"The data-plane subnet's 0.0.0.0/0 route forces traffic to "
                f"{target_host or target_ip} through this appliance regardless of the NSG."),
        )


    def check_peering(self):
        """Check VNet peering status and configuration."""
        if not self.vnet_name:
            return CheckResult("VNet Peering", "N/A", Status.SKIP,
                "VNet name not provided -- skipping peering check.",
                recommendation="Provide the Databricks VNet name to enable peering checks.")
        start = time.time()
        try:
            peerings = self._list(
                self._rg_path(f"Microsoft.Network/virtualNetworks/{self.vnet_name}/virtualNetworkPeerings"),
                self._NETWORK_API)
            if not peerings:
                # "No peerings" is benign in a standalone VNet, but it is CRITICAL when the
                # subnet forced-tunnels to an appliance that lives in another VNet: that next
                # hop is then unreachable and every egress packet is black-holed. Live on
                # In the field this was only a WARN, the correlation engine still concluded
                # all_healthy, and the customer was told "connectivity is healthy" while
                # nothing in the workspace worked. Surface the dependency explicitly.
                return CheckResult("VNet Peering", self.vnet_name, Status.WARN,
                    "No VNet peerings found.",
                    duration_ms=(time.time()-start)*1000,
                    metadata={"peering_count": 0, "not_connected": [], "no_forwarding": []},
                    recommendation=("No peering found. If this VNet forced-tunnels (0.0.0.0/0) to a "
                                    "firewall/NVA in a hub VNet, that next hop is UNREACHABLE without a "
                                    "peering and all egress is dropped — recreate the hub peering. "
                                    "Otherwise, if the target lives in a hub or on-prem via a hub:\n"
                                    "Azure Portal > Virtual networks > Peerings > Add"))
            issues = []
            details = []
            # Two DISTINCT faults, kept apart as structured metadata so the correlation
            # engine can pick the right rule and name the right object. Previously only
            # the not-Connected case recorded a name, and the rules discriminated by
            # substring-matching this check's `message` — which is just a generic
            # "N peering issue(s) found" count. Live result: a peering that
            # was Connected with allowForwardedTraffic=OFF was reported as
            # peering_broken "not in 'Connected' state" (factually wrong) and named
            # "'the peering'" (an unfilled placeholder).
            not_connected = []   # [{name, remote, state}]
            no_forwarding = []   # [{name, remote}]
            for p in peerings:
                pp = p.get("properties", {}) or {}
                name = p.get("name", "")
                remote_id = ((pp.get("remoteVirtualNetwork") or {}).get("id") or "")
                remote = remote_id.split("/")[-1] if remote_id else "unknown"
                state = pp.get("peeringState", "")
                fwd = pp.get("allowForwardedTraffic", False)
                details.append(f"{name} -> {remote}: state={state}, forwarded={fwd}, remote_gw={pp.get('useRemoteGateways', False)}")
                if state != "Connected":
                    issues.append(f"Peering '{name}' state is '{state}' (expected Connected)")
                    not_connected.append({"name": name, "remote": remote, "state": state})
                if not fwd:
                    issues.append(f"Peering '{name}' (state {state}): 'Allow forwarded traffic' is OFF "
                                  "-- traffic forwarded by an NVA/gateway in the peered VNet is dropped")
                    no_forwarding.append({"name": name, "remote": remote})
            raw = "\n".join(details)
            if issues:
                # Keep the legacy keys populated for compatibility, preferring the
                # not-Connected peering when both faults are present.
                primary = (not_connected or no_forwarding or [{}])[0]
                return CheckResult("VNet Peering", self.vnet_name, Status.FAIL,
                    f"{len(issues)} peering issue(s) found", raw_output=raw,
                    duration_ms=(time.time()-start)*1000,
                    metadata={"peering_name": primary.get("name", ""),
                              "remote_vnet": primary.get("remote", ""),
                              "not_connected": not_connected,
                              "no_forwarding": no_forwarding},
                    recommendation="Fix peering:\n" + "\n".join(f"- {i}" for i in issues) +
                    "\nAzure Portal > Virtual networks > Peerings > Edit")
            return CheckResult("VNet Peering", self.vnet_name, Status.PASS,
                f"{len(peerings)} peering(s) configured correctly", raw_output=raw,
                duration_ms=(time.time()-start)*1000)
        except Exception as e:
            return CheckResult("VNet Peering", self.vnet_name, Status.ERROR,
                f"Could not read VNet peerings: {e}", duration_ms=(time.time()-start)*1000)

    def check_private_endpoints(self, target_host):
        """Check connection states only for Private Endpoints attributable to target.

        The ARM collection is resource-group-wide. Inventory membership alone does not
        establish that a target is private-linked: a workspace RG commonly contains PEs
        for several unrelated services. Preserve the full inventory as metadata, but
        expose `pe_ips` / failures only for endpoints whose DNS configuration or target
        resource id matches `target_host`.
        """
        start = time.time()
        try:
            endpoints = self._list(self._rg_path("Microsoft.Network/privateEndpoints"), self._NETWORK_API)
            if not endpoints:
                return CheckResult("Private Endpoints", target_host, Status.PASS,
                    ("No Private Endpoints found in the resource group; this inventory "
                     f"does not establish a private path for {target_host}."),
                    duration_ms=(time.time()-start)*1000,
                    metadata={"pe_ips": [], "pe_ip_owner": {}, "pe_count": 0,
                              "target_attribution_available": True,
                              "target_pe_names": [], "all_pe_ips": [],
                              "all_pe_ip_owner": {}, "all_pe_count": 0})
            results = []
            all_pe_ips = []
            all_pe_ip_owner = {}
            target_pe_ips = []
            target_pe_ip_owner = {}
            target_pe_names = set()
            target_states = []
            for pe in endpoints:
                pe_props = pe.get("properties", {}) or {}
                pe_name = pe.get("name", "")
                target_match, match_source = _private_endpoint_matches_target(
                    pe_props, target_host)
                if target_match:
                    target_pe_names.add(pe_name)
                _this_pe_ips = []
                for dns_cfg in (pe_props.get("customDnsConfigs") or []):
                    _this_pe_ips.extend(dns_cfg.get("ipAddresses") or [])
                # customDnsConfigs is frequently EMPTY on a PE that uses a private DNS
                # zone group. Without a second source the DNS<->PE cross-check has no PE
                # IPs to compare against and silently says nothing. The PE's NIC
                # always carries the address, so fall back to it.
                if not _this_pe_ips:
                    for nic_ref in (pe_props.get("networkInterfaces") or []):
                        nic_id = nic_ref.get("id", "")
                        if not nic_id:
                            continue
                        try:
                            nic = self._get(f"https://management.azure.com{nic_id}"
                                            f"?api-version={self._NETWORK_API}")
                        except Exception:
                            continue
                        for ipc in ((nic.get("properties", {}) or {}).get("ipConfigurations") or []):
                            addr = ((ipc.get("properties", {}) or {}).get("privateIPAddress") or "")
                            if addr:
                                _this_pe_ips.append(addr)
                for _ip in _this_pe_ips:
                    all_pe_ip_owner.setdefault(_ip, pe_name)
                    if target_match:
                        target_pe_ip_owner.setdefault(_ip, pe_name)
                all_pe_ips.extend(_this_pe_ips)
                if target_match:
                    target_pe_ips.extend(_this_pe_ips)
                conns = ((pe_props.get("privateLinkServiceConnections") or [])
                         + (pe_props.get("manualPrivateLinkServiceConnections") or []))
                for conn in conns:
                    cp = conn.get("properties", {}) or {}
                    state = ((cp.get("privateLinkServiceConnectionState") or {}).get("status")) or "Unknown"
                    relation = f"target match: {match_source}" if target_match else "unrelated to target"
                    results.append(
                        f"PE '{pe_name}' / '{conn.get('name', '')}': {state} ({relation})")
                    if target_match:
                        target_states.append((state, pe_name))

            metadata = {
                # Existing consumers use `pe_ips`; its meaning is now deliberately
                # target-scoped. The RG-wide inventory remains available under explicit
                # `all_*` keys for evidence/debugging, never for target conclusions.
                "pe_ips": sorted(set(target_pe_ips)),
                "pe_ip_owner": target_pe_ip_owner,
                "pe_count": len(target_pe_names),
                "target_attribution_available": True,
                "target_pe_names": sorted(target_pe_names),
                "all_pe_ips": sorted(set(all_pe_ips)),
                "all_pe_ip_owner": all_pe_ip_owner,
                "all_pe_count": len(endpoints),
            }
            rejected = [name for state, name in target_states if state.lower() == "rejected"]
            if rejected:
                return CheckResult("Private Endpoints", target_host, Status.FAIL,
                    f"PE '{rejected[0]}' connection for {target_host} is REJECTED",
                    raw_output="\n".join(results), duration_ms=(time.time()-start)*1000,
                    metadata=metadata,
                    recommendation="Private Endpoint connection was rejected.\nFix: Target resource owner must approve it:\nAzure Portal > Resource > Networking > Private endpoint connections > Approve")
            pending = [name for state, name in target_states if state.lower() == "pending"]
            if pending:
                return CheckResult("Private Endpoints", target_host, Status.WARN,
                    f"PE '{pending[0]}' connection for {target_host} is PENDING approval",
                    raw_output="\n".join(results), duration_ms=(time.time()-start)*1000,
                    metadata=metadata,
                    recommendation="PE is pending. Resource owner must approve:\nAzure Portal > Resource > Networking > Private endpoint connections > Approve")
            if target_pe_names:
                message = (f"{len(target_pe_names)} PE(s) attributed to {target_host}, "
                           "all approved")
            else:
                message = (f"{len(endpoints)} PE(s) exist in the resource group, but none "
                           f"is attributable to {target_host}; unrelated endpoints do not "
                           "establish that this target is private-linked")
            return CheckResult("Private Endpoints", target_host, Status.PASS,
                message, raw_output="\n".join(results),
                duration_ms=(time.time()-start)*1000,
                metadata=metadata)
        except Exception as e:
            return CheckResult("Private Endpoints", target_host, Status.ERROR,
                f"Could not read PEs: {e}", duration_ms=(time.time()-start)*1000)

    def check_dns_zones(self, target_host):
        """Check Private DNS Zone configuration and VNet linking."""
        start = time.time()
        try:
            zones = self._list(
                f"/subscriptions/{self.subscription_id}/providers/Microsoft.Network/privateDnsZones",
                self._PRIVATE_DNS_API)
            if not zones:
                return CheckResult("Private DNS Zones", target_host, Status.WARN,
                    "No Private DNS Zones found.", duration_ms=(time.time()-start)*1000)
            zone_names = [z.get("name", "") for z in zones]
            issues = []
            # Only zones RELEVANT TO THIS TARGET may produce a finding. The list above is
            # subscription-wide, so an unfiltered loop fails on zones the workspace has no
            # reason to be linked to — live on a healthy SRA it flagged
            # privatelink.vaultcore.azure.net (a hub-only Key Vault zone) and a second
            # spoke's zones, producing "DNS Zone not linked to Databricks VNet" and advice
            # to link Key Vault's zone to the Databricks VNet. In a shared subscription it
            # would also fail on other teams' zones. A zone is relevant only when its
            # suffix actually covers the host we are diagnosing.
            relevant = [z for z in zones
                        if _dns_zone_covers_host(z.get("name", ""), target_host)]
            if not relevant:
                return CheckResult("Private DNS Zones", target_host, Status.PASS,
                    f"No Private DNS Zone covers {target_host} — not a Private Link target, "
                    "so zone linking is not part of this path.",
                    raw_output="Zones in subscription: " + ", ".join(zone_names),
                    duration_ms=(time.time()-start)*1000)
            # Resolution needs ONE covering zone linked to our VNet — not every copy of it.
            # A subscription commonly holds many same-named privatelink zones (one per team
            # or per environment); requiring all of them to be linked to this workspace's
            # VNet fails on other people's zones. So: PASS if ANY covering zone is linked.
            linked, unlinked = [], []
            for zone in relevant:
                zone_name = zone.get("name", "")
                zone_id = zone.get("id", "")
                if not ("privatelink" in zone_name and zone_id):
                    continue
                try:
                    links = self._list(f"{zone_id}/virtualNetworkLinks", self._PRIVATE_DNS_API)
                    vnet_linked = any(
                        self.vnet_name.lower() in
                        (((l.get("properties", {}) or {}).get("virtualNetwork") or {}).get("id", "") or "").lower()
                        for l in links
                    ) if self.vnet_name else None
                    if self.vnet_name:
                        (linked if vnet_linked else unlinked).append(zone_id)
                except Exception:
                    pass
            raw = ("Zones covering the target: "
                   + ", ".join(sorted({z.get("name", "") for z in relevant}))
                   + f" | copies linked to '{self.vnet_name}': {len(linked)}"
                   + f" | copies not linked: {len(unlinked)}")
            if self.vnet_name and not linked and unlinked:
                issues = [f"No Private DNS zone covering {target_host} is linked to VNet "
                          f"'{self.vnet_name}' ({len(unlinked)} covering zone(s) exist elsewhere)"]
                return CheckResult("Private DNS Zones", target_host, Status.FAIL,
                    "DNS Zone not linked to Databricks VNet", raw_output=raw + "\n" + "\n".join(issues),
                    duration_ms=(time.time()-start)*1000,
                    recommendation="A Private DNS Zone for this target exists but none is linked to your VNet.\nFix: Azure Portal > Private DNS zones > Virtual network links > Add link to " + self.vnet_name)
            msg = (f"Zone covering {target_host} is linked to '{self.vnet_name}'"
                   if linked else f"{len(relevant)} zone(s) covering {target_host} found")
            return CheckResult("Private DNS Zones", target_host, Status.PASS, msg,
                raw_output=raw, duration_ms=(time.time()-start)*1000)
        except Exception as e:
            return CheckResult("Private DNS Zones", target_host, Status.ERROR,
                f"Could not read DNS zones: {e}", duration_ms=(time.time()-start)*1000)


def _dns_zone_covers_host(zone_name, host):
    """True when `zone_name` is the Private DNS zone that would resolve `host`.

    A Private Link zone is named for the public suffix it shadows, e.g.
    `privatelink.dfs.core.windows.net` resolves `myacct.dfs.core.windows.net`, and
    `privatelink.azuredatabricks.net` resolves `adb-123.4.azuredatabricks.net`. So a
    zone is relevant only when the host actually ends with the zone's suffix once the
    leading `privatelink.` label is removed.

    This exists to keep the zone check from reporting zones the workspace has no reason
    to be linked to (Key Vault's zone, another spoke's zones, another team's zones in a
    shared subscription) as a failure of THIS diagnosis.
    """
    z = (zone_name or "").strip().lower().rstrip(".")
    h = (host or "").strip().lower().rstrip(".")
    if not z or not h:
        return False
    suffix = z[len("privatelink."):] if z.startswith("privatelink.") else z
    if not suffix:
        return False
    return h == suffix or h.endswith("." + suffix)


def _canonical_private_fqdn(host):
    """Normalise public/private-link aliases for exact target attribution."""
    h = (host or "").strip().lower().rstrip(".")
    return h.replace(".privatelink.", ".", 1)


def _private_endpoint_matches_target(pe_properties, target_host):
    """Return (matched, evidence source) for one PE and one hostname.

    Reuses `infer_resource_type`, the NCC detector that already maps supported Azure
    service hostnames to resource type/name. An exact custom-DNS FQDN is even stronger
    evidence and also covers types that detector does not yet know. No substring-only
    match is accepted: `pypi.org` cannot inherit an unrelated workspace PE.
    """
    props = pe_properties or {}
    target = _canonical_private_fqdn(target_host)
    if not target:
        return False, ""
    for cfg in (props.get("customDnsConfigs") or []):
        fqdn = cfg.get("fqdn", "") if isinstance(cfg, dict) else ""
        if _canonical_private_fqdn(fqdn) == target:
            return True, "customDnsConfigs.fqdn"

    resource_type, _group, resource_name = infer_resource_type(target_host, 0)
    if resource_type == "unknown" or not resource_name:
        return False, ""
    expected_provider = "/providers/" + resource_type.strip("/").lower() + "/"
    expected_name = resource_name.strip("/").lower()
    conns = ((props.get("privateLinkServiceConnections") or [])
             + (props.get("manualPrivateLinkServiceConnections") or []))
    for conn in conns:
        cp = (conn.get("properties", {}) or {}) if isinstance(conn, dict) else {}
        resource_id = (cp.get("privateLinkServiceId", "") or "").strip().lower().rstrip("/")
        if expected_provider in resource_id and resource_id.rsplit("/", 1)[-1] == expected_name:
            return True, "privateLinkServiceId"
    return False, ""


def _privatelink_zone_for(host):
    """The privatelink DNS zone that should serve `host`, derived from the hostname.

    The recommendation used to hardcode `privatelink.database.windows.net` regardless of
    the target, which pointed a Databricks-workspace or storage problem at a SQL zone.
    """
    h = (host or "").lower().rstrip(".")
    table = [
        (".azuredatabricks.net", "privatelink.azuredatabricks.net"),
        (".blob.core.windows.net", "privatelink.blob.core.windows.net"),
        (".dfs.core.windows.net", "privatelink.dfs.core.windows.net"),
        (".database.windows.net", "privatelink.database.windows.net"),
        (".vault.azure.net", "privatelink.vaultcore.azure.net"),
        (".servicebus.windows.net", "privatelink.servicebus.windows.net"),
    ]
    for suffix, zone in table:
        if h.endswith(suffix):
            return zone
    return "the matching privatelink.* zone for this service"


def cross_check_dns_pe_alignment(dns_result, pe_result):
    """Cross-check the DNS-authoritative address against the Private Endpoint IPs.

    Two distinct misalignments, both meaning traffic does not reach the PE:
      * resolved address is PUBLIC while a PE exists -> the private path is bypassed;
      * resolved address is PRIVATE but is not any PE's IP -> a stale/wrong A record, or
        a record pointing at something else entirely.

    the second case existed but could not fire in practice, because the only source
    of `pe_ips` was `customDnsConfigs` (frequently empty on a zone-group PE) and because
    the whole function required the DNS check to be PASS — which it no longer is when the
    node's local resolver disagrees with DNS. Both are fixed, and the comparison is now
    made over the whole SET of answers so a legitimately multi-record hostname or a
    multi-PE workspace does not produce a false positive: it fires only when NOT ONE
    resolved address matches ANY PE IP.

    Returns a list of CheckResults (possibly empty).
    """
    results = []
    if not dns_result or not pe_result:
        return results
    # A DNS row is usable when it produced addresses — including the WARN case where a
    # local override was detected and DNS won (that is exactly when this matters most).
    if dns_result.status not in (Status.PASS, Status.WARN):
        return results
    if pe_result.status not in (Status.PASS, Status.WARN):
        return results

    resolved_ips = list((dns_result.metadata or {}).get("ips") or [])
    if not resolved_ips and "Resolved to " in dns_result.message:
        ip_part = dns_result.message.split("Resolved to ", 1)[1]
        resolved_ips = [ip.strip() for ip in ip_part.split(",")]
    parsed = []
    for ip_str in resolved_ips:
        try:
            parsed.append((ip_str, _ipaddress.ip_address(ip_str)))
        except ValueError:
            continue
    if not parsed:
        return results

    pe_ips = [str(x) for x in ((pe_result.metadata or {}).get("pe_ips") or [])]
    pe_owner = (pe_result.metadata or {}).get("pe_ip_owner") or {}
    pe_count = (pe_result.metadata or {}).get("pe_count")
    # New reports carry target-scoped PE metadata. When the resource-group inventory
    # contains only unrelated endpoints, there is no target PE to align DNS against and
    # therefore no Private-Link conclusion to make. Older saved reports lack the marker
    # and retain their conservative legacy behaviour.
    if ((pe_result.metadata or {}).get("target_attribution_available")
            and not pe_count):
        return results
    zone = _privatelink_zone_for(dns_result.target)
    name = "DNS \u2192 Private Endpoint Alignment"

    # PUBLIC resolution while a PE exists — the private path is bypassed entirely.
    public = [ip for ip, obj in parsed if not obj.is_private]
    if public:
        pe_ip_info = f" (PE IP: {pe_ips[0]})" if pe_ips else ""
        results.append(CheckResult(
            check_name=name, target=dns_result.target, status=Status.FAIL,
            message=(f"DNS resolves to public IP {public[0]} but a Private Endpoint exists"
                     f"{pe_ip_info}. Traffic bypasses the PE and goes over the public internet."),
            metadata={"resolved_ips": resolved_ips, "pe_ips": pe_ips, "public_ips": public},
            recommendation=(
                f"Create/attach the `{zone}` Private DNS zone, link it to the Databricks VNet, and "
                "point the A record at the PE's private IP so the name resolves privately."),
        ))
        return results

    # Every answer is private. Does any of them actually land on a PE?
    if not pe_ips:
        results.append(CheckResult(
            check_name=name, target=dns_result.target, status=Status.WARN,
            message=(f"DNS resolves to {', '.join(ip for ip, _ in parsed)} and "
                     f"{('%d target Private Endpoint(s) exist' % pe_count) if pe_count else 'a target Private Endpoint exists'}, "
                     "but none of their private IPs could be read (no customDnsConfigs and the PE "
                     "NICs were not readable), so alignment is INCONCLUSIVE — this is NOT a "
                     "confirmation that DNS points at the Private Endpoint."),
            metadata={"resolved_ips": resolved_ips, "pe_ips": [], "inconclusive": True},
            recommendation=(
                "Grant the diagnostic Service Principal Reader on the resource group holding the "
                "private endpoints (their NICs live in the same RG), then re-run. Or compare "
                f"manually: Azure Portal > Private DNS zones > {zone} > Records against Private "
                "endpoint > DNS configuration."),
        ))
        return results

    matched = [ip for ip, _ in parsed if ip in pe_ips]
    if matched:
        return results          # at least one answer is a PE IP — aligned, say nothing.

    unmatched = [ip for ip, _ in parsed]
    results.append(CheckResult(
        check_name=name, target=dns_result.target, status=Status.FAIL,
        message=(
            f"DNS resolves {dns_result.target} to {', '.join(unmatched)}, and NONE of those "
            f"addresses is a Private Endpoint IP for this workspace/service "
            f"(PE IPs: {', '.join(pe_ips)}"
            + (f"; owners: {', '.join(f'{k}->{v}' for k, v in sorted(pe_owner.items()))}"
               if pe_owner else "")
            + "). The address is private, so this is not a public-internet bypass — it is a WRONG "
              "private target: a stale A record, a record created for a different resource, or a "
              "local/hub forwarder answering with something else. Any NSG, route or firewall "
              "finding about these addresses is about the wrong subnet."),
        metadata={"resolved_ips": resolved_ips, "pe_ips": pe_ips,
                  "unmatched_private_ips": unmatched, "pe_ip_owner": pe_owner},
        recommendation=(
            f"Azure Portal > Private DNS zones > {zone} > Records: point the A record for "
            f"{dns_result.target} at one of the Private Endpoint IPs ({', '.join(pe_ips)}), and "
            "confirm the zone is linked to the VNet doing the resolving (in hub-spoke, also check "
            "the hub forwarder / custom DNS servers). Then re-run — the NSG and route findings "
            "will change target."),
    ))
    return results
