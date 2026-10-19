"""Storage access checks for the Network Connectivity Doctor.

Diagnoses Unity Catalog storage permission issues (PERMISSION_DENIED,
User Delegation Key errors) by verifying Azure RBAC role assignments
on storage accounts via the ARM REST API.

Importable module: sibling scripts resolve via sys.path (the skill dir is
inserted by SKILL.md Step 1). Also works exec-loaded for back-compat.
No pip dependencies beyond 'requests' (already available).
"""

import time

from models import CheckResult, DiagnosticReport, Status, derive_overall_status


# ---------------------------------------------------------------------------
# Well-known Azure role definition IDs for storage
# ---------------------------------------------------------------------------

_STORAGE_ROLE_DEFS = {
    "Storage Blob Delegator":       "db58b8e5-c6ad-4a2a-8342-4190687cbf4a",
    "Storage Blob Data Contributor": "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
    "Storage Blob Data Reader":     "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
    "Storage Blob Data Owner":      "b7e6dc6d-f1e8-4753-8033-0f276bb0955b",
}

_ROLE_ID_TO_NAME = {v: k for k, v in _STORAGE_ROLE_DEFS.items()}


# ---------------------------------------------------------------------------
# ARM Authentication
# ---------------------------------------------------------------------------

def _looks_like_jwt(tok):
    """A real ARM access token is a JWT: three non-empty dot-separated segments,
    and comfortably longer than ~100 chars. We have seen the AAD endpoint
    intermittently hand back an empty/short string that 401s on first use but
    works on a re-mint — treat anything that doesn't look like a JWT as invalid
    so the retry loop re-mints instead of returning a dud token.
    """
    if not tok or not isinstance(tok, str):
        return False
    if len(tok) < 100:
        return False
    parts = tok.split(".")
    return len(parts) == 3 and all(parts)


class _ArmTokenResult(str):
    """The return type of get_arm_token: the value IS the token string, while
    result["token"] / result["error"] / result.token / result.error keep the
    dict-style API working.

    Why: callers in the scripts read result["token"], but ad-hoc code written at
    diagnosis time repeatedly treated the old dict return as the token itself —
    len(result) printed 2 (the dict's key count) and was misread as "AAD minted a
    2-char token" (seen in a real session). As a str subclass,
    len() is the real token length, bool() is "do I have a token", and f-string
    interpolation into an Authorization header just works.
    """

    def __new__(cls, token, error=""):
        obj = super().__new__(cls, token or "")
        obj._error = error or ""
        return obj

    @property
    def token(self):
        return str(self)

    @property
    def error(self):
        return self._error

    def __getitem__(self, key):
        if key == "token":
            return str(self)
        if key == "error":
            return self._error
        return super().__getitem__(key)

    def get(self, key, default=None):
        if key in ("token", "error"):
            return self[key]
        return default


def get_arm_token(tenant_id, client_id, client_secret, max_attempts=3):
    """Authenticate an Azure Service Principal and return an ARM access token.

    Robust against intermittent AAD flakiness: retries up to `max_attempts` times
    with a short backoff when the mint raises, returns a non-200, or returns a
    token that does not look like a JWT (empty / too short / not 3 dot-separated
    segments).

    Returns:
        _ArmTokenResult — a str whose value IS the token (empty on failure), with
        ["token"] / ["error"] / .token / .error also available so dict-style
        callers keep working unchanged.
        On success: token string, error "".
        On final failure after retries: empty token, error "<clear, actionable
        message including the last HTTP status / AADSTS code>". Never returns a
        short/empty token with an empty error. Secret values are never logged.
    """
    return _get_aad_token(tenant_id, client_id, client_secret,
                          "https://management.azure.com/.default", max_attempts)


# Azure Databricks first-party application id — AAD tokens minted with this
# audience authenticate against BOTH workspace APIs and the account console API
# (accounts.azuredatabricks.net), provided the SP has the corresponding access
# (account admin / account-level permission for account APIs).
# Public because the account-layer snapshot script (serverless_ncc_checks
# .generate_account_dump_script) has to embed this same id in an `az account
# get-access-token --resource ...` line. A second literal copy of a magic GUID is how
# the two halves of one flow drift apart, so there is one name for it.
AZURE_DATABRICKS_APP_ID = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"
_AZURE_DATABRICKS_APP_ID = AZURE_DATABRICKS_APP_ID   # back-compat alias


def get_databricks_account_token(tenant_id, client_id, client_secret, max_attempts=3):
    """Mint an AAD token for the Azure Databricks audience (account/workspace APIs).

    Same return contract and retry/JWT-validation behavior as get_arm_token.
    Used by the NCC inspection path: the SP must be an ACCOUNT ADMIN (or hold
    account-level permission) for accounts.azuredatabricks.net calls to succeed —
    a 403 there means the SP lacks account access, not a network problem.
    """
    return _get_aad_token(tenant_id, client_id, client_secret,
                          f"{_AZURE_DATABRICKS_APP_ID}/.default", max_attempts)


def _get_aad_token(tenant_id, client_id, client_secret, scope, max_attempts=3):
    import requests as _req

    last_error = "unknown error"
    for attempt in range(1, max_attempts + 1):
        try:
            resp = _req.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": scope,
                },
                timeout=10,
            )
            if resp.status_code != 200:
                # Surface the AADSTS code/description from the body (no secrets in it).
                detail = ""
                try:
                    body = resp.json()
                    detail = body.get("error_description") or body.get("error") or ""
                except Exception:
                    detail = (resp.text or "")[:200]
                last_error = f"HTTP {resp.status_code}" + (f": {detail.splitlines()[0]}" if detail else "")
            else:
                token = ""
                try:
                    token = resp.json().get("access_token", "") or ""
                except Exception as e:
                    last_error = f"could not parse token response: {e}"
                    token = ""
                if _looks_like_jwt(token):
                    return _ArmTokenResult(token, "")
                if token:
                    last_error = f"received a malformed token (len={len(token)}, not a JWT)"
                elif not last_error or last_error == "unknown error":
                    last_error = "token response contained no access_token"
        except Exception as e:
            last_error = f"{e.__class__.__name__}: {e}"

        if attempt < max_attempts:
            time.sleep(attempt)  # ~1s, then ~2s backoff

    return _ArmTokenResult(
        "",
        (
            f"ARM token acquisition failed after {max_attempts} attempts: {last_error}. "
            "Verify the SP's tenant_id/client_id/client_secret are correct and current "
            "(rotate the secret if it may be expired), and that the SP exists in this tenant."
        ),
    )


# ---------------------------------------------------------------------------
# Databricks API helpers (workspace-scoped)
# ---------------------------------------------------------------------------

def get_table_storage_info(workspace_url, token, full_table_name):
    """Get the storage location and account for a Unity Catalog table.

    Args:
        workspace_url: e.g. "adb-123.4.azuredatabricks.net"
        token: Databricks API token
        full_table_name: "catalog.schema.table"

    Returns:
        dict with keys: catalog_name, storage_location, storage_account, container, error
    """
    import requests as _req

    base = f"https://{workspace_url}" if not workspace_url.startswith("https://") else workspace_url
    result = {"catalog_name": "", "storage_location": "", "storage_account": "", "container": "", "error": ""}

    # Extract catalog name from full_table_name
    parts = full_table_name.replace("`", "").split(".")
    if len(parts) >= 1:
        result["catalog_name"] = parts[0]

    try:
        resp = _req.get(
            f"{base}/api/2.1/unity-catalog/tables/{full_table_name}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        if resp.status_code != 200:
            result["error"] = f"Could not get table info: HTTP {resp.status_code}"
            return result

        table = resp.json()
        loc = table.get("storage_location", "")
        result["storage_location"] = loc
        result["catalog_name"] = table.get("catalog_name", result["catalog_name"])

        # Parse abfss://container@account.dfs.core.windows.net/...
        if "@" in loc and ".dfs.core.windows.net" in loc:
            result["container"] = loc.split("://")[1].split("@")[0] if "://" in loc else ""
            result["storage_account"] = loc.split("@")[1].split(".dfs.core.windows.net")[0]
        elif "@" in loc and ".blob.core.windows.net" in loc:
            result["container"] = loc.split("://")[1].split("@")[0] if "://" in loc else ""
            result["storage_account"] = loc.split("@")[1].split(".blob.core.windows.net")[0]

    except Exception as e:
        result["error"] = f"Error getting table info: {e}"

    return result


def get_access_connector_for_table(workspace_url, token, catalog_name):
    """Trace the credential chain: catalog → storage credential → Access Connector.

    Checks the catalog first for a custom storage credential, then falls back
    to the metastore's default. This is deterministic — it does NOT guess by
    listing all Access Connectors in the subscription.

    Args:
        workspace_url: Databricks workspace URL
        token: Databricks API token
        catalog_name: Name of the catalog containing the table

    Returns:
        dict with keys: access_connector_id, credential_name, credential_source
                        (\"catalog\" or \"metastore\"), metastore_id, error
    """
    import requests as _req

    base = f"https://{workspace_url}" if not workspace_url.startswith("https://") else workspace_url
    headers = {"Authorization": f"Bearer {token}"}
    result = {
        "access_connector_id": "",
        "credential_name": "",
        "credential_source": "",
        "metastore_id": "",
        "error": "",
    }

    try:
        # Step 1: Check catalog for a custom storage credential
        cat_resp = _req.get(
            f"{base}/api/2.1/unity-catalog/catalogs/{catalog_name}",
            headers=headers, timeout=15,
        )
        catalog_credential = ""
        if cat_resp.status_code == 200:
            cat = cat_resp.json()
            # Catalogs with isolated storage have their own credential
            # The field varies by API version; check common fields
            catalog_credential = (
                cat.get("storage_root_credential_name", "")
                or cat.get("connection_name", "")
            )
            if catalog_credential:
                result["credential_source"] = "catalog"
                result["credential_name"] = catalog_credential

        # Step 2: If catalog has no custom credential, use metastore default
        if not catalog_credential:
            meta_resp = _req.get(
                f"{base}/api/2.1/unity-catalog/metastore_summary",
                headers=headers, timeout=15,
            )
            if meta_resp.status_code != 200:
                result["error"] = f"Could not get metastore summary: HTTP {meta_resp.status_code}"
                return result

            meta = meta_resp.json()
            result["metastore_id"] = meta.get("metastore_id", "")
            result["credential_name"] = meta.get("storage_root_credential_name", "")
            result["credential_source"] = "metastore"

            if not result["credential_name"]:
                result["error"] = "No storage root credential on metastore and no catalog-level credential found"
                return result

        # Step 3: Get the storage credential → Access Connector
        cred_resp = _req.get(
            f"{base}/api/2.1/unity-catalog/storage-credentials/{result['credential_name']}",
            headers=headers, timeout=15,
        )
        if cred_resp.status_code != 200:
            result["error"] = f"Could not get storage credential '{result['credential_name']}': HTTP {cred_resp.status_code}"
            return result

        cred = cred_resp.json()
        ami = cred.get("azure_managed_identity", {})
        result["access_connector_id"] = ami.get("access_connector_id", "")

        if not result["access_connector_id"]:
            if cred.get("azure_service_principal"):
                result["error"] = (
                    f"Storage credential '{result['credential_name']}' uses a Service Principal, "
                    "not an Access Connector. SP-based credentials are managed differently."
                )
            else:
                result["error"] = f"Could not find Access Connector in credential '{result['credential_name']}'"

    except Exception as e:
        result["error"] = f"Error tracing credential chain: {e}"

    return result


def get_metastore_access_connector(workspace_url, token):
    """Get the Access Connector used by the metastore's default storage credential.

    DEPRECATED: Use get_access_connector_for_table() instead, which checks
    catalog-level credentials first before falling back to the metastore.

    Returns:
        dict with keys: access_connector_id, credential_name, credential_id,
                        metastore_id, error
    """
    import requests as _req

    base = f"https://{workspace_url}" if not workspace_url.startswith("https://") else workspace_url
    headers = {"Authorization": f"Bearer {token}"}
    result = {
        "access_connector_id": "",
        "credential_name": "",
        "credential_id": "",
        "metastore_id": "",
        "error": "",
    }

    try:
        resp = _req.get(
            f"{base}/api/2.1/unity-catalog/metastore_summary",
            headers=headers, timeout=15,
        )
        if resp.status_code != 200:
            result["error"] = f"Could not get metastore summary: HTTP {resp.status_code}"
            return result

        meta = resp.json()
        result["metastore_id"] = meta.get("metastore_id", "")
        result["credential_name"] = meta.get("storage_root_credential_name", "")
        result["credential_id"] = meta.get("storage_root_credential_id", "")

        if not result["credential_name"]:
            result["error"] = "No storage root credential configured on metastore"
            return result

        cred_resp = _req.get(
            f"{base}/api/2.1/unity-catalog/storage-credentials/{result['credential_name']}",
            headers=headers, timeout=15,
        )
        if cred_resp.status_code != 200:
            result["error"] = f"Could not get storage credential details: HTTP {cred_resp.status_code}"
            return result

        cred = cred_resp.json()
        ami = cred.get("azure_managed_identity", {})
        result["access_connector_id"] = ami.get("access_connector_id", "")

        if not result["access_connector_id"]:
            if cred.get("azure_service_principal"):
                result["error"] = "Storage credential uses a Service Principal, not an Access Connector"
            else:
                result["error"] = "Could not determine Access Connector from storage credential"

    except Exception as e:
        result["error"] = f"Error getting metastore info: {e}"

    return result


# ---------------------------------------------------------------------------
# Azure ARM helpers (require ARM token from get_arm_token)
# ---------------------------------------------------------------------------

def resolve_access_connector_principal(arm_token, access_connector_id):
    """Resolve an Access Connector ARM resource ID to its managed identity principal ID.

    Args:
        arm_token: Azure ARM bearer token
        access_connector_id: Full ARM resource ID, e.g.
            /subscriptions/.../providers/Microsoft.Databricks/accessConnectors/my-ac

    Returns:
        dict with keys: principal_id, identity_type, name, error
    """
    import requests as _req

    result = {"principal_id": "", "identity_type": "", "name": "", "error": ""}

    try:
        resp = _req.get(
            f"https://management.azure.com{access_connector_id}?api-version=2024-05-01",
            headers={"Authorization": f"Bearer {arm_token}"},
            timeout=15,
        )
        if resp.status_code == 404:
            result["error"] = f"Access Connector not found at {access_connector_id}"
            return result
        if resp.status_code == 403:
            result["error"] = "SP lacks permission to read the Access Connector (needs Reader on the resource)"
            return result
        if resp.status_code != 200:
            result["error"] = f"Could not get Access Connector: HTTP {resp.status_code}"
            return result

        ac = resp.json()
        identity = ac.get("identity", {})
        result["principal_id"] = identity.get("principalId", "")
        result["identity_type"] = identity.get("type", "")
        result["name"] = ac.get("name", "")

        if not result["principal_id"]:
            result["error"] = "Access Connector has no managed identity principal ID"

    except Exception as e:
        result["error"] = f"Error resolving Access Connector: {e}"

    return result


def find_storage_account_scope(arm_token, storage_account_name):
    """Find a storage account's ARM scope by searching across accessible subscriptions.

    Args:
        arm_token: Azure ARM bearer token
        storage_account_name: Storage account name (e.g. "mystorage")

    Returns:
        dict with keys: scope, subscription_id, resource_group, location, error
    """
    import requests as _req

    result = {"scope": "", "subscription_id": "", "resource_group": "", "location": "", "error": ""}
    headers = {"Authorization": f"Bearer {arm_token}"}

    try:
        # List subscriptions
        subs_resp = _req.get(
            "https://management.azure.com/subscriptions?api-version=2020-01-01",
            headers=headers, timeout=15,
        )
        if subs_resp.status_code != 200:
            result["error"] = f"Could not list subscriptions: HTTP {subs_resp.status_code}"
            return result

        subscriptions = subs_resp.json().get("value", [])

        for sub in subscriptions:
            sub_id = sub.get("subscriptionId", "")
            # List storage accounts in this subscription
            sa_resp = _req.get(
                f"https://management.azure.com/subscriptions/{sub_id}"
                f"/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
                headers=headers, timeout=15,
            )
            if sa_resp.status_code != 200:
                continue

            for sa in sa_resp.json().get("value", []):
                if sa.get("name", "").lower() == storage_account_name.lower():
                    sa_id = sa.get("id", "")
                    rg = ""
                    if "/resourceGroups/" in sa_id:
                        rg = sa_id.split("/resourceGroups/")[1].split("/")[0]
                    result["scope"] = sa_id
                    result["subscription_id"] = sub_id
                    result["resource_group"] = rg
                    result["location"] = sa.get("location", "")
                    return result

        result["error"] = (
            f"Storage account '{storage_account_name}' not found in any accessible subscription. "
            f"Searched {len(subscriptions)} subscription(s). "
            "The SP may lack Reader role on the subscription containing this storage account."
        )

    except Exception as e:
        result["error"] = f"Error finding storage account: {e}"

    return result


def check_storage_roles(arm_token, scope, principal_id):
    """Check Azure RBAC role assignments for a principal on a storage account.

    Args:
        arm_token: Azure ARM bearer token
        scope: Full ARM scope of the storage account
        principal_id: The managed identity's principal (object) ID

    Returns:
        CheckResult with role assignment details in metadata:
            found_roles, missing_roles, has_delegator, has_data_access
    """
    import requests as _req

    start = time.time()
    target = scope.split("/")[-1] if "/" in scope else scope

    try:
        url = (
            f"https://management.azure.com{scope}"
            f"/providers/Microsoft.Authorization/roleAssignments"
            f"?api-version=2022-04-01"
            f"&$filter=principalId eq '{principal_id}'"
        )
        resp = _req.get(
            url,
            headers={"Authorization": f"Bearer {arm_token}"},
            timeout=15,
        )
        if resp.status_code == 403:
            return CheckResult(
                "Storage Role Assignments", target, Status.ERROR,
                "SP lacks permission to read role assignments (needs Azure Reader on the storage account scope or a parent scope)",
                duration_ms=(time.time() - start) * 1000,
            )
        if resp.status_code != 200:
            return CheckResult(
                "Storage Role Assignments", target, Status.ERROR,
                f"Could not list role assignments: HTTP {resp.status_code}",
                duration_ms=(time.time() - start) * 1000,
            )

        assignments = resp.json().get("value", [])

        found_roles = []
        found_role_ids = set()
        for a in assignments:
            props = a.get("properties", {})
            role_def_id = props.get("roleDefinitionId", "").split("/")[-1]
            role_name = _ROLE_ID_TO_NAME.get(role_def_id, role_def_id[:12] + "...")
            found_roles.append(role_name)
            found_role_ids.add(role_def_id)

        has_delegator = _STORAGE_ROLE_DEFS["Storage Blob Delegator"] in found_role_ids
        has_data_access = any(
            _STORAGE_ROLE_DEFS[r] in found_role_ids
            for r in ("Storage Blob Data Contributor", "Storage Blob Data Reader", "Storage Blob Data Owner")
        )

        missing = []
        if not has_delegator:
            missing.append("Storage Blob Delegator")
        if not has_data_access:
            missing.append("Storage Blob Data Contributor (or equivalent storage data-plane role)")

        ms = (time.time() - start) * 1000
        metadata = {
            "found_roles": found_roles,
            "missing_roles": missing,
            "has_delegator": has_delegator,
            "has_data_access": has_data_access,
            "principal_id": principal_id,
            "scope": scope,
        }

        if missing:
            return CheckResult(
                "Storage Role Assignments", target, Status.FAIL,
                f"Missing required role(s): {', '.join(missing)}",
                duration_ms=ms, metadata=metadata,
                raw_output=f"Found roles: {found_roles or '(none)'}\nMissing: {missing}",
                recommendation=(
                    f"The Access Connector identity is missing role(s) on this storage account.\n"
                    f"Missing: {', '.join(missing)}"
                ),
            )

        return CheckResult(
            "Storage Role Assignments", target, Status.PASS,
            f"All required roles present: {', '.join(found_roles)}",
            duration_ms=ms, metadata=metadata,
            raw_output=f"Found roles: {found_roles}",
        )

    except Exception as e:
        return CheckResult(
            "Storage Role Assignments", target, Status.ERROR,
            f"Error checking role assignments: {e}",
            duration_ms=(time.time() - start) * 1000,
        )


# ---------------------------------------------------------------------------
# Storage Firewall & Network Security Perimeter (NSP) checks
# ---------------------------------------------------------------------------

def check_storage_firewall(arm_token, scope):
    """Check storage account network configuration: publicNetworkAccess AND firewall rules.

    IMPORTANT: There are TWO distinct settings that control network access:

    1. publicNetworkAccess (Enabled/Disabled/SecuredByPerimeter):
       Controls whether the public endpoint exists at all.
       - Disabled = public endpoint shut down = NSP/service tags CANNOT work
       - Only Private Endpoints survive publicNetworkAccess: Disabled

    2. defaultAction (Allow/Deny):
       Controls what happens to traffic that REACHES the public endpoint.
       - Deny = firewall active, only matched rules pass

    publicNetworkAccess: Disabled overrides everything — firewall rules, NSP,
    service tags, bypass. Only Private Endpoints work.

    Args:
        arm_token: Azure ARM bearer token
        scope: Full ARM scope of the storage account

    Returns:
        CheckResult with firewall details in metadata including:
            public_network_access, default_action, private_endpoint_connections
    """
    import requests as _req

    start = time.time()
    target = scope.split("/")[-1] if "/" in scope else scope

    try:
        resp = _req.get(
            f"https://management.azure.com{scope}?api-version=2023-05-01",
            headers={"Authorization": f"Bearer {arm_token}"},
            timeout=15,
        )
        if resp.status_code == 403:
            return CheckResult(
                "Storage Firewall", target, Status.ERROR,
                "SP lacks permission to read storage account properties",
                duration_ms=(time.time() - start) * 1000,
            )
        if resp.status_code != 200:
            return CheckResult(
                "Storage Firewall", target, Status.ERROR,
                f"Could not read storage account: HTTP {resp.status_code}",
                duration_ms=(time.time() - start) * 1000,
            )

        sa = resp.json()
        props = sa.get("properties", {})
        acls = props.get("networkAcls", {})

        public_network_access = props.get("publicNetworkAccess", "Enabled")
        default_action = acls.get("defaultAction", "Allow")
        bypass = acls.get("bypass", "")
        vnet_rules = acls.get("virtualNetworkRules", [])
        ip_rules = acls.get("ipRules", [])
        resource_rules = acls.get("resourceAccessRules", [])

        # Count private endpoint connections
        pe_connections = props.get("privateEndpointConnections", [])
        approved_pes = [
            pe for pe in pe_connections
            if pe.get("properties", {}).get("privateLinkServiceConnectionState", {}).get("status", "") == "Approved"
        ]

        ms = (time.time() - start) * 1000
        metadata = {
            "public_network_access": public_network_access,
            "default_action": default_action,
            "bypass": bypass,
            "vnet_rules_count": len(vnet_rules),
            "ip_rules_count": len(ip_rules),
            "resource_rules_count": len(resource_rules),
            "resource_rules": resource_rules,
            "vnet_rules": [r.get("id", "") for r in vnet_rules],
            "private_endpoint_count": len(pe_connections),
            "approved_pe_count": len(approved_pes),
        }

        # Build raw output
        details = [
            f"publicNetworkAccess: {public_network_access}",
            f"defaultAction: {default_action}",
            f"bypass: {bypass}",
            f"Private Endpoints: {len(approved_pes)} approved / {len(pe_connections)} total",
        ]
        if vnet_rules:
            details.append(f"VNet rules: {len(vnet_rules)} subnet(s)")
        if ip_rules:
            details.append(f"IP rules: {len(ip_rules)} range(s)")
        if resource_rules:
            details.append(f"Resource access rules: {len(resource_rules)}")
            for rr in resource_rules:
                details.append(f"  - {rr.get('resourceId', '')} (tenant: {rr.get('tenantId', '')[:8]}...)")
        raw = "\n".join(details)

        # CRITICAL: publicNetworkAccess: Disabled kills NSP/service tags entirely
        if public_network_access == "Disabled":
            if approved_pes:
                return CheckResult(
                    "Storage Firewall", target, Status.WARN,
                    f"Public endpoint DISABLED but {len(approved_pes)} Private Endpoint(s) approved. "
                    "Only PE-based access works. NSP/service tags are blocked.",
                    duration_ms=ms, metadata=metadata, raw_output=raw,
                )
            else:
                return CheckResult(
                    "Storage Firewall", target, Status.FAIL,
                    "CRITICAL: publicNetworkAccess is DISABLED and NO Private Endpoints exist. "
                    "All access is blocked — NSP, service tags, and firewall rules have no effect.",
                    duration_ms=ms, metadata=metadata, raw_output=raw,
                    recommendation=(
                        "publicNetworkAccess: Disabled shuts down the public endpoint entirely.\n"
                        "NSP inbound rules (including AzureDatabricksServerless) CANNOT work.\n\n"
                        "Fix (choose one):\n"
                        "1. RECOMMENDED: Change publicNetworkAccess to 'Enabled from selected "
                        "virtual networks and IP addresses' + configure NSP with "
                        "AzureDatabricksServerless service tag\n"
                        "2. ALTERNATIVE: Keep Disabled + add NCC Private Endpoint for this "
                        "storage account (Account Console > Network Connectivity > NCC)"
                    ),
                )

        # publicNetworkAccess is Enabled (or SecuredByPerimeter)
        if default_action == "Allow":
            return CheckResult(
                "Storage Firewall", target, Status.PASS,
                f"Firewall is OFF (publicNetworkAccess={public_network_access}, defaultAction=Allow). "
                "All networks can access this storage account.",
                duration_ms=ms, metadata=metadata, raw_output=raw,
            )

        # Firewall is ON (defaultAction=Deny, public endpoint active)
        return CheckResult(
            "Storage Firewall", target, Status.WARN,
            f"Firewall ON (defaultAction=Deny). {len(vnet_rules)} VNet rule(s), "
            f"{len(approved_pes)} PE(s), {len(resource_rules)} resource rule(s). "
            "Serverless needs NSP or PE.",
            duration_ms=ms, metadata=metadata, raw_output=raw,
            recommendation=(
                "Storage firewall is enabled. Serverless compute needs one of:\n"
                "1. NSP with AzureDatabricksServerless service tag (recommended)\n"
                "2. NCC Private Endpoint approved on this storage account"
            ),
        )

    except Exception as e:
        return CheckResult(
            "Storage Firewall", target, Status.ERROR,
            f"Error checking firewall: {e}",
            duration_ms=(time.time() - start) * 1000,
        )


def _serverless_storage_routes(firewall, target):
    """The GUIDANCE text for "no NSP is associated", and the verdict that goes with it.

    Serverless reaches a storage account by exactly ONE of two routes, and they are
    alternatives, not a checklist:

      * an NCC PRIVATE ENDPOINT rule for this storage account, with the matching private
        endpoint connection APPROVED on the account, or
      * an NSP association with an inbound rule for the regional AzureDatabricksServerless
        SERVICE TAG, which needs the public endpoint to be reachable.

    The old verdict FAILED for the absence of NSP and prescribed "create an NSP", which was
    wrong twice over. In the field against a private-endpoint-locked account it
    contradicted the firewall row printed immediately above it ("Only PE-based access works.
    NSP/service tags are blocked.") and would have sent the customer to build a perimeter the
    topology makes irrelevant. And with no error message shared, WHICH route the customer's
    architecture intends is not something this diagnosis can know.

    So: instruct, do not determine. Name both routes, say what to verify in each, and let the
    evidence we do have (public endpoint state, approved PE count) order them. Returns
    (Status, message, recommendation).
    """
    md = getattr(firewall, "metadata", None) or {}
    public = str(md.get("public_network_access") or "").strip()
    approved = md.get("approved_pe_count")
    pe_locked = public.lower() == "disabled"
    has_pe = isinstance(approved, int) and approved > 0

    # The ONE provable case: nothing can reach it by either route. Public endpoint closed,
    # no approved private endpoint, no NSP -> there is no path, whatever the intent was.
    if pe_locked and isinstance(approved, int) and approved == 0:
        status = Status.FAIL
        msg = ("No NSP is associated AND the public endpoint is disabled with no approved private "
               "endpoint connection — serverless currently has NO route to this storage account.")
    else:
        status = Status.WARN
        if pe_locked and has_pe:
            msg = (f"No NSP is associated. With the public endpoint disabled and {approved} approved "
                   f"private endpoint connection(s), the private-endpoint route is the one this "
                   f"account's topology implies — the absence of an NSP is NOT itself a fault here.")
        elif pe_locked:
            msg = ("No NSP is associated, and the public endpoint is disabled — so the private-endpoint "
                   "route is the only one currently possible. Verify it end to end.")
        else:
            msg = (f"No NSP is associated (public endpoint: {public or 'unknown'}). Either route below can "
                   f"serve serverless; which one applies depends on the design you intend.")

    pe_route = (
        "ROUTE A — NCC private endpoint (per storage account):\n"
        "  1. Account Console > Cloud resources > Network Connectivity Configurations > your NCC >\n"
        "     Private endpoint rules — there must be a rule targeting THIS storage account, with the\n"
        f"     right sub-resource ('dfs' for ADLS Gen2, 'blob' for blob) for {target}.\n"
        "  2. On the storage account, the matching Private endpoint connection must be APPROVED —\n"
        "     a Pending connection looks configured and still refuses traffic.\n"
        "  3. That NCC must be attached to this workspace.\n"
        "  I can CHECK this route for you: re-run with your Databricks account id and an\n"
        "  account-admin service principal, and I will read the NCC's rules directly."
    )
    nsp_route = (
        "ROUTE B — NSP with the regional service tag (needs the public endpoint reachable):\n"
        "  1. Azure Portal > Network security perimeters — associate this storage account with a profile.\n"
        "  2. Add an inbound access rule: Source = Service Tag, Value = AzureDatabricksServerless.\n"
        "  3. Set the access mode to Enforced once you have verified it (Learning mode is audit-only —\n"
        "     it logs and does NOT grant access)."
        + ("\n  NOTE: this route needs publicNetworkAccess ENABLED; it is currently Disabled, so choosing\n"
           "  it means changing the account's network posture." if pe_locked else "")
    )
    order = (pe_route, nsp_route) if pe_locked or has_pe else (nsp_route, pe_route)

    rec = (
        "Serverless reaches a storage account by ONE of two routes, and you should not build both.\n"
        "No error message was shared, so this is what to VERIFY rather than what to change:\n\n"
        + order[0] + "\n\n" + order[1] + "\n\n"
        "Then re-run this diagnostic with the failing catalog.schema.table so the credential chain\n"
        "(catalog -> storage credential -> Access Connector -> RBAC) is traced as well — a correct\n"
        "network route with a missing role assignment produces the same 403."
    )
    return status, msg, rec


def check_storage_nsp(arm_token, scope, firewall=None):
    """Check if the storage account is associated with a Network Security Perimeter (NSP)
    and whether it has an inbound access rule for AzureDatabricksServerless.

    NSP is the recommended way for serverless compute to access storage when the
    firewall is enabled (replacing legacy subnet-based rules, EOL June 2026).

    Args:
        arm_token: Azure ARM bearer token
        scope: Full ARM scope of the storage account

    Returns:
        CheckResult with NSP details in metadata:
            has_nsp, access_mode, has_databricks_rule, nsp_profiles
    """
    import requests as _req

    start = time.time()
    target = scope.split("/")[-1] if "/" in scope else scope

    try:
        # Query NSP configurations on the storage account
        url = (
            f"https://management.azure.com{scope}"
            f"/networkSecurityPerimeterConfigurations"
            f"?api-version=2023-05-01"
        )
        resp = _req.get(
            url,
            headers={"Authorization": f"Bearer {arm_token}"},
            timeout=15,
        )

        # NSP API may return 404 if no NSP feature or no association
        if resp.status_code == 404:
            # No NSP association. This is NOT automatically a fault: the private-endpoint
            # route is the alternative, and which route the customer intends is unknowable
            # from here. `_serverless_storage_routes` decides the verdict from the firewall
            # topology and returns guidance for BOTH routes.
            _st, _msg, _rec = _serverless_storage_routes(firewall, target)
            return CheckResult(
                "Network Security Perimeter", target, _st, _msg,
                duration_ms=(time.time() - start) * 1000,
                # Keys unchanged on purpose: `_nsp_grants_access` and the storage diagnosis
                # rules read this metadata, never the status, so the verdict can soften
                # without moving any diagnosis.
                metadata={"has_nsp": False, "has_databricks_rule": False,
                          "routes_guidance": True},
                recommendation=_rec,
            )
        if resp.status_code == 403:
            return CheckResult(
                "Network Security Perimeter", target, Status.ERROR,
                "SP lacks permission to read NSP configuration on this storage account",
                duration_ms=(time.time() - start) * 1000,
            )
        if resp.status_code != 200:
            # Some API versions may not support this endpoint
            return CheckResult(
                "Network Security Perimeter", target, Status.WARN,
                f"Could not query NSP configuration: HTTP {resp.status_code}. "
                "NSP may not be available in this region or the API version may differ.",
                duration_ms=(time.time() - start) * 1000,
                metadata={"has_nsp": False},
            )

        configs = resp.json().get("value", [])
        if not configs:
            # THE BRANCH THAT ACTUALLY FIRES. The NSP API answers 200 with an empty `value`
            # for an unassociated account, not 404 — verified in the field, when a fix
            # applied only to the 404 branch above changed nothing in the report. Both
            # branches mean the same thing and must give the same guidance, so both route
            # through `_serverless_storage_routes`.
            _st, _msg, _rec = _serverless_storage_routes(firewall, target)
            return CheckResult(
                "Network Security Perimeter", target, _st, _msg,
                duration_ms=(time.time() - start) * 1000,
                metadata={"has_nsp": False, "has_databricks_rule": False,
                          "routes_guidance": True},
                recommendation=(
                    _rec + "\nDocs: https://learn.microsoft.com/azure/databricks/security/network/"
                    "serverless-network-security/serverless-nsp-firewall"
                ),
            )

        # Parse NSP configurations
        nsp_profiles = []
        has_databricks_rule = False
        access_modes = []
        all_inbound_rules = []

        for config in configs:
            props = config.get("properties", {})
            nsp_info = props.get("networkSecurityPerimeter", {})
            profile_info = props.get("profile", {})
            provisioning = props.get("provisioningState", "")

            nsp_id = nsp_info.get("id", "")
            nsp_location = nsp_info.get("location", "")
            profile_name = profile_info.get("name", "")
            access_mode = profile_info.get("accessRulesVersion", "")

            # Get access mode from the profile
            profile_access_mode = props.get("profile", {}).get("accessRulesVersion", "")

            # Check inbound access rules for AzureDatabricksServerless
            inbound_rules = profile_info.get("accessRules", [])
            for rule in inbound_rules:
                rule_props = rule.get("properties", {}) if isinstance(rule, dict) else {}
                rule_name = rule.get("name", "")
                direction = rule_props.get("direction", "")
                service_tags = rule_props.get("serviceTags", [])
                address_prefixes = rule_props.get("addressPrefixes", [])

                all_inbound_rules.append({
                    "name": rule_name,
                    "direction": direction,
                    "service_tags": service_tags,
                    "address_prefixes": address_prefixes,
                })

                if direction == "Inbound":
                    for tag in service_tags:
                        if "AzureDatabricksServerless" in tag:
                            has_databricks_rule = True

            # Also check for the service tag in various response formats
            resource_associations = props.get("resourceAssociation", {})
            ra_access_mode = resource_associations.get("accessMode", "")
            if ra_access_mode:
                access_modes.append(ra_access_mode)

            nsp_profiles.append({
                "nsp_id": nsp_id,
                "nsp_location": nsp_location,
                "profile_name": profile_name,
                "access_mode": ra_access_mode,
                "provisioning_state": provisioning,
                "inbound_rules_count": len(inbound_rules),
            })

        ms = (time.time() - start) * 1000
        metadata = {
            "has_nsp": True,
            "has_databricks_rule": has_databricks_rule,
            "nsp_profiles": nsp_profiles,
            "access_modes": access_modes,
            "inbound_rules": all_inbound_rules,
        }

        raw_parts = [f"NSP profiles: {len(nsp_profiles)}"]
        for p in nsp_profiles:
            raw_parts.append(
                f"  - {p['profile_name']}: mode={p['access_mode']}, "
                f"rules={p['inbound_rules_count']}, state={p['provisioning_state']}"
            )
        raw_parts.append(f"\nInbound rules: {len(all_inbound_rules)}")
        for r in all_inbound_rules:
            raw_parts.append(f"  - {r['name']}: tags={r['service_tags']}, prefixes={r['address_prefixes']}")
        raw_parts.append(f"\nAzureDatabricksServerless rule found: {has_databricks_rule}")
        raw = "\n".join(raw_parts)

        if has_databricks_rule:
            mode_str = ", ".join(access_modes) if access_modes else "unknown"
            return CheckResult(
                "Network Security Perimeter", target, Status.PASS,
                f"NSP configured with AzureDatabricksServerless inbound rule (mode: {mode_str})",
                duration_ms=ms, metadata=metadata, raw_output=raw,
            )

        # NSP exists but missing the Databricks serverless rule
        return CheckResult(
            "Network Security Perimeter", target, Status.FAIL,
            "NSP is associated but MISSING AzureDatabricksServerless inbound access rule!",
            duration_ms=ms, metadata=metadata, raw_output=raw,
            recommendation=(
                "The storage account has an NSP but it lacks the required inbound rule.\n"
                "Fix: NSP > Settings > Profiles > select profile > Inbound access rules > Add\n"
                "  Source Type: Service Tag\n"
                "  Allowed Sources: AzureDatabricksServerless\n"
                "For region-specific restriction use: AzureDatabricksServerless.<RegionName>"
            ),
        )

    except Exception as e:
        return CheckResult(
            "Network Security Perimeter", target, Status.ERROR,
            f"Error checking NSP: {e}",
            duration_ms=(time.time() - start) * 1000,
        )


# ---------------------------------------------------------------------------
# Dashboard adapter
# ---------------------------------------------------------------------------

def build_storage_report(host, checks_list, diagnoses=None, summary=""):
    """Bundle storage CheckResults into a DiagnosticReport for build_dashboard_v2.

    Args:
        host: storage account FQDN (e.g. "mystorage.dfs.core.windows.net")
        checks_list: list[CheckResult] from storage checks (firewall, nsp,
            resource_instance_rule, ac_principal, roles, etc.)
        diagnoses: optional list[Diagnosis] (root cause + prescription cards)
        summary: short narrative shown in the dashboard summary

    Returns:
        DiagnosticReport ready for build_dashboard_v2([report], ...)
    """
    checks = {c.check_name: c for c in checks_list if c is not None}
    # Same severity-aware headline as the connectivity path: one derivation,
    # so a storage report cannot grade itself by a different rule.
    overall = derive_overall_status(checks, diagnoses)
    return DiagnosticReport(
        target=host,
        host=host,
        port=443,
        checks=checks,
        diagnoses=list(diagnoses or []),
        overall_status=overall,
        summary=summary,
    )
