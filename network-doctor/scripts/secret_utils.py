"""Secret-loading helpers for the Network Connectivity Doctor.

These helpers intentionally deal only with Databricks secret references in
logs/errors. Secret values are returned to the caller for in-memory use and
must never be printed.
"""


class SecretReferenceError(ValueError):
    """Raised when a Databricks secret reference is missing or unreadable."""


DEFAULT_AZURE_SP_SECRET_KEYS = {
    "tenant_id_key": "azure-tenant-id",
    "client_id_key": "azure-client-id",
    "client_secret_key": "azure-client-secret",
}


def normalize_azure_sp_secret_ref(secret_ref):
    """Return a normalized Azure SP secret reference dictionary.

    Args:
        secret_ref: dict with scope and optional tenant/client key names.

    Returns:
        dict containing scope, tenant_id_key, client_id_key, client_secret_key.
    """
    if not isinstance(secret_ref, dict):
        raise SecretReferenceError("Azure SP secret reference must be a dictionary")

    scope = str(secret_ref.get("scope", "")).strip()
    if not scope:
        raise SecretReferenceError("Azure SP secret reference is missing 'scope'")

    normalized = {"scope": scope}
    for field, default_key in DEFAULT_AZURE_SP_SECRET_KEYS.items():
        value = str(secret_ref.get(field, "")).strip() or default_key
        normalized[field] = value

    return normalized


def _read_required_secret(dbutils_obj, scope, key, label):
    try:
        value = dbutils_obj.secrets.get(scope=scope, key=key)
    except Exception as exc:
        raise SecretReferenceError(
            f"Cannot read Azure SP {label} from Databricks secret scope "
            f"'{scope}' key '{key}': {exc}"
        ) from exc

    if not value:
        raise SecretReferenceError(
            f"Azure SP {label} is empty in Databricks secret scope '{scope}' key '{key}'"
        )

    return value


def load_azure_sp_from_secrets(dbutils_obj, secret_ref):
    """Load Azure Service Principal values from Databricks Secrets.

    Args:
        dbutils_obj: Databricks dbutils object.
        secret_ref: dict with:
            - scope
            - tenant_id_key (optional, defaults to azure-tenant-id)
            - client_id_key (optional, defaults to azure-client-id)
            - client_secret_key (optional, defaults to azure-client-secret)

    Returns:
        dict with tenant_id, client_id, client_secret.
    """
    ref = normalize_azure_sp_secret_ref(secret_ref)
    scope = ref["scope"]

    return {
        "tenant_id": _read_required_secret(
            dbutils_obj, scope, ref["tenant_id_key"], "tenant_id"
        ),
        "client_id": _read_required_secret(
            dbutils_obj, scope, ref["client_id_key"], "client_id"
        ),
        "client_secret": _read_required_secret(
            dbutils_obj, scope, ref["client_secret_key"], "client_secret"
        ),
    }
