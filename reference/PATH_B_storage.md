# Path B — Storage Access / Permissions (reference)

Open this when `run_network_doctor()` classified the problem as **Path B** (storage/UC-Volume access errors: `PERMISSION_DENIED`, `AbfsRestOperationException`, "Request not authorized to perform this operation", `AuthorizationFailure`/403, user delegation key/SAS errors, Storage Blob Delegator, SELECT on a Volume or external table failing, and ESPECIALLY anything that works on one compute type but fails on the other — that asymmetry is a network-path signature, not an RBAC one). Shared machinery (Step 1 load, the driver loop, secret-scope walkthrough, session resume) lives in `reference/DIAGNOSTIC_MACHINERY.md`.

## Path B scope

**Path B: Storage Access / Permissions** — errors mentioning `PERMISSION_DENIED`, `user delegation key`, `not authorized`, `403 Forbidden`, `access denied`, storage roles, `Storage Blob Delegator` (driver-owned; Steps S1-S7 are the underlying machinery).

`run_network_doctor` classifies the path itself — you do not pick it by hand.

**Network before RBAC** for storage access issues: check `publicNetworkAccess`, storage firewall / network ACLs, and Network Security Perimeter (NSP) BEFORE concluding it is a role-assignment problem. A failure that is network-path-shaped (works on classic, fails on serverless or vice versa) is almost never an RBAC gap.

---

# Storage Access Diagnostic (Path B)

Path B is DRIVER-OWNED. For storage/UC-access symptoms (`PERMISSION_DENIED`, user-delegation key errors, `AuthorizationFailure`, Volume/table access failing), do not hand-run S1-S8 style cells anymore.

Use the same `run_network_doctor()` loop from Step 1b (NEED_INPUT -> IN_PROGRESS -> DONE). The driver already does all of this deterministically:

- Classifies Path B and asks for `full_table` when needed.
- Traces credential chain (`table -> catalog -> storage credential -> access connector`).
- Runs storage checks in the right order: **network before RBAC**.
- Selects storage diagnosis in code (`_compose_storage_diagnosis`) instead of free-form prose.
- Produces `chat_prescription` + dashboard/report payload in the standard finalize order.

## Path B Hard Rules (must keep)

- Call `run_network_doctor(problem_text)` first; never bypass the driver with hand-authored storage steps.
- Never ask for secret values. Ask only `sp_scope` (key names only if non-default).
- If the SP is declined (`sp_declined=true`), be explicit: credential chain can be traced, but root cause cannot be confirmed without Reader SP (no fabricated verdict).
- Keep credential-shaped strings out of the `run_network_doctor` call cell; in the common case pass only `answers={"sp_scope": "<scope>"}`.
- Finalize in the global order: confirmation questions (if any) -> `chat_prescription` -> `displayHTML(...)` -> dashboard pointer.
- Re-verification after fixes also goes through the driver with a fresh call; do not rebuild a manual Path B check matrix in chat.

## Path B Reference (read-only)

The detailed storage implementation lives in code and is the source of truth:

- `scripts/doctor.py` (`_stage_B`, `_compose_storage_diagnosis`)
- `scripts/storage_access_checks.py`

If docs and code diverge, follow code + `deploy/gen_docs.py --check` gate, then update docs.
