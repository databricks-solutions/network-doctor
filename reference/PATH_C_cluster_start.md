# Path C — Cluster Start / Launch Failure (reference)

Open this when `run_network_doctor()` classified the problem as **Path C** (a classic VNet-injected cluster cannot bootstrap and reach RUNNING: `X_NHC_`, "Network configuration failure", "Add nodes failed", "Compute terminated", "Instance failed network health check", `SERVICE_FAULT` / `X_UnexpectedLaunchFailure` launch errors, "Configured privacy settings disallow access for this workspace over your current network"). Shared machinery (Step 1 load, the driver loop, secret-scope walkthrough, session resume) lives in `reference/DIAGNOSTIC_MACHINERY.md`.

## Path C scope and triage

**Path C: Cluster Start / Launch Failure** — ANY indication that a classic VNet-injected cluster never reached RUNNING. This covers two families of signature — BOTH route to Path C:

- **NHC health-check failures:** `Network configuration failure`, `X_NHC_`, `Add nodes failed`, `Compute terminated`, `Instance failed network health check`, `failed component(s): control_plane`. Typical signal: a "Terminating" / "Add nodes failed" event with `X_NHC_CONTROL_PLANE_HTTP_ERROR` and entity lines for `*.azuredatabricks.net` (HTTP 401) and/or `www.databricks.com` (HTTP 403).
- **Launch failures (NON-NHC signatures — these ALSO go to Path C):** `X_UnexpectedLaunchFailure`, `UNEXPECTED_LAUNCH_FAILURE`, `Unexpected failure during launch`, `No such workerEnvironment`, and any `SERVICE_FAULT` cluster termination where a classic VNet-injected cluster failed to launch. **A customer who pastes a cluster id + "my cluster won't spin up / fails during launch" is Path C**, even when the error is not an `X_NHC_` code. Do NOT treat these as out-of-scope and do NOT conclude "Databricks backend bug" from them — see the hard rule below.

→ Follow Steps C1-C7 below.

**Path C HARD RULE — never bail to "Databricks-side / SERVICE_FAULT / file a support ticket / nothing you can do" for a cluster launch failure WITHOUT first running the deep ARM diagnostic.** The `SERVICE_FAULT` / `UNEXPECTED_LAUNCH_FAILURE` classification (and messages like "No such workerEnvironment") are downstream SYMPTOMS, not proof of a Databricks bug. The real root cause is frequently a customer-side Azure misconfiguration — broken subnet delegation, missing required NSG rules, forced-tunnel / blackhole UDR, DNS, or private link — exactly what `diagnose_cluster_start` checks against the workspace's real ARM data. You may state "this looks Databricks-side / open a support ticket" ONLY after you have (a) asked for the Azure SP secret references AND (b) actually run `diagnose_cluster_start(...)` and it found no customer-side misconfiguration — OR the customer declined to provide credentials (in which case say honestly you cannot determine it — see the credential-optional rule in C2-C4). Running `databricks clusters get/list` and reading the termination_reason type is NOT a substitute for the ARM diagnostic.

**Path C trap — DO NOT FALL INTO THIS:** the 401 message "Configured privacy settings disallow access for this workspace over your current network" looks like an IP access list problem. It is NOT. IP access lists govern end-user / SDK ingress to the workspace UI and REST API, not data-plane→control-plane bootstrap. The causes confirmed against real workspaces for this exact 401 are: workspace `requiredNsgRules=NoAzureDatabricksRules` with the canonical NSG rule missing, `publicNetworkAccess=Disabled` with no PE in the data-plane VNet, forced-tunnel UDR sending traffic through a firewall that blocks Databricks endpoints, missing subnet delegation, or unlinked `privatelink.azuredatabricks.net` Private DNS zone. Do not name the cause until the orchestrator has told you which one applies.

## Step C1: Cluster Start Failure Diagnostic — Overview

This path diagnoses why a classic VNet-injected cluster never reaches RUNNING — whether it fails NHC (`X_NHC_*`) OR fails to launch with a non-NHC signature (`X_UnexpectedLaunchFailure`, `UNEXPECTED_LAUNCH_FAILURE`, "Unexpected failure during launch", "No such workerEnvironment", `SERVICE_FAULT`). The broken cluster cannot run probes, so this entire diagnostic is **ARM-only and runs from serverless**. Do not try to attach to the broken cluster, and do not spin up a transient diagnostic cluster — if the data-plane subnet has a misconfiguration, the transient cluster will fail the same way and waste time.

**`diagnose_cluster_start` handles BOTH families.** It parses the pasted error; if it is not a canonical `X_NHC_` code it recognises the launch-failure signatures, marks `nhc_parse` accordingly, and runs the SAME full ARM check set anyway (subnet delegation, required NSG rules, route tables / forced-tunnel, egress IP, private link, DNS). A `SERVICE_FAULT` / launch-failure is a SYMPTOM — the diagnostic still hunts for the customer-side Azure root cause and reports real findings rather than refusing because the error isn't `X_NHC_`. Feed the pasted launch-error text in as `nhc_error_text` regardless of signature.

The diagnosis flow:
1. Parse the customer-pasted error (no Azure call needed). NHC and launch-failure signatures are both recognised.
2. Read the workspace ARM resource → discover VNet, public/private subnet names, `publicNetworkAccess`, `requiredNsgRules`, PE connections.
3. Validate each data-plane subnet: delegation, NSG rules, route table, NAT egress IP.
4. Validate workspace-level: Private Link topology, Private DNS zone for `privatelink.azuredatabricks.net`.
5. Correlate the error signals (e.g. 401 from workspace, 403 from www.databricks.com — or, for a launch failure with no such signals, the ARM findings themselves) into diagnoses.

## Step C1.5: Routing — LIVE only, no offline mode

Path C reads Azure ARM LIVE from this notebook. There is no offline/snapshot mode. Do NOT ask "what compute do you have available" — that question is dead weight. Do NOT offer a LIVE branch from a working classic cluster (if a classic cluster were working, the customer wouldn't be here).

The reachability decision is made deterministically in Step C3 (the driver probes whether this runtime can reach management.azure.com — no credential needed). The customer just provides the inputs in Step C2; if ARM is unreachable the driver returns the egress to enable and the customer re-runs.

## Step C2-C4: Path C — driver-first, LIVE only

`run_network_doctor()` owns the Path C intake (full error text verbatim = the problem_text; workspace ARM resource id `/subscriptions/.../providers/Microsoft.Databricks/workspaces/<name>`; SP key NAMES) and runs `diagnose_cluster_start` LIVE. Hard rules that survive any flow:

- SERVICE_FAULT / `X_UnexpectedLaunchFailure` / "No such workerEnvironment" is a SYMPTOM — run the ARM diagnostic; never conclude "Databricks bug / open a ticket" before it has run clean against complete Reader scope (`launch_failure_arm_clean` is the honest pattern for that case, and even then confirm scope completeness first).
- Azure cluster-start termination codes that ARE network-configuration failures (`NPIP_TUNNEL_SETUP_FAILURE` / Ngrok setup timeout, `NETWORK_CONFIGURATION_FAILURE`, `SUBNET_EXHAUSTED_FAILURE`, `CONTROL_PLANE_REQUEST_FAILURE`, `DRIVER_UNREACHABLE`, `SECURITY_DAEMON_REGISTRATION_EXCEPTION`) route to Path C even when the customer pastes only the bare code with no "won't start" prose.
- **Credential-optional, honest:** no SP and the customer declines the scope walkthrough → Path C has no credential-free version, so say honestly that without a Reader SP you cannot inspect the Azure config; do NOT pattern-match the error text into a guessed cause. There is no offline path to offer.
- `nhc_subnet_nsg_*` prescriptions present ALL options from the diagnosis (A AllRules / B back-end Private Link / C manual canonical rules); with `nhc_subnet_nsg_backend_pl_expected` never recommend AllRules — diagnose the back-end PL path (zone link, PE private IP, SCC, Premium) instead.

### LIVE flow

The driver runs `diagnose_cluster_start` LIVE (you do not hand-call it). Internally: probe whether this runtime can reach management.azure.com (`probe_arm_reachability` — one cheap GET, no credential; do NOT skip it, do NOT guess), and if reachable, mint the ARM token from the SP and run the cluster-start suite from this notebook. The dashboard is produced here — "produced", never "rendered": you cannot see the notebook, so you assert only that the file was written and where it is.

### When ARM is unreachable (egress blocked)

If this runtime cannot reach management.azure.com, the driver returns NEED_INPUT with the egress to enable — there is NO offline snapshot. A reachable-but-401/403 probe is a token/RBAC issue, not this case: it means grant the SP Reader, not change the network. When ARM is genuinely unreachable, relay to the customer: WHY (an EGRESS block, not a permissions problem and not a finding about their config); WHAT to enable — outbound HTTPS to `management.azure.com` and `login.microsoftonline.com` (serverless: Account Console > Settings > Network / NCC; classic: the data-plane subnet's route table / NSG / hub firewall); and that they should re-run for a LIVE diagnosis afterward. If their security policy forbids that egress, say the Azure layer stays uninspected rather than guessing.

```python
# After the customer enables egress, re-run the same session — the driver re-probes:
result = run_network_doctor(
    answers={"egress_enabled": "ready"},
    session_path=r"<printed>",
)
```

The report's checks are keyed `nhc_parse`, `ws_network_cfg`, `<public|private>_subnet_<delegation|nsg|routes|egress_ip>`, `ws_private_link`, `ws_backend_private_link`, `ws_private_dns`, `outbound_databricks_com`; diagnoses come from the correlation engine. Present per Step 6 (PATH_A_connectivity.md) + the Finalize-Turn rule in SKILL.md.

## NSG AllRules prescription (the primary fix for NoAzureDatabricksRules)

When the diagnostic finds the workspace on `NoAzureDatabricksRules` AND the canonical AzureDatabricks rule (`Microsoft.Databricks-workspaces_UseOnly_databricks-worker-to-databricks-webapp`) is missing, the prescription must lead with this exact one-liner — and ONLY this one-liner — as the primary fix:

```bash
az databricks workspace update --resource-group <rg> --name <ws> --required-nsg-rules AllRules
```

Verified against a real workspace: NHC keys on the canonical rule name, not just the service tag and ports. Manually adding a doc-correct rule with `dst=AzureDatabricks` and the right ports does NOT unstick NHC unless the rule also has the `Microsoft.Databricks-workspaces_UseOnly_*` naming convention. Therefore manual rule editing is a FALLBACK only for customers with a hard policy requirement to keep `NoAzureDatabricksRules`. Do not present manual edits as an equal alternative.

For the NSG 3-option prescription ALL THREE options (A AllRules / B back-end Private Link / C manual canonical rules) go in the chat text. With `nhc_subnet_nsg_backend_pl_expected` never recommend AllRules — diagnose the back-end PL path (zone link, PE private IP, SCC, Premium) instead.

## Step C5: Generate Report

The driver already built the `DiagnosticReport`, the chat prescription, and the saved HTML. Finalize in the global SKILL.md order — do not rebuild the dashboard by hand:

1. Post `result["chat_prescription"]` VERBATIM (for the NSG 3-option prescription ALL THREE options are already in that text).
2. NEW cell: `displayHTML(nd_render_dashboard(result["session_path"]))`.
3. Post `result["dashboard_pointer"]` VERBATIM.

The prescription is CHAT text, not a notebook cell: commands (`az ...`) stay in the driver's fenced blocks. Notebook magics (`%md`, `%python`) are forbidden in it — a literal `%md` line has rendered in the customer-facing OPTION A text on two separate occasions. Do not also output a markdown per-check table.

**This is the end of the turn.** Do not write more prose after `displayHTML` — follow-up text has been observed to collapse the inline HTML render in Genie.

## Step C6: Re-verification

After the customer applies the fix, re-run through the driver — do **not** hand-call `diagnose_cluster_start`. A finished session for the same paste is `STALE_SESSION`; start fresh so the LIVE reachability probe runs again:

```python
result = run_network_doctor(problem_text, fresh=True)
```

Reuse the same ARM id and secret-scope **names** (`answers={'sp_scope': '<scope>', 'workspace_arm_id': '<arm id>'}`) when the driver asks. If this runtime still cannot reach ARM, the driver returns the egress-to-enable question again — there is no offline path; the customer enables the egress and re-runs.

Confirm the previously failing checks now pass before suggesting they retry the cluster start.

## Step C7: Cleanup

Path C creates **no** Databricks resources — no transient diagnostic cluster, no Delta tables. There is nothing to clean up. Confirm the workspace's cluster list is unchanged.
