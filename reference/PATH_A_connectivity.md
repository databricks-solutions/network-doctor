# Path A — Network Connectivity (reference)

Open this when `run_network_doctor()` classified the problem as **Path A** (connectivity from a running cluster to a data source: timeout, connection refused, DNS resolution failure, cannot connect, unreachable, Lakehouse Federation query failures). Shared machinery (Step 1 load, the driver loop, chunked flow, session resume, secret-scope walkthrough) lives in `reference/DIAGNOSTIC_MACHINERY.md` — read that for anything not specific to Path A.

## Path A scope

**Path A: Network Connectivity** — errors mentioning timeout, connection refused, DNS resolution failure, cannot connect, unreachable (driver-owned; Steps 1-9 are the underlying machinery).

`run_network_doctor` classifies the path itself — you do not pick it by hand.

**LAYER RULE — serverless = account Network policy egress, classic = VNet.** For a SERVERLESS problem the diagnosis lives at the account-level **Network policy** egress layer (`serverless_egress_ncc` pattern); the workspace VNet's DNS/NSG/peering checks are classic-plane and are auto-skipped. Customer-facing nomenclature: a PUBLIC destination is fixed under Account Console > Security > Network policies > **Egress** > **Egress rules** (Allowed internet destinations, Type DNS_NAME) — NOT Private Endpoints. Private Endpoint / NCC rules apply ONLY to a private-linked target (and then the target's DNS name must also be in the Egress rules). Never ask the VNet DNS-architecture question (6e) or prescribe VNet zone links for a serverless target; 6e applies to classic/both only.

## Step 2: Detect Current Compute Environment

Immediately after loading scripts, detect whether this notebook is running on classic or serverless compute. This determines what is possible from the current environment.

```python
ws_ctx = get_workspace_context()
print(f"[Doctor] Workspace: {ws_ctx['workspace_url']}")
print(f"[Doctor] Running on: {'Serverless' if ws_ctx['is_serverless'] else 'Classic'} compute")
```

Store `ws_ctx` for use throughout the session. Do NOT ask the user what compute the notebook is on -- detect it automatically.

## Step 3: Intake — the driver asks, you relay

For Paths A and C the intake IS `run_network_doctor()`: call it first; it returns the next question (NEED_INPUT). The driver asks ONE thing at a time — relay that single question, wait for the answer, call again for the next, and do NOT run any diagnostics until intake is complete. Universal intake rules (apply to every path, including B):

- **Never accept raw credentials.** Only secret-scope KEY NAMES (`scope`, `tenant_id_key`, `client_id_key`, `client_secret_key`). If the customer pastes a value (UUID / high-entropy string): refuse, tell them to rotate it (Azure Portal > App registrations > Certificates & secrets), store the replacement via `databricks secrets put-secret`, and send NAMES. Never echo the value. Never request write-capable roles (no Owner/Contributor/UAA) — Reader only, subscription scope recommended.
- **Port inference — never ask a separate port question.** Use `host:port` if given, else infer: SQL Server/Azure SQL=1433, Oracle=1521, MySQL=3306, PostgreSQL=5432, HTTPS/REST/ADLS/Blob=443; `*.database.windows.net`→1433; `*.blob/dfs.core.windows.net`→443. State the inferred port as fact; the customer corrects it if wrong.
- **NCC / account-id is OPTIONAL.** Never hunt for account ids or account-admin tokens; the machinery marks NCC checks SKIP and proceeds.
- **Classic probes need a classic cluster, and it is the CUSTOMER'S cluster** (in-session probes measure the serverless plane). The driver asks for the id; relay that ask. **Never create compute in the customer's workspace** — not with the clusters API, not with a job, not "just this once". Compute we create bills them, has to be waited for, and becomes ours to tear down on every exit path; the ask tells them how to make a single-node one themselves and to send the id. If they have none and do not want to start one, `none` is a real answer and the report names what goes unverified.
  If the id they give is not a running cluster, the probe rows come back as unverified naming that reason — do NOT re-run those probes from this session to fill the gap, because that measures a different network. Ask them to check the cluster is RUNNING and send the id again.
  Never tell the customer to attach/reattach a notebook either — probes run remotely via `run_on_cluster()` (see 4d in DIAGNOSTIC_MACHINERY).
- **Secret-scope setup walkthrough** — see DIAGNOSTIC_MACHINERY.md (values are typed at THEIR terminal, never in chat).
- **After the customer confirms — execute immediately.** The next thing you produce is a code cell (Step 1 load if needed, then the driver call). Never hand the work back to the customer ("once you're in a notebook..."); you ARE in the notebook.

## Steps 4-5: Diagnostic machinery (reference — the driver wraps this)

`run_network_doctor()` builds the context and drives the chunked flow itself. You only touch this machinery directly for: re-verification (Step 8), classic-cluster remote probes (4d in DIAGNOSTIC_MACHINERY), or if the driver returns ERROR and instructs a manual step. The full machinery (context dict keys, chunked flow, remote execution code) is in `reference/DIAGNOSTIC_MACHINERY.md`.

- Azure checker: pass `azure_sp` (secret REFS) in the context — the INFRA phase resolves it via Databricks Secrets and builds `AzureInfraChecker` with auto-discovery. Manual build only when needed: `azure_ctx = auto_discover_azure_context(sp["client_id"], sp["client_secret"], tenant_id=sp["tenant_id"])` then `AzureInfraChecker(**{k: azure_ctx[k] for k in ("tenant_id","client_id","client_secret","subscription_id","resource_group","vnet_name")})`. Do NOT `%pip install` anything, ever — all Azure reads are raw ARM REST over `requests`.
- Long runs (any Azure infra/NCC checks) MUST be chunked — `diagnose_target` REFUSES them with the recipe: `start_diagnosis(host, port, context)` → `continue_diagnosis(ckpt, context)` → `finalize_diagnosis(ckpt, context)`, one cell each, checkpoint persisted after every check, resumable after resets, removed on finalize. Follow each printed "[Doctor] NEXT" verbatim.
- Short serverless-only runs may use single-call `diagnose_target(host, port, context)`.

## Step 6: Diagnosis — gates and final-recommendation selection

Enter only AFTER a diagnostic has run and produced `report` (the driver does this). Each `report.diagnoses` item carries `pattern_id`, `severity`, `confidence`, `prescription`, `follow_up_questions`, and `needs_confirmation` — a `needs_confirmation` finding is a HYPOTHESIS, not a confirmed root cause.

**CONFIRMATION GATE — HARD STOP, same turn as the diagnostic.** If ANY diagnosis has `needs_confirmation == True` (the driver surfaces these as `confirmation_questions`): ask its follow-up questions in chat THIS turn and STOP. Do NOT render/save the dashboard, say "Diagnosis complete", or assert the finding as the root cause (in prose either) until the customer answers. Concretely:
- A non-Connected peering matters only if it is on the path to the target or its DNS — ask, even when the remote VNet name looks suggestive (`...sqlvnet` is a hint, never proof).
- Never assume "custom DNS" on a DNS failure — ask WHICH architecture (see 6e), then finalize.
- Batch all confirmation + follow-up questions into ONE message.

**Re-read the LAYER RULE at the top of this document before writing a serverless
prescription** — it is the rule most often broken at exactly this point.

**ASK-ONLY-ACTIONABLE.** Only ask if the answer changes a check you can run or a recommendation you give. Never ask for the DNS server's IP, whether conditional forwarding is "already configured", or for Portal values an Azure SP can read programmatically. When in doubt, finalize with an actionable recommendation instead of asking.

**Healthy fast-path.** For sanity checks where DNS/TCP (and TLS/latency/PE/zone/NSG where applicable) pass: present an All Clear summary + "no configuration change needed" + suggest a small scheduled synthetic check. Do not keep generating diagnostic cells.

**Presentation.** Sort by `fix_order`. High-confidence → present root cause + prescription directly. needs_confirmation → hypothesis + question. Medium/low → root cause + its follow-ups. The chat prescription comes FROM `diagnosis.root_cause`/`diagnosis.prescription` (the driver pre-builds it as `chat_prescription`) — never invent a fix that is not in a Diagnosis.

### 6e. DNS failure — final recommendation per architecture (deliver immediately after the customer names it; no further question)

| Customer's DNS architecture | FINAL recommendation |
|---|---|
| **Azure-provided DNS (168.63.129.16)** | Private Azure resources: link the relevant `privatelink.*` Private DNS zone to the Databricks VNet (Portal > Private DNS zones > zone > Virtual network links > Add). On-prem/corporate names (e.g. `corp.internal`): Azure-provided DNS alone CANNOT resolve them — the VNet needs a custom DNS server or Private Resolver forwarding that zone. |
| **Custom DNS server** | Verify/add a conditional forwarder on the customer's DNS server for the target's zone — to `168.63.129.16` for Azure/`privatelink.*` zones, or to the authoritative on-prem DNS for corporate zones — and ensure the forwarder target is reachable from the VNet. Applied on the DNS server by its owners; the server's IP is irrelevant to the recommendation. |
| **Azure DNS Private Resolver** | Check the Resolver's forwarding ruleset for the target zone: rule exists, target DNS IPs correct/reachable, ruleset linked to the Databricks VNet (Portal > DNS Private Resolvers > Rulesets / Virtual network links). |

Never present a recommendation for an architecture the customer has not confirmed.

## Step 7: Generate Report

First write the chat prescription (Root cause / Fix / Verification — see the global CRITICAL Finalize-Turn rule in SKILL.md), THEN build the visual dashboard using the DiagnosticReport from the orchestrator. **The dashboard is the final ACT of the Path A turn** — do not also output a markdown per-check summary table; the dashboard replaces it.

```python
from datetime import datetime, timezone

timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# Use v2 dashboard with diagnosis cards and fix ordering
html = build_dashboard_v2([report], problem_description, timestamp)
displayHTML(html)
saved_path = save_dashboard_html(html, report)  # writes <stem>.html AND <stem>.json
print(f"[Doctor] Saved report stem: {saved_path}")  # remember this path for follow-up turns
```

`save_dashboard_html(html, report)` writes BOTH `<stem>.html` (the dashboard) and `<stem>.json` (the structured `DiagnosticReport`) to `/Workspace/Users/<email>/network_doctor_reports/`. The JSON copy is what lets a later follow-up turn reload the report after a serverless session reset (see "Resuming after a session reset" in DIAGNOSTIC_MACHINERY). **Note the saved path** — you'll need it if the customer asks a follow-up and `report` is no longer in scope.

The v2 dashboard includes:
- **Diagnosis & Fix Order** section at top with numbered, severity-coded cards
- **Per-target check tables** with status, duration, and details
- **Summary** auto-generated by the correlation engine

Session-reset / follow-up recovery (Step 7b) is shared machinery — see `reference/DIAGNOSTIC_MACHINERY.md`.

## Step 8: Re-verification (after customer applies fixes)

When the customer says they've fixed something, re-run only the failed checks:

```python
# Re-run only the checks that failed, carry forward passing checks
report_v2 = diagnose_target(host, port, context={
    "compute_type": compute_type,
    "azure_checker": checker,
    "ncc_config": ncc_config,
    "ws_ctx": ws_ctx,
    "cluster_id": diagnostic_cluster_id,
    "rerun_failed_only": True,
    "previous_results": report.checks,  # from the initial run
})

# Show updated results
for check_name, result in report_v2.checks.items():
    print(f"[Doctor] {check_name}: {result.status.value.upper()} -- {result.message}")

timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
html = build_dashboard_v2([report_v2], problem_description + " (re-verification)", timestamp)
displayHTML(html)
save_dashboard_html(html, report_v2)
```

Re-verification runs MUST also follow the finalize order: short chat prescription update (what changed since last run), then a fresh `displayHTML(build_dashboard_v2(...))` + `save_dashboard_html(...)`.

## Step 9: Follow-Up

**There is nothing to clean up, and no cluster of ours to delete.** Every cluster in play was started by the customer and belongs to them: never delete one, never stop one, and never offer to. If they want it gone they will do it, and the ask already told them to give it a short auto-terminate.

After the report, offer:
- "Would you like details on any specific check?"
- "Should I re-run diagnostics after you apply a fix? (re-verification mode)"
- "Want me to show the raw traceroute or nslookup output?"
- "Should I run additional checks on another target?"

The user can continue the conversation interactively.
