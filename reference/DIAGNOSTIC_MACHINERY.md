# Shared Diagnostic Machinery (reference)

Shared, path-independent machinery for all three paths: package policy, the execution model, the driver loop detail, the chunked Path A flow, remote execution on a classic cluster, session-reset recovery, and the secret-scope-creation walkthrough. The thin core in SKILL.md points here; the per-path docs (PATH_A/PATH_B/PATH_C) point here for anything not specific to their path.

## Step 0: NO package installs — go straight to Step 1

**There is NOTHING to install.** Every script in this skill (including `AzureInfraChecker` — migrated to raw ARM REST) uses only `requests`, which is preinstalled on every Databricks runtime. Do NOT run `%pip install` at ANY point in the session — there is no Azure SDK dependency anymore, and on serverless `%pip install` **resets the Python context**, wiping every variable, function, and `exec`-loaded script (observed in the field). If you catch yourself writing `%pip install azure-...` or `import azure.mgmt...`, STOP — that dependency was removed; the checks call `https://management.azure.com` directly.

## Execution model — read this once and remember it for the whole session

This skill runs *inside* the customer's notebook session. The model executes Python in code cells via the Genie Code runtime; the customer is not switching tools. Anything that needs to happen on a classic cluster runs through `run_on_cluster()` from this same session. Never instruct the customer to "open a notebook," "attach the notebook to a cluster," "reattach," "switch to a notebook on cluster X," or otherwise leave this conversation to perform setup. If a step requires code, the model writes and runs that code — full stop.

Do NOT load the scripts with `exec(open(...).read())` — they are proper importable modules now, and plain `import` does not trigger the code-execution safety gate that `exec` did on every load. (The Step 1 import loop itself is in SKILL.md.)

## Step 1b: THE DRIVER — `run_network_doctor()` (full loop detail)

For connectivity (Path A) and cluster-start (Path C) problems, do NOT hand-pick checks or call the lower-level functions yourself — the doctor entry point owns the whole orchestration (path classification, intake gate, SP secret handling, chunked execution, correlation, presentation payload). Your loop is:

```python
# First call: pass the customer's message / error paste VERBATIM.
result = run_network_doctor(problem_text)
```

Then follow `result["status"]` (every call also PRINTS the literal next action):

- **NEED_INPUT** → relay `result["questions"]` to the customer in ONE chat message (no hypotheses, no diagnosis); when they answer, run `run_network_doctor(answers={...}, session_path=r'<printed>')` filling the question ids. SP credentials stay names-only — the doctor resolves them internally.
- **IN_PROGRESS** → run `result["next_step"]` in a NEW cell (one execution turn per phase; the session file survives resets — after a reset just repeat the same call, nothing re-runs).
- **DONE** → present in this exact order: (0) if `result["confirmation_questions"]` is non-empty, ask them FIRST and present only the matching option; (1) post `result["chat_prescription"]` in chat; (2) NEW cell: `displayHTML(nd_render_dashboard(result["session_path"]))`; (3) post `result["dashboard_pointer"]` VERBATIM — never a sentence of your own, and never a claim that the dashboard rendered or is visible. This satisfies the global Finalize-Turn rule.
- **ERROR** → the message says exactly what the customer must fix; relay it and re-call with corrected answers.
- Path B (storage / UC access) is now driven by `run_network_doctor` too — same NEED_INPUT → DONE loop as A and C (it classifies B, traces the credential chain, runs the storage network/RBAC checks network-first, and SELECTS the storage Diagnosis in code). It does NOT hand off. The PATH_B_storage.md prose is the underlying machinery / reference only.

Every call also returns `result["reference_doc"]` naming the matching path doc, and `result["next_step"]` carries a one-line inline summary so the flow is robust even if the reference file is not auto-read.

The manual Steps 2-8 remain valid as the underlying machinery and for re-verification and classic-cluster probe provisioning via 4d. Path B is driver-owned — do not treat those steps as a parallel agent playbook.

## Steps 4-5: Diagnostic machinery context dict

`run_network_doctor()` builds the context and drives the chunked flow itself. You only touch this machinery directly for: re-verification (Step 8), classic-cluster remote probes (4d below), or if the driver returns ERROR and instructs a manual step.

- Azure checker: pass `azure_sp` (secret REFS) in the context — the INFRA phase resolves it via Databricks Secrets and builds `AzureInfraChecker` with auto-discovery. Manual build only when needed: `azure_ctx = auto_discover_azure_context(sp["client_id"], sp["client_secret"], tenant_id=sp["tenant_id"])` then `AzureInfraChecker(**{k: azure_ctx[k] for k in ("tenant_id","client_id","client_secret","subscription_id","resource_group","vnet_name")})`. Do NOT `%pip install` anything, ever — all Azure reads are raw ARM REST over `requests`.
- Long runs (any Azure infra/NCC checks) MUST be chunked — `diagnose_target` REFUSES them with the recipe: `start_diagnosis(host, port, context)` → `continue_diagnosis(ckpt, context)` → `finalize_diagnosis(ckpt, context)`, one cell each, checkpoint persisted after every check, resumable after resets, removed on finalize. Follow each printed "[Doctor] NEXT" verbatim.
- Short serverless-only runs may use single-call `diagnose_target(host, port, context)`.

### Chunked Path A flow (REQUIRED for long runs — one phase per notebook cell, resumable)

```python
start_diagnosis(host, port, context, checkpoint_path=None)   # cell 1: probes; returns checkpoint path (resumes if it exists)
continue_diagnosis(checkpoint_path, context)                 # cell 2: Azure infra + NCC; idempotent
finalize_diagnosis(checkpoint_path, context=None, keep_checkpoint=False)  # cell 3: correlate -> DiagnosticReport; removes checkpoint
load_checkpoint(path)                                        # inspect a checkpoint dict (debugging)
```

context dict keys for `diagnose_target` / `start_diagnosis` / `continue_diagnosis` (all optional except as noted):

```python
{"compute_type": "classic"|"serverless"|"both",
 "azure_checker": AzureInfraChecker | None,
 "azure_sp": dict | None,           # EITHER the secret REFS the intake collected
                                    # ({"scope", "tenant_id_key", "client_id_key", "client_secret_key"})
                                    # OR loaded values ({"tenant_id", "client_id", "client_secret"}).
                                    # The chunked INFRA phase resolves refs via Databricks Secrets and
                                    # builds the AzureInfraChecker automatically (auto-discovery included)
 "ncc_config": dict | None,
 "ws_ctx": dict,
 "cluster_id": str | None,
 "rerun_failed_only": bool,
 "previous_results": dict | None}   # report.checks from a prior run
```

### 4d. Remote Execution (if on serverless testing classic)

If `ws_ctx['is_serverless']` is True and `compute_type` includes "classic", the network probes (DNS, TCP, TLS, etc.) must run on the classic cluster. **Compute-plane alignment is evidence integrity**: when the customer says the failure is on CLASSIC compute, probe results from THIS serverless session are evidence about the wrong network path (serverless and classic VNets/DNS differ) — do not run them in-session first "for a quick look" and do not present in-session results as findings about the classic path (observed in the field). Go straight to the classic cluster via `run_on_cluster()`; the only in-session steps for a classic problem are ARM reads (they're plane-independent). Build the probe code as a string and use `run_on_cluster()`:

```python
import json

_user = spark.sql("SELECT current_user()").collect()[0][0]
_skill_dir = f"/Workspace/Users/{_user}/.assistant/skills/network-doctor/scripts"

# Classic clusters mount /Workspace via FUSE, so the remote cluster imports the
# same modules directly — no source inlining needed.
probe_code = f"""
import sys, json
if "{_skill_dir}" not in sys.path:
    sys.path.insert(0, "{_skill_dir}")
from models import Status
from classic_probers import check_dns, check_latency, check_ping, check_tcp, check_tls, check_traceroute

host = "{host}"
port = {port}
results = {{}}

dns_result = check_dns(host)
results["dns"] = {{"status": dns_result.status.value, "message": dns_result.message, "ips": dns_result.metadata.get("ips", [])}}

if dns_result.status == Status.PASS:
    tcp_result = check_tcp(host, port)
    results["tcp"] = {{"status": tcp_result.status.value, "message": tcp_result.message}}
    if tcp_result.status == Status.FAIL:
        trace_result = check_traceroute(host)
        results["traceroute"] = {{"status": trace_result.status.value, "message": trace_result.message, "raw": trace_result.raw_output[:2000]}}
    if tcp_result.status == Status.PASS:
        tls_result = check_tls(host, port)
        results["tls"] = {{"status": tls_result.status.value, "message": tls_result.message}}
        latency_result = check_latency(host, port)
        results["latency"] = {{"status": latency_result.status.value, "message": latency_result.message, "metadata": latency_result.metadata}}

ping_result = check_ping(host)
results["ping"] = {{"status": ping_result.status.value, "message": ping_result.message}}

print(json.dumps(results))
"""

print("[Doctor] Running network probes on classic cluster (remote execution)...")
probe_result = run_on_cluster(ws_ctx["workspace_url"], ws_ctx["token"], diagnostic_cluster_id, probe_code)

if probe_result["status"] == "OK":
    results = json.loads(probe_result["results"])
    for check_name, data in results.items():
        print(f"[Doctor] {check_name}: {data['status'].upper()} -- {data['message']}")
else:
    print(f"[Doctor] Remote execution failed: {probe_result['error']}")
```

Then run Azure infra checks and NCC checks locally (API-based, no VNet needed), feeding the remote probe results to the correlation engine.

## Step 7b: Resuming after a session reset / follow-up turn

Genie Code's serverless session can drop in-memory state between turns — `report`, `ws_ctx`, and even the imported skill functions may be gone when the customer sends a follow-up (e.g. "we use a custom DNS server — what's your final recommendation?"). Field-observed: re-reading `report` in that follow-up turn STALLS or raises `NameError`. **Do NOT re-run the whole diagnostic and do NOT re-provision a cluster to answer a follow-up.**

Two reset situations, two recoveries:
- **Reset MID-diagnostic (before finalize):** the chunked checkpoint already has every completed check. Re-run Step 1 and simply re-call the driver (`run_network_doctor(...)` with the same problem text or session_path) — sessions and checkpoints resume from disk; nothing recorded re-runs.
- **Reset AFTER the diagnostic (follow-up turn):** recover by reloading the saved report JSON:

```python
# Run this defensively at the top of any follow-up turn. It rebuilds only what's missing.
try:
    report  # is the report still in scope?
except NameError:
    # Session was reset. Re-run Step 1 (the sys.path + importlib loop — no pip install needed)
    # in the cells above FIRST so load_saved_report / models classes exist, then:
    report = load_saved_report("/Workspace/Users/<email>/network_doctor_reports/<stem>.json")
    print(f"[Doctor] Reloaded saved report for {report.target} from JSON (no re-run needed).")
```

Procedure when answering a follow-up after a possible reset:
1. If `report` (or `load_saved_report`, or the `models` classes) is undefined → the session reset. Re-run **Step 1** (the sys.path + importlib loop — no pip install needed, ever) to restore the functions, then `report = load_saved_report(<the .json path you saved>)`. If you don't have the exact path, list `/Workspace/Users/<email>/network_doctor_reports/` and pick the newest `<target>_*.json`.
2. Now answer the follow-up from the reloaded `report` — e.g. for "it's custom DNS", pull the matching FINAL recommendation from the `needs_confirmation` diagnosis's `prescription` (6e in PATH_A_connectivity.md), render the dashboard, and save. No probes, no cluster, no Azure calls are needed just to answer the DNS-architecture question.
3. Only re-run actual checks (Step 8 re-verification) if the customer says they APPLIED a fix and wants to re-verify — not merely to answer a confirmation question.

## Secret handling — Databricks Secrets-First Principle (full detail)

When ANY diagnostic requires verification in Azure (role assignments, NSG rules, DNS zones, Private Endpoints, etc.):

1. **What you ask for is the secret-scope NAME (and, only if non-default, the key NAMES) — never the values.** A secret-scope key name is a label like `azure-tenant-id` that points at a value already stored inside Databricks Secrets — it is NOT itself the tenant id. In the common case you only need the SCOPE NAME (e.g. `my-reader-sp`): the doctor defaults the three key names to `azure-tenant-id` / `azure-client-id` / `azure-client-secret`. Ask the customer for the three key names ONLY if their scope uses different labels. Keep credential-shaped strings (`client_secret`, `tenant_id`, …) OUT of the `run_network_doctor` call cell — pass `answers={'sp_scope': '<scope>'}` in the common case (the upstream safety classifier can deny a call that looks like it carries credentials). When asking, show a worked example so the customer can't confuse "key name" with "value". A correct ask looks like:
   > Reply with your secret SCOPE name, e.g.:
   > - scope: `my-reader-sp`
   > (Only if your scope uses non-default key labels, also send tenant_id_key / client_id_key / client_secret_key — names, never values.)
   > Don't paste tenant ids, client ids, secrets, or any UUID-looking values.

2. **NEVER accept raw credential values in chat — refuse and rotate.** If the customer pastes anything that looks like a tenant id, client id, secret, token, password, or API key (UUIDs, base64 strings, anything with `client_secret=`, `password=`, etc.), STOP. Do not echo the value. Do not pass it to any function. Reply: *"That looks like a raw credential. Treat it as compromised — rotate it immediately in Azure Portal > App registrations > Certificates & secrets. Then store the replacement in Databricks Secrets (see scope-creation walkthrough) and give me the key NAMES, not the values."* Same applies to PATs, OAuth tokens, etc.

3. **If the customer has no secret scope yet — the DRIVER walks them through creating one; you relay it.** Every credential ask offers a third answer, `create`, next to the scope name and `none`. Pass `answers={'sp_scope': 'create'}` and the driver returns the walkthrough below as a NEED_INPUT question, in the flavour that matches the layer that asked (Azure **Reader** for ARM reads, **account admin on the Databricks account** for the account layer). Relay it VERBATIM and wait — do not summarize the commands, do not swap in a portal click-path, and do not record it as a decline (`sp_scope` stays unanswered on purpose, so the ask comes back if they return without a name). Never just say "no scope? use OFFLINE". Only if the customer refuses the walkthrough (no CLI access, platform team owns the workspace) do you fall back to OFFLINE Cloud Shell. **`sp_declined` is reversible:** a customer who answered `none`, created the scope and came back with its name is no longer credential-less — pass the scope and the Azure layer reopens in the same session.

4. **Read-only permission model** — For Azure deep analysis, request only Azure **Reader** permissions. Do not ask for `Owner`, `Contributor`, `User Access Administrator`, or any write-capable role. The Doctor diagnoses and generates precise remediation steps; the customer applies changes through their normal change-control process.

5. **Scope of Reader access** — Because Databricks networking resources can span many resource groups (workspace RG, managed RG, hub/spoke VNets, route tables, NSGs, Azure Firewall/NVA, Private DNS zones, Private Endpoints, storage accounts, and access connectors), the recommended permission for complete deep analysis is **Reader at the relevant Azure subscription scope(s)**. If the customer cannot grant subscription-level Reader, accept Reader on every relevant resource group/resource, but warn that discovery can be incomplete and some checks may be skipped.

Never jump straight to "go to Azure Portal" as the primary recommendation. The secret-scope-based SP approach is always the first choice.

### How deep, before anything else (Paths A and B)

The driver's FIRST question on Paths A and B is `analysis_depth`, and it decides whether the
two credential-bearing questions are asked at all:

- `simple` — no Azure credential. In-workspace probes (on classic, from inside the VNet —
  which is why the cluster question is still asked, and why `simple` is NOT "nothing needed
  from you"), the Databricks-side configuration, and the serverless egress verdict. The
  driver sets `sp_declined` and `workspace_arm_declined` itself, so **do not raise a scope
  question of your own during intake** — the driver won't, and asking anyway contradicts the
  choice they just made.
- `deep` — the above plus the ARM layer, which needs the workspace ARM resource id and the
  Reader SP.

**The ONE exception, and it is deliberate:** on serverless the driver still makes the
account-layer offer after the probes have produced a finding, even under `simple`
(`_credential_ask_is_closed`). The customer sees a measured result before being asked for
anything, and that grant is **account admin on the Databricks account**, not Azure Reader.
Relay it. A typed `none`, or an exhausted ask, does close it.

**What `simple` does NOT mean on Path B.** There is no DNS/TCP/TLS suite on the storage
path, and the storage account's firewall, network perimeter and role assignments are all ARM
reads — so `sp_declined` on Path B lands on the `storage_needs_sp` diagnosis ("Cannot
Determine Root Cause Without an Azure Reader SP") with four of five rows skipped. The
driver's Path B depth question says this outright; do not talk the customer past it.

Two more consequences. **`simple` is reversible only while the run is unfinished**: the
driver records exactly what the choice switched off, so a later `deep` re-opens the Azure
layer, leaving a `none` the customer typed deliberately alone — but once the session reaches
`done` it re-serves its stored result and supplying a scope changes nothing, so the upgrade
is a FRESH run. And **the credential ask is bounded**: the terse ask, the walkthrough below,
and one more ask with no scope name, after which the driver switches the run to `simple`
itself and says so — relay that, including what it leaves unverified, instead of presenting
a reduced run as a complete one.

Path C is never asked the depth question. Its diagnosis is read entirely from ARM, so
there is no credential-free version: a customer with no Reader SP cannot have the Azure
config inspected, and the report says so rather than guessing. There is no offline
snapshot — the ARM config is read LIVE, or (if the runtime cannot reach ARM) the customer
is told which egress to enable and to re-run.

### Scope-creation walkthrough (use when the customer has no Databricks-backed secret scope)

This is the reference copy. The driver emits the same thing itself (`doctor._scope_setup_question`) when the customer answers `create`, so in a live session RELAY THE DRIVER'S TEXT rather than retyping this one — that is what keeps every customer getting the same commands. Hand the customer this exact set of `databricks` CLI commands. They run them in their LOCAL terminal — the values are typed locally, never pasted into this chat:

```bash
# 1. Create a Databricks-backed secret scope (one-time).
databricks secrets create-scope <scope-name>     # e.g. my-reader-sp

# 2. Store the SP credentials. Each command prompts for the value
#    interactively — paste the value at the local prompt, not in chat.
databricks secrets put-secret <scope-name> azure-tenant-id
databricks secrets put-secret <scope-name> azure-client-id
databricks secrets put-secret <scope-name> azure-client-secret

# 3. Verify.
databricks secrets list-secrets <scope-name>
```

Tell the customer: the SP must already exist in Azure AD with **Reader** at the relevant subscription / RG scopes (see permission section above). If they don't have an SP yet, point them at Azure Portal > App registrations > New registration — they create it once, then store the three values via the CLI commands above. After the scope exists, the customer comes back to chat and provides the scope NAME only — the doctor defaults the three key names, so key names are needed only if their labels differ from `azure-tenant-id` / `azure-client-id` / `azure-client-secret`.

The same walkthrough applies with an explicit ACL set (`databricks secrets put-acl <scope> <user-or-group> READ`). Explain if new to them: a scope is a named container; the keys are NAMES, not values; the values are read in-notebook via `dbutils.secrets.get()`; the secret ACL is separate from the SP's Azure Reader role.

If the customer refuses to use the CLI (no local install, no access, etc.), there is no offline fallback for the ARM/Azure-config layer: the Azure inspection needs a Reader SP, and without one the report names the Azure layer as not inspected rather than guessing a cause.

## Step 6 mechanics shared across paths

Enter Step 6 (gates + final-recommendation selection) only AFTER a diagnostic has run and produced `report`. The per-path Step 6 detail and the DNS 6e table live in PATH_A_connectivity.md; the CONFIRMATION GATE, ASK-ONLY-ACTIONABLE, Healthy fast-path, and Presentation rules apply to every path that finalizes a diagnosis. The chat prescription always comes FROM `diagnosis.root_cause`/`diagnosis.prescription` (the driver pre-builds it as `chat_prescription`) — never invent a fix that is not in a Diagnosis.
