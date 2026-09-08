# Changelog

The version shown in the footer of every report is the version you are running.
Quote it if you need help with a result.

## 1.1.0 — 2026-09-07

### Changed

- **The Azure configuration is now read only LIVE — the offline snapshot mode was removed.**
  Previously, when the notebook could not reach Azure Resource Manager (serverless with a
  restrictive egress policy), the tool handed you a script to run in Azure Cloud Shell that
  dumped your network config to a file it then read. That file was a point-in-time copy taken
  from a different identity; a cluster-start or connectivity problem has to be read from your
  configuration as it is now. So when the runtime cannot reach ARM, the tool instead names the
  exact egress to enable — outbound HTTPS to `management.azure.com` and
  `login.microsoftonline.com` (serverless: Account Console > Settings > Network; classic: the
  data-plane subnet's route table / NSG / firewall) — and you re-run for a live diagnosis. If
  your security policy forbids that egress, the report says the Azure layer was not inspected
  rather than working from a snapshot.

### Fixed

- **Cluster-start error codes now route to the cluster-start diagnosis.** A paste of only the
  Azure termination code — `NPIP_TUNNEL_SETUP_FAILURE`, `NETWORK_CONFIGURATION_FAILURE`,
  `SUBNET_EXHAUSTED_FAILURE`, `CONTROL_PLANE_REQUEST_FAILURE`, `DRIVER_UNREACHABLE`,
  `SECURITY_DAEMON_REGISTRATION_EXCEPTION` — with no "won't start" prose used to be classified
  as a connectivity problem and then asked for a destination host that a broken cluster does
  not have. These now go to the cluster-start (Azure-config) diagnosis.
- **A blackhole default route now leads the cluster-start diagnosis.** When the data-plane
  subnet's `0.0.0.0/0` route is a blackhole (next hop `None`), that is the root cause of a
  cluster that cannot bootstrap — but on the cluster-start path it was found as a failing check
  and never surfaced as the diagnosis, so a lower-severity NSG finding led instead. The route
  now leads, with the fix (correct the route table) named first.

## 1.0.0 — 2026-09-01

First release for customers outside Databricks.

### What it does

- Diagnoses three families of Azure Databricks network failure, classified from your own
  description in any language: **connectivity** from a cluster or serverless warehouse to a
  data source, **storage / Unity Catalog access** errors that look like permissions problems
  but are not, and **classic cluster start / NHC** failures.
- Reads your real Azure configuration through a read-only service principal — NSGs, route
  tables, peerings, Azure Firewall policies, Private Endpoints, Private DNS zones, storage
  network settings — plus the serverless NCC and egress policy at the Databricks account
  layer, and traces the actual egress path rather than checking layers in isolation.
- Correlates the results with deterministic rules into a ranked diagnosis: the same evidence
  produces the same primary cause every run, with a stable fix order.
- Reports what it could **not** verify. A layer it had no credentials for, or no permission
  to read, is listed as unverified rather than quietly passed.
- Saves an HTML dashboard and a structured JSON report in your workspace.

### Behaviour worth knowing

- **It asks one question at a time**, and never proposes a cause before it has run checks
  against your infrastructure.
- **The diagnosis is delivered as text in the chat.** The dashboard is extra detail, not the
  deliverable: it is drawn by a notebook cell, and if that does not render you still have the
  complete answer — the cause, the fix, the checks that failed with their messages, and every
  layer that was not checked, all named in the conversation.
- **One diagnosis covers one compute plane — serverless or classic, never both.** They are
  different networks: classic egresses through your VNet, serverless does not touch it and is
  governed by your Databricks account's network policy. If both are failing, run one
  diagnosis for each and get two correct answers instead of one that mixes them up.
- **It asks how far to go before it asks you for anything.** On a connectivity or storage
  problem the first question is `simple` (needs no Azure credential — probes from inside
  your workspace, and on classic from inside your VNet) or `deep` (that plus your Azure
  network configuration, which needs the workspace resource id and a read-only service
  principal). The report always names the layers left unverified. Two honest caveats: the
  upgrade from simple to deep is a **fresh run**, not a continuation; and on a storage /
  Unity Catalog error `simple` is thin, because almost everything that decides those is read
  from Azure. A cluster-start problem is not asked at all, because it has no credential-free
  version.
- **"I don't have a service principal" is an answer.** It replies with the exact CLI
  commands to create the secret scope, keeps the question open, and continues where it left
  off when you come back with the scope name. If you still can't produce one, it stops
  asking and gives you the simple analysis rather than the same question again.
- **Credentials are handled by name only.** You give it the name of a Databricks secret
  scope; values are read at runtime and never printed, logged, or written into a report.
- **Azure is read-only** — GET requests only, nothing in Azure is ever modified. On the
  Databricks side the only thing written is the saved report, and **no compute is ever
  created**: the classic probes run on a cluster you started, addressed by the id you gave.
  Declining to start one costs you the in-VNet probes and nothing else.
- **Every check row says which network it was measured on.** The report's checks table has a
  **Measured on** column: for the classic probes it names the cluster that ran them and
  whether that machine was confirmed to be inside your VNet. A probe measures the network of
  the machine that runs it, so this is what makes a diagnosis checkable by hand.
- **`Reader` is the only Azure role it needs.** Subscription scope gives the fullest
  coverage; resource-group scope works with less.

### Fixed in this release

- The Databricks **account id** could be asked for indefinitely, and any reply was accepted
  as the id — so a polite "I'll have to ask our admin" was sent to the account API and the
  failure read as if the account were misconfigured. The ask now recognises a UUID, says so
  when it cannot, and after two replies with no id finalizes with the NCC layer honestly
  marked as not inspected.

- An unexpected internal error used to surface as a raw Python traceback. The entry point now
  always returns a readable error. (It also used to be able to leave a diagnostic cluster of
  its own running — the tool no longer creates compute at all, so there is nothing to leak.)
- A `Connected` VNet peering whose remote hub could not be read was reported as a critical
  "recreate the peering" — advice to rebuild something that was working, when the service
  principal simply lacked `Reader` on the hub. Unprovable now degrades to a note instead of
  a false verdict.
- Azure discovery ignored the workspace resource id when it was supplied, so a run without
  access to instance metadata skipped the entire Azure-configuration suite despite having
  valid credentials and the exact id.
- The report footer carried a hardcoded version that nothing updated.
- A run that honestly could not reach a verdict said so in its counts and then said nothing
  about what would produce one. A storage error diagnosed without an Azure credential now
  states plainly, in the chat message, that it has no verdict and what would settle it.

### Known limitations

- **Azure only.** The Azure-configuration and NCC checks are specific to Azure Databricks.
- **Classic-compute probes need a cluster you start.** The probes must run inside your VNet,
  so they run on one of your classic clusters and the tool asks for its id — it never creates
  compute. Without a running cluster the network-path probes do not run, and the report says
  which layers that leaves unverified. An id that is not actually RUNNING produces those same
  unverified rows rather than a measurement taken somewhere else.
- **Serverless diagnosis is account-layer.** Serverless compute does not egress through your
  workspace VNet, so VNet findings do not apply to it and the tool will not claim they do.
  Inspecting the NCC needs a service principal that is a Databricks account admin; without
  it the NCC is reported as not inspected.
- **Coverage follows the service principal's scope.** Anything outside it comes back
  unverified, by design rather than as a failure.
- **Public Azure only.** The Azure endpoints are `management.azure.com` and
  `login.microsoftonline.com`; sovereign clouds (Azure Government, Azure China) are neither
  supported nor tested.
- **Reports accumulate.** They are written to
  `/Workspace/Users/<you>/network_doctor_reports/` and never cleaned up automatically. A
  report names the Azure resources it read (subnets, NSGs, storage accounts, IP ranges), so
  review one before sending it outside your organisation.
