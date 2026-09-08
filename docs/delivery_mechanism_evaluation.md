# Why Genie Code Skill (and not MCP)

This is a short decision narrative for anyone forking this project and wondering "why isn't this an MCP server?" The Genie Code Skill is the canonical delivery mechanism; MCP was evaluated and rejected for one specific architectural reason. The trade-offs below also apply if you're building a similar diagnostic tool for Databricks on Azure.

## The verdict in one sentence

**Network probes have to run inside the customer's VNet, and MCP servers run outside it.** Everything else flows from that.

## The setup

The Network Doctor needs to test things like:

- Does the cluster's DNS resolve `<storage>.dfs.core.windows.net` to a Private Endpoint IP?
- Can TCP 443 actually connect from this subnet?
- What does the effective route table do with `0.0.0.0/0`?

For those answers to be useful, the probes must execute from **inside the same network namespace as the customer's compute**. Otherwise you're measuring the Databricks control plane's view of the world, not the customer's.

## Why MCP doesn't fit

[Databricks Apps](https://docs.databricks.com/aws/en/dev-tools/databricks-apps/networking) (where you'd host a custom MCP server) run on serverless compute **outside the customer's VNet**. DNS resolution, TCP reachability, and traceroute from there are misleading: a probe that says "I can resolve the storage account" from the app's network has no bearing on whether the customer's classic cluster can.

You can work around this with the [Command Execution API](https://docs.databricks.com/api/workspace/commandexecution) — the MCP server sends probe code to a cluster, waits for output, returns it. But by the time you've added that indirection, you've reinvented the simpler thing: just run the skill *as* the customer in a notebook context.

Other practical issues with MCP for this product (less fundamental, but worth flagging):

- **20-tool limit** across all MCP servers attached to a Genie Code agent. The diagnostic engine has 14+ logical tools; that consumes most of the budget.
- **No HTML rendering** — MCP returns JSON, so the polished dashboard would have to be reconstructed by the LLM, unreliably.
- **9+ deployment steps** (app create, sync, deploy, secret scope, attach to Genie Code) vs cloning one Git folder for the skill.

## Where MCP would make sense

Products that need only API access and not VNet-local execution. Examples on Databricks:

- Workspace health checker
- Cost optimization advisor
- Unity Catalog audit / lineage tool

For any of those, MCP's deployment story (one app, attached to many users, centrally maintained) is a real win. Just not for network probes.

## Why Genie Code Skill works

- **Probes run on the customer's own cluster** via the notebook context — accurate VNet-level diagnostics.
- **Conversational intake** — customer describes the problem in natural language; the skill asks structured follow-ups before running anything.
- **Zero footprint** — no Delta tables, no schemas, no infrastructure, and no compute created. Deleting the folder is the whole uninstall.
- **Install is a clone** — the repo goes into `.assistant/skills/network-doctor` as a Databricks Git folder, and updating is a `Pull`.
- **Transparent** — every script is plain Python the customer can read in their workspace before approving execution.

## Known weaknesses (the honest part)

These are real and worth knowing if you fork this:

- **Skill bootstrap remains prompt-dependent.** The script loader now uses `importlib` modules (not `exec()`), but the agent still has to reliably run Step 1 before diagnostics.
- **Reliability depends on SKILL.md.** The conversational protocol is a long prompt asking the LLM to follow specific instructions. Model upgrades or context truncation can shift behavior without code changes — which is why the `dev` branch runs the chaos→detect loop (break real infra → drive the live Genie Code UI → verify the Doctor still finds it) to catch regressions.
- **No progress indicators.** Long operations (cluster startup, traceroute) only print to output. No progress bar.
- **Live Genie UI remains a manual gate.** There is no public Genie Code API for full end-to-end UI automation, so release confidence still depends on browser-harness rounds plus workspace artifact evidence.

## Sources

- [Custom MCP Servers on Databricks Apps](https://docs.databricks.com/aws/en/generative-ai/mcp/custom-mcp)
- [Connect Genie Code to MCP servers](https://docs.databricks.com/aws/en/genie-code/mcp)
- [Databricks Apps networking](https://docs.databricks.com/aws/en/dev-tools/databricks-apps/networking)
- [Genie Code skills](https://docs.databricks.com/aws/en/genie-code/skills)
