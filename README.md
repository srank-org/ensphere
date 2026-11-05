<div align="center">

<img src="./assets/ensphere-banner.png" alt="Ensphere" width="100%">

</div>

---

**A security review of the system you own, run by your agent on every release.**

Your agent can already read your code for security holes. Ensphere makes it prove them: every claim is a measured request you can replay, every fix leaves a check your CI runs on every pull request, and nothing is ever called "secure".

Most small teams ship without a security review, and the problems that hurt them are ordinary: an OTP endpoint with no rate limit in front of an SMS bill, an upload path with no size cap, a table with no row policy, a query built by string concatenation. Left to itself, an agent's review has three defects. It skips whole categories, because nothing tells it what a complete pass looks like. Nothing it says can be checked afterward, because its claims rest on reading rather than measurement. And you cannot let it send requests at a running system, because it has no notion of scope or risk. Ensphere supplies the three missing pieces: a written method, a measurement layer with a ledger the report cites, and rules the CLI enforces about where a request may go and how far a probe may push.

It is the review you run before you can afford a penetration test, between the ones you can, and on every release in between. It is not a substitute for one.

---

## Who does what

Ensphere is a tool for the agent. The skill, the method, and the binary are written for a model: exact flags, JSON output, rules stated once. The agent runs every session, sends every request, writes every file, and fixes what the gate rejects.

The owner does five things, each because it cannot be delegated: authorizes the run and names the repository and the sandbox; approves the sandbox commands and the request limits by writing them into the workspace config, which is the only way the guard lets a command through without asking; answers a blocker the agent may not decide, such as a state change on staging; reviews the pull request that carries the system map and the invariants; and signs the statement, because a model cannot sign anything.

---

## How it works

A run is nine sessions. Each reads its inputs from files in the workspace and writes its outputs to files, so a session can run in a fresh subagent with no shared memory, and a run that loses its context resumes from the workspace.

1. **Recon.** The agent reads the source and the running sandbox and writes a stack profile, a table that maps every surface to its role (the login route is an entry point, the invoice route is an authorization decision, the OTP send is a billed operation), the hypotheses specific to this system, and the system map in `.ensphere/surfaces.yaml`: each surface, the files that implement it, the sessions that own its checks.
2. **Plan.** `ensphere run plan` drafts a decision for every session; the agent corrects it from recon and asks you, once, for everything the run still needs.
3. **Checks.** Injection, authentication, authorization, cross-site scripting, server-side request forgery, cloud configuration, API controls, abuse and cost controls. Every check follows one loop. The agent writes a coverage row before it probes, then resolves it with three requests through the CLI, labelled `baseline`, `probe`, and `control`:

   ```bash
   ensphere verify request --url "http://localhost:3000/api/invoices/INV-B" \
     --header "Authorization: Bearer [TENANT_A]" --result probe \
     --note "tenant A reads tenant B's invoice" --in-scope localhost
   ```

   The CLI checks the URL against the approved scope, sends the request, and appends status, timing, headers, and body hash to the session's `evidence.jsonl`, each entry chained to the previous one by hash. It returns the evidence id and no opinion. The agent reads the three results beside the source, decides what they mean, and writes the row as `tested` with the three ids. Measurements that are fiddly by hand have their own commands: a rate-limit burst with header capture, a race with a start barrier, an upload-size probe, a two-tenant row-policy check. There is no other way to send a request; while a workspace exists, the plugin's guard refuses `curl` and every other raw network tool.
4. **Prove.** In the sandbox only, the agent joins the likely findings into multi-step chains and runs each one end to end, so a finding that would matter is demonstrated rather than argued.
5. **Report.** The agent writes the finding registry, the report, and the evidence appendix, and promotes every finding's validation criteria and every defense that held into `.ensphere/invariants/`. Then `ensphere run report` runs the gate: every session done, every tested row citing a baseline, a probe, and a control that exist in the ledger, every finding cited, every open finding promoted to an invariant, every ledger's chain intact, the source tree still at the commit the run began on. When it passes, `ensphere run statement` derives the one-page statement from the workspace, and refuses otherwise.

The line Ensphere holds: the binary does only what can be done the same way every time (send, measure, hash, refuse, count, compare, gate), and the agent does everything that needs judgment (what to check, what a number means, how severe it is, what the fix is). Because none of the reasoning lives in the tool, a better model produces a better assessment with no change to Ensphere, and because every claim points at a measurement, the report can be checked by someone who was not in the room.

---

## Getting started

In Claude Code:

```text
/plugin marketplace add srank-org/ensphere
/plugin install ensphere@srank
```

Say `ensphere-setup` once. It installs the `ensphere` binary at the plugin's version from a signed release, reports which provider CLIs are logged in, and ends with `ensphere run doctor`, the read-only check that a run can proceed. The plugin also installs the guard and a session-start hook. For Codex, another harness, or a build from source, see [Build and Install](docs/cli-reference.md#build-and-install).

In the project you want to check:

```bash
ensphere run init --target "http://localhost:3000" --in-scope localhost
```

Point `--target` at a **sandbox**: a local copy of your app with synthetic data. The agent offers to stand one up from your compose file or dev script and checks that it is isolated from anything real. Add a staging URL only for what a sandbox cannot show, such as the edge in front of your origin. Omit `--target` to assess from source alone.

Then say `ensphere`. The run takes tens of minutes to a few hours and pauses only for what only you can give. At the end the agent tells you the three to five things to fix first and where the report and the statement are.

---

## What you get back

- **The report**, written for the developer who has to act on it: a prioritised fix list that interleaves vulnerabilities and missing controls, the state of every control on every billed service and storage surface, findings with safe reproduction steps, and "checks executed" and "not checked" sections copied from the coverage rows with the reason for each gap. A coverage appendix maps it to OWASP WSTG and ASVS.
- **Two files that stay in your repository** under `.ensphere/`, committed and reviewed like code. The **system map** lets the next run reconcile instead of rediscover, and lets a pull request be assessed against only the surfaces it touched. The **invariants** are the findings' validation criteria and the defenses that held, as declared expectations your own CI runs on every pull request with the binary alone, no agent. A failing invariant is a fact about one expectation; a passing one is never a security verdict.
- **A one-page Statement of Assessment** derived from the workspace: system and commit, dates, environment, model and Ensphere versions, checks executed and not checked, unresolved findings, ledger hashes. It says in plain words that it is a self-assessment and not an audit. It is the document for a security questionnaire; the report is the document to hand a pentester so their hours go to the hard problems.

Nothing in a run needs a person at the keyboard once the inputs are known, so the natural cadence is a run per release or nightly. `ensphere run diff` reports what changed since the previous run, `ensphere run sarif` feeds code scanning, and the pipeline can sign the statement's provenance. The recipe is in [`docs/release-pipeline.md`](docs/release-pipeline.md), with ready-made workflows in [`templates/`](templates/index.md).

---

## Compared with the alternatives

| | Ensphere | Typical scanner | Manual pentest |
| --- | --- | --- | --- |
| Cost and cadence | Agent time, on every release | Subscription, continuous | Thousands, yearly |
| Reads your source code | Yes, alongside the live target | No | Sometimes |
| Who decides what a result means | The agent, with a written method | The tool, by threshold | The tester |
| Evidence you can re-verify | Every request in a ledger, cited per finding | A severity label | A PDF |
| Finds missing controls, not just bugs | Yes, per billed service and storage surface | Rarely | Yes |
| Proves a multi-step chain end to end | Yes, in a sandbox copy of your app | No | Yes |
| Leaves a check behind for every pull request | Yes, invariants your CI runs without an agent | Sometimes, as its own scan | No |
| Independence | None; you sign the statement | None | The firm's name on the result |
| Will ever say "secure" | Never | Often | No |

---

## Does it work?

Not yet measured against a real system. The deterministic half (the runner, the gate, the statement, the map, the invariants) is driven end to end through the real binary in CI with no model, so what the tool enforces is proven. What the method finds is not. The evaluation protocol in [`docs/evaluation/`](docs/evaluation/README.md) defines what a result would be: blind runs against OWASP Juice Shop, OWASP crAPI, and an owned fixture, a frozen report before the answers are opened, and a scorecard for found, missed, and unsupported claims. Until those numbers are published here, treat Ensphere as a method to review, not a result to rely on.

---

## Boundaries

- **It proves only against a copy that cannot be hurt.** Proof happens in a sandbox. Staging receives bounded measurement. Production is never sent a request; only its provider configuration is read. There is no data extraction and no load testing anywhere.
- **It needs your source.** Ensphere is for the person who owns the system. Source is always in scope; a live target is optional.
- **Every request is scoped.** Each verify command requires `--in-scope` and refuses any host outside it, including redirect hops. Bursts need a count you approved. Probes carry a risk level, and the default ceiling refuses the higher ones.
- **It never says "secure".** The report says what was tested, against which assets and roles, and what held. A missing signal is never proof that a surface is absent.
- **The judgment is the model's.** The method is written for a frontier model and kept short enough to read beside your code; a stronger model finds more.

---

## For agents and contributors

The assessment skill's entry point is [`skills/ensphere/SKILL.md`](skills/ensphere/SKILL.md); [`index.md`](index.md) maps the repository and explains how the workspace lets sessions run in fresh subagents or in one context. [`AGENTS.md`](AGENTS.md) is for agents working on Ensphere itself, and [`CONTRIBUTING.md`](CONTRIBUTING.md) holds the engineering bar: keep judgment out of the CLI, keep business logic out of `cli/cmd/`, and never add a command, flag, or payload whose purpose is exploitation, extraction, credential access, or load generation.

## License

[GNU Affero General Public License v3.0](./LICENSE). If you modify Ensphere and offer it over a network, you must offer users the corresponding source.
