<div align="center">

<img src="./assets/ensphere-banner.png" alt="Ensphere" width="100%">

</div>

---

**A security review of the system you own, run by your agent on every release.**

Your agent can already read your code for security holes. Ensphere makes it prove them: every claim is a measured request you can replay, every fix leaves a check your CI runs on every pull request, and nothing is ever called "secure".

Most small teams ship without a security review, and the problems that hurt them are ordinary: an OTP endpoint with no rate limit in front of an SMS bill, an upload path with no size cap, a table with no row policy, a query built by string concatenation. Ensphere is a skill for agents plus a small Go CLI. Point the agent at your repository and a disposable copy of your app. It learns your stack, decides what needs checking, measures each check through the CLI, proves what matters in the sandbox, and writes a report of what is broken, which controls are missing, how to fix each one, and exactly what was and was not checked.

It is the review you run before you can afford a penetration test, between the ones you can, and on every release in between. It is not a substitute for one.

---

## Why Ensphere exists

Your agent can already review your security. Ask it to, and it will read your code and produce a confident list. Left to itself that review has three defects. It skips whole categories, because nothing tells it what a complete pass looks like. Nothing it says can be checked afterward, because its claims rest on reading rather than measurement. And you cannot let it send requests at a running system, because it has no notion of scope or risk.

Ensphere supplies the three missing pieces: a written method that says what every system must satisfy, a measurement layer that records every request in a ledger the report cites, and rules the CLI enforces about where a request may go and how far a probe may push. The agent does the thinking. Ensphere makes the thinking complete, checkable, and safe to act on.

---

## Who does what

Ensphere is a tool for the agent. The skill, the method, and the binary are written for a model: exact flags, JSON output, rules stated once. The agent runs every session, sends every request, writes every file, and fixes what the gate rejects.

The person who owns the system does five things, each one because it cannot be delegated:

- **Authorizes the run** and names the repository and the sandbox. Ownership is never inferred from repository access.
- **Approves the sandbox commands and the request limits** by writing them into the workspace config. Those are the only commands the guard lets through without asking, and a burst runs only with a count the owner wrote down.
- **Answers a blocker** the agent is not allowed to decide, such as a state change on staging.
- **Reviews the pull request** that carries the system map and the invariants, like any other code review.
- **Signs the statement.** A model cannot sign anything, and the statement says so.

---

## How Ensphere works

A run is nine sessions. Each one reads its inputs from files in the workspace and writes its outputs to files, so a session can run in a fresh subagent with no shared memory, and a run that loses its context resumes from the workspace.

1. **Recon.** The agent reads the source and the running sandbox and writes what it learned: a stack profile, a table that maps every surface to its role (the login route is an entry point, the invoice route is an authorization decision, the OTP send is a billed operation), the hypotheses specific to this system, and the system map in `.ensphere/surfaces.yaml`, which names the files that implement each surface and the sessions that own its checks.
2. **Plan.** `ensphere run plan` drafts a decision for every session from the config. The agent corrects the draft from what recon found and asks the owner, once, for everything the run still needs.
3. **Checks.** Injection, authentication, authorization, cross-site scripting, server-side request forgery, cloud configuration, API controls, abuse and cost controls. Every check follows one loop. The agent writes a coverage row before it probes: the surface, the check, the identity, `planned`. Then it resolves the row with three requests, all through the CLI, labelled `baseline`, `probe`, and `control`:

   ```bash
   ensphere verify request --url "http://localhost:3000/api/invoices/INV-B"      --header "Authorization: Bearer [TENANT_A]" --result probe      --note "tenant A reads tenant B's invoice" --in-scope localhost
   ```

   The CLI checks the URL against the approved scope, sends the request, and appends status, timing, headers, and body hash to the session's `evidence.jsonl`, each entry chained to the previous one by hash. It returns the evidence id and no opinion. The agent reads the three results beside the source, decides what they mean, and writes the row as `tested` with the three ids. A few measurements that are fiddly by hand have their own commands: a rate-limit burst with header capture, a race with a start barrier, an upload-size probe, a two-tenant row-policy check. There is no other way for the agent to send a request; while a workspace exists, the plugin's guard refuses `curl` and every other raw network tool.
4. **Prove.** In the sandbox only, the agent joins the likely findings into multi-step chains and runs each one end to end, resetting the sandbox with the approved command between attempts, so a finding that would matter is demonstrated rather than argued.
5. **Report.** The agent writes the finding registry, the report, and the evidence appendix, and promotes every finding's validation criteria and every defense that held into `.ensphere/invariants/`. Then `ensphere run report` runs the gate: every session done, every `tested` row citing a baseline, a probe, and a control that exist in the ledger, every finding cited with valid fields, every open finding promoted to an invariant, every ledger's chain intact, and the source tree still at the commit the run began on. A failure names the file. When the gate passes, `ensphere run statement` derives the one-page statement from the workspace, and refuses to run otherwise.

The line Ensphere holds is this: the binary does only what can be done the same way every time (send, measure, hash, refuse, count, compare, gate), and the agent does everything that needs judgment (what to check, what a number means, how severe it is, what the fix is). Neither can do the other's job, and the gate is where they meet. Because none of the reasoning lives in the tool, a better model produces a better assessment with no change to Ensphere, and because every claim points at a measurement, the report can be checked by someone who was not in the room.

---

## Running it

Ensphere is a Claude Code plugin plus a Go binary. In Claude Code:

```text
/plugin marketplace add srank-org/ensphere
/plugin install ensphere@srank
```

Then say `ensphere-setup` once. It installs the `ensphere` binary at the plugin's version, from a signed release when one exists and from source otherwise, tells you which provider CLIs are logged in, and ends with `ensphere run doctor`, the read-only check that a run can proceed here. The plugin also installs two hooks: while a project holds an assessment workspace, raw network tools such as `curl` are refused so every request goes through the CLI's scope enforcement, and each new session starts from the workspace's next action. Set `ENSPHERE_GUARD=off` to switch the guard off for a shell.

For Codex or another harness that loads skills from a directory, or to build by hand:

```bash
git clone https://github.com/srank-org/ensphere.git
cd ensphere
make build            # builds bin/ensphere
make install-all      # installs the binary to /usr/local/bin and the skill to ~/.claude and ~/.codex
```

You need **Go 1.26+** to build from source. If you later switch to the plugin, remove the copied skill with `./install-skills.sh --uninstall --target claude` so it is not loaded twice. For platform configuration checks the agent uses the provider's own CLI, so have `aws`, `gcloud`, `az`, `wrangler`, or `supabase` installed and logged in for the platforms you run on. The agent tells you which one it needs and marks the check blocked until you sign in.

Then, in the project you want to check:

```bash
ensphere run init --target "http://localhost:3000" --in-scope localhost
```

Point `--target` at a **sandbox**: a local instance of your application with synthetic data. The agent offers to stand one up from your compose file or dev script, checks that it is isolated from anything real, and seeds the accounts, tenants, and objects the checks need. Add a staging URL for the checks a sandbox cannot show: the edge in front of your origin, deployed configuration, the shared rate-limit store. If you cannot run the app at all, omit `--target`; the assessment runs from source alone and marks every live measurement as not tested.

Now open your agent in that directory and say `ensphere`. It runs the nine sessions described above in one go, tens of minutes to a few hours depending on the size of the system, and pauses only for the things only you can give: the go-ahead to start the sandbox, a login to a provider, a decision about staging. When it finishes it tells you the three to five things to fix first, where the report and the statement are, and that the statement is yours to sign.

The CLI is the agent's instrument, but nothing stops you from holding it. Measure whether an endpoint throttles a burst you have approved:

```bash
ensphere verify ratelimit --url "https://staging.example.com/api/otp" \
  --method POST --burst-count 10 --window-sec 10 --in-scope staging.example.com
```

It records ten status codes, ten timings, and any rate-limit headers. It does not say "rate limit missing". You, or the agent, read the numbers. The full command surface is in [`docs/cli-reference.md`](docs/cli-reference.md).

---

## Running it on every release

Nothing in a run needs a person at the keyboard once the inputs are known. The agent collects every input in the planning step and pauses only at five gates, and each gate can be answered in advance in the workspace config: the authorization statement, the sandbox start, seed, and reset commands, the approved burst counts, and who signs. So the natural cadence is a run per release, or nightly, with the report and the statement attached to the release. A run is agent time measured in tens of minutes to a few hours depending on the size of the system, so it is not a pull-request check.

Three outputs are deterministic and safe to gate a pipeline on. The statement command exits non-zero until the report gate passes; the finding registry lists every unresolved finding with its priority; and `ensphere run diff` compares the run with the previous release's and reports every finding that is new, reopened, or resolved and every check whose state changed, so a control that disappeared shows up as a fact rather than an opinion. `ensphere run sarif` sends findings to code scanning, and the pipeline can sign the statement's provenance so a reader can verify which workflow produced it, on which commit, with which ledgers. The recipe is in [`docs/release-pipeline.md`](docs/release-pipeline.md) and a ready-made workflow in [`templates/github-workflow.yml`](templates/github-workflow.yml).

---

## What you get back

An `ensphere-pentest/` directory in your project, one folder per session, each with its plan, evidence ledger, transcripts, and report. The final report is written for the developer who has to act on it: the three to five things to fix first, a fix list that interleaves vulnerabilities and missing controls by priority, the state of every control on every billed service and storage surface, detailed findings with safe reproduction steps, and a "checks executed" and a "not checked" section copied from the coverage rows, with the reason for each gap. A coverage appendix maps it all to OWASP WSTG and ASVS and marks what no session covers. The full structure is in [Session 09](skills/ensphere/methodology/09-report.md).

Two things stay in your repository under `.ensphere/`, committed and reviewed like code. The **system map** says what the system is for, which product fills each role, and every surface with the files that implement it, so the next run reconciles instead of rediscovering and a change in a pull request can be traced to the surfaces it touches. The **invariants** are the findings' validation criteria and the defenses that held, written as declared expectations your own CI runs on every pull request with the binary alone, in minutes, with no agent. A failing invariant is a fact about one expectation; a passing one is never a security verdict.

Alongside it is a one-page **Statement of Assessment** derived from the workspace: system, dates, environment, model and Ensphere versions, checks executed and not checked, unresolved findings by severity, and the ledger's final hash. It says in plain words that it is a self-assessment by the system owner and not an independent audit. It is the document to attach to a security questionnaire, and the report is the document to hand a pentester so their hours go to the hard problems.

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

Not yet measured against a real system. Ensphere is a proof of concept published for review, and a clean run is not a security guarantee. The deterministic half, the runner, the gate, the statement, the map, and the invariants, is driven end to end through the real binary in CI with no model, so what the tool enforces is proven; what the method finds is not. The claims above describe the design. The evaluation protocol in [`docs/evaluation/`](docs/evaluation/README.md) defines what a result would be: blind runs against targets with known ground truth (OWASP Juice Shop, OWASP crAPI, and a small owned fixture), a frozen report before the answers are opened, and a scorecard for found, missed, and unsupported claims. Until those numbers are published here, treat Ensphere as a method to review, not a result to rely on.

---

## Boundaries

- **It proves only against a copy that cannot be hurt.** Proof, including chains and state changes, happens in a sandbox. Staging receives bounded measurement, and a probe that would change state there needs explicit authorization and cleanup evidence. Production is never sent a request; only its provider configuration is read. There is no data extraction and no load testing anywhere.
- **It needs your source.** Ensphere is for the person who owns the system. Source is always in scope; a live target is optional.
- **Every request is scoped.** Each verify command requires `--in-scope` and refuses any host outside it, including redirect hops. Rate-limit probes require a burst count you approved; there is no default. Probes carry a risk level, and the default ceiling refuses the higher ones.
- **It never says "secure".** The report says what was tested, against which assets and roles, with which controls, and what held. A missing signal is never treated as proof that a surface is absent.
- **The judgment is the model's.** Ensphere holds the method and the measurements steady. The methodology files are written for a frontier model and kept short enough to read alongside your code; a stronger model finds more.

---

## For agents

The repository is a Claude Code plugin: `.claude-plugin/plugin.json` is the manifest, `skills/ensphere/` is the assessment skill, `skills/ensphere-setup/` installs the matching binary, `agents/ensphere-session.md` is the fresh-context agent that runs one check session, and `hooks/` holds the assessment guard. `make install-all` copies the skill to `~/.claude/skills/ensphere` and `~/.codex/skills/ensphere` for harnesses without plugins. The entry point is [`skills/ensphere/SKILL.md`](skills/ensphere/SKILL.md), which loads the contract, the fundamentals map, and one methodology file per session. The workspace is the protocol between sessions: an orchestrator can run recon, planning, and the report itself and dispatch each check session to a fresh subagent with a short brief, and a harness without subagents runs the same files in one context and resumes from `next-action.md` after a context loss. [`AGENTS.md`](AGENTS.md) is the entry point for agents working on the Ensphere codebase itself.

---

## Contributing

Contributions are welcome under the same license. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for the engineering bar and the checks to run before opening a pull request. The short version: keep judgment out of the CLI, keep business logic out of `cli/cmd/`, and never add a command, flag, or payload whose purpose is exploitation, extraction, credential access, or load generation.

---

## License

[GNU Affero General Public License v3.0](./LICENSE). If you modify Ensphere and offer it over a network, you must offer users the corresponding source.
