<div align="center">

<img src="./assets/ensphere-banner.png" alt="Ensphere" width="100%">

</div>

---

**A security review of the system you own, run by your agent on every release.**

Most small teams ship without a security review, and the problems that hurt them are ordinary: an OTP endpoint with no rate limit in front of an SMS bill, an upload path with no size cap, a table with no row policy, a query built by string concatenation. Ensphere is a skill for agents plus a small Go CLI. Point the agent at your repository and a disposable copy of your app. It learns your stack, decides what needs checking, measures each check through the CLI, proves what matters in the sandbox, and writes a report of what is broken, which controls are missing, how to fix each one, and exactly what was and was not checked.

It is the review you run before you can afford a penetration test, between the ones you can, and on every release in between. It is not a substitute for one.

---

## Why Ensphere exists

Your agent can already review your security. Ask it to, and it will read your code and produce a confident list. Left to itself that review has three defects. It skips whole categories, because nothing tells it what a complete pass looks like. Nothing it says can be checked afterward, because its claims rest on reading rather than measurement. And you cannot let it send requests at a running system, because it has no notion of scope or risk.

Ensphere supplies the three missing pieces: a written method that says what every system must satisfy, a measurement layer that records every request in a ledger the report cites, and rules the CLI enforces about where a request may go and how far a probe may push. The agent does the thinking. Ensphere makes the thinking complete, checkable, and safe to act on.

---

## How Ensphere works

Ensphere splits the work along one line and holds it there.

- **The CLI is deterministic.** It sends scoped HTTP requests, measures timing, hashes responses, captures headers, counts rows, reads provider configuration through the provider's own CLI, validates scope, redacts secrets, and appends every observation to an evidence ledger. It never says "vulnerable" or "safe". A contract test rejects any output field that would carry a verdict.
- **The agent does the reasoning.** It reads your source and the raw numbers side by side and resolves each claim the same way: a baseline request, the smallest probe that distinguishes the claim, and a control that rules out the obvious alternative explanation. Every finding cites evidence IDs in the ledger, and the report gate refuses a check that has a probe but no baseline or control behind it.
- **The methodology is a floor, not a ceiling.** A short file lists the roles every system has, whatever it is built on, and the invariant each must satisfy: an entry point has a deliberate authentication state, a query only ever receives user data as a parameter, a billed operation runs behind a limiter keyed on the caller. That map guarantees nothing is skipped. Then the agent reads what your particular system is for and writes down what a motivated user of it would go after: the coupon that can be applied twice, the webhook that can be replayed, the price the client is trusted to compute. Each hypothesis is tested like any other check, and the ones that hold up are proven end to end in the sandbox.

Because none of the reasoning lives in the tool, a better model produces a better assessment with no change to Ensphere. And because every claim points at a measurement, the report can be checked by someone who was not in the room.

---

## Running it

```bash
git clone https://github.com/srank-org/ensphere.git
cd ensphere
make build            # builds bin/ensphere
make install-all      # installs the binary to /usr/local/bin and the skill to ~/.claude and ~/.codex
```

You need **Go 1.26+** to build and an **agent surface that can load a skill**: Claude Code, Codex, or similar. For platform configuration checks the agent uses the provider's own CLI, so have `aws`, `gcloud`, `az`, `wrangler`, or `supabase` installed and logged in for the platforms you run on. The agent tells you which one it needs and marks the check blocked until you sign in.

Then, in the project you want to check:

```bash
ensphere run init --target "http://localhost:3000" --in-scope localhost
```

Point `--target` at a **sandbox**: a local instance of your application with synthetic data. The agent offers to stand one up from your compose file or dev script, checks that it is isolated from anything real, and seeds the accounts, tenants, and objects the checks need. Add a staging URL for the checks a sandbox cannot show: the edge in front of your origin, deployed configuration, the shared rate-limit store. If you cannot run the app at all, omit `--target`; the assessment runs from source alone and marks every live measurement as not tested.

Now open your agent in that directory and say `ensphere`. It runs five phases in one go and pauses only for things only you can give: the go-ahead to start the sandbox, a login to a provider, a decision about staging.

1. **Recon.** Reads the repository, stands up and seeds the sandbox, writes a stack profile and a role table, and lists the hypotheses specific to your system.
2. **Plan.** The stack profile picks the checklists. The agent decides which sessions apply and asks for everything it still needs, once.
3. **Check.** Injection, authentication, authorization and workflow state, cross-site scripting, server-side request forgery, cloud and platform configuration, API controls, abuse and cost controls. Each check is baseline, probe, control, and each observation lands in the ledger.
4. **Prove.** In the sandbox, joins what it found into multi-step chains and runs each one end to end, so a finding that would matter is demonstrated rather than argued.
5. **Report.** A prioritised fix list, the missing controls per service, detailed findings with safe reproduction steps, what was checked, what was not and why, and a one-page statement.

You can also drive the CLI by hand. Measure whether an endpoint throttles a burst you have approved:

```bash
ensphere verify ratelimit --url "https://staging.example.com/api/otp" \
  --method POST --burst-count 10 --window-sec 10 --in-scope staging.example.com
```

It records ten status codes, ten timings, and any rate-limit headers. It does not say "rate limit missing". You, or the agent, read the numbers. The full command surface is in [`docs/cli-reference.md`](docs/cli-reference.md).

---

## Running it on every release

Nothing in a run needs a person at the keyboard once the inputs are known. The agent collects every input in the planning step and pauses only at five gates, and each gate can be answered in advance in the workspace config: the authorization statement, the sandbox start, seed, and reset commands, the approved burst counts, and who signs. So the natural cadence is a run per release, or nightly, with the report and the statement attached to the release. A run is agent time measured in tens of minutes to a few hours depending on the size of the system, so it is not a pull-request check.

Two outputs are deterministic and safe to gate a pipeline on. The statement command exits non-zero until the report gate passes, and the finding registry lists every unresolved finding with its priority. Compare the missing-controls table with the previous release's, and a control that disappeared shows up as a fact rather than an opinion. The recipe is in [`docs/release-pipeline.md`](docs/release-pipeline.md).

---

## What you get back

An `ensphere-pentest/` directory in your project, one folder per session, each with its plan, evidence ledger, transcripts, and report. The final report is written for the developer who has to act on it: the three to five things to fix first, a fix list that interleaves vulnerabilities and missing controls by priority, the state of every control on every billed service and storage surface, detailed findings with safe reproduction steps, and a "checks executed" and a "not checked" section copied from the coverage rows, with the reason for each gap. A coverage appendix maps it all to OWASP WSTG and ASVS and marks what no session covers. The full structure is in [Session 09](skills/methodology/09-report.md).

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
| Independence | None; you sign the statement | None | The firm's name on the result |
| Will ever say "secure" | Never | Often | No |

---

## Does it work?

Not yet measured. Ensphere is a proof of concept published for review, and a clean run is not a security guarantee. The claims above describe the design. The evaluation protocol in [`skills/evaluation/`](skills/evaluation/README.md) defines what a result would be: blind runs against targets with known ground truth (OWASP Juice Shop, OWASP crAPI, and a small owned fixture), a frozen report before the answers are opened, and a scorecard for found, missed, and unsupported claims. Until those numbers are published here, treat Ensphere as a method to review, not a result to rely on.

---

## Boundaries

- **It proves only against a copy that cannot be hurt.** Proof, including chains and state changes, happens in a sandbox. Staging receives bounded measurement, and a probe that would change state there needs explicit authorization and cleanup evidence. Production is never sent a request; only its provider configuration is read. There is no data extraction and no load testing anywhere.
- **It needs your source.** Ensphere is for the person who owns the system. Source is always in scope; a live target is optional.
- **Every request is scoped.** Each verify command requires `--in-scope` and refuses any host outside it, including redirect hops. Rate-limit probes require a burst count you approved; there is no default. Probes carry a risk level, and the default ceiling refuses the higher ones.
- **It never says "secure".** The report says what was tested, against which assets and roles, with which controls, and what held. A missing signal is never treated as proof that a surface is absent.
- **The judgment is the model's.** Ensphere holds the method and the measurements steady. The methodology files are kept short enough for a mid-tier model to read alongside your code, and a stronger model finds more.

---

## For agents

`make install-all` copies the skill to `~/.claude/skills/ensphere` and `~/.codex/skills/ensphere`. The entry point is [`skills/SKILL.md`](skills/SKILL.md), which loads the contract, the fundamentals map, and one methodology file per session. The workspace is the protocol between sessions: an orchestrator can run recon, planning, and the report itself and dispatch each check session to a fresh subagent with a short brief, and a harness without subagents runs the same files in one context and resumes from `next-action.md` after a context loss. [`AGENTS.md`](AGENTS.md) is the entry point for agents working on the Ensphere codebase itself.

---

## Contributing

Contributions are welcome under the same license. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for the engineering bar and the checks to run before opening a pull request. The short version: keep judgment out of the CLI, keep business logic out of `cli/cmd/`, and never add a command, flag, or payload whose purpose is exploitation, extraction, credential access, or load generation.

---

## License

[GNU Affero General Public License v3.0](./LICENSE). If you modify Ensphere and offer it over a network, you must offer users the corresponding source.
