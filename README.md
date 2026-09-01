<div align="center">

<img src="./assets/ensphere-banner.png" alt="Ensphere" width="100%">

</div>

# Ensphere

**A security check for the system you own, run by your AI coding agent, that reports facts and shows its work.**

Most small teams ship without a security review. A penetration test costs thousands and happens once a year, if ever, and the problems that actually hurt a small team are ordinary: an OTP endpoint with no rate limit in front of an SMS bill, an upload path with no size cap, a database table with no row policy, a query built by string concatenation. Ensphere is a skill for coding agents plus a small Go CLI. Point the agent at your repository and a disposable copy of your app. It learns your stack, decides what needs checking, runs bounded measurements through the CLI, and writes a report of what is broken, which controls are missing, how to fix each one, and exactly what was and was not checked.

It runs as a CLI, and it ships as a skill so an AI agent can run the assessment for you.

---

## The problem: the options are expensive, noisy, or unverifiable

- **A pentest is expensive and rare.** It is the right tool, and most teams cannot afford it before launch. By the time one happens, the missing rate limiter has been in production for a year.
- **A scanner is cheap and noisy.** It pattern-matches responses and declares things vulnerable. You spend the afternoon triaging false positives, and it never reads your code, so it cannot tell you that the limiter exists but is keyed on the wrong thing.
- **Asking an AI to "check my security" gives you an essay.** With no method and no measurements, a model produces a confident list that skips whole categories and ends with "looks good". Nothing in it can be verified after the fact.

## The idea: the tool produces facts, the agent produces judgments

Ensphere splits the work along one line and holds it there.

- **The CLI is deterministic.** It sends scoped HTTP requests, measures timing, hashes responses, captures headers, counts rows, reads provider configuration through the provider's own CLI, validates scope, redacts secrets, and appends every observation to a hash-chained evidence ledger. It never says "vulnerable" or "safe". A contract test rejects any output field that would carry a verdict.
- **The agent does the reasoning.** It reads your source and the raw numbers side by side, follows a written methodology, and resolves each claim with a baseline, a probe, and a control that rules out the obvious alternative explanation. Every finding cites an evidence ID that anyone can verify against the ledger.
- **The methodology is a map, not a script.** A short file lists the roles every system has, whatever it is built on, and the invariant each must satisfy: an entry point has a deliberate authentication state, a query only ever receives user data as a parameter, a billed operation runs behind a limiter keyed on the caller. Checklists for common stacks say where each role lives in that framework and what the idiomatic fix is. A stack with no checklist is assessed from the map.

The split is the point. Because none of the reasoning lives in the tool, a better model produces a better assessment with no change to Ensphere. And because every claim points at a measurement, the report can be checked by someone who was not in the room.

---

## Watch it work

Build once, install the skill, then initialise a workspace inside the project you want to check:

```bash
ensphere run init \
  --target "http://localhost:3000" \
  --in-scope localhost
```

Now open your agent in that directory and say `ensphere`. From there the agent runs through five phases in one go. It pauses only for things only you can give: the go-ahead to start the sandbox, a login to a provider, a decision about staging. Everything else it records and carries on.

1. **Recon.** It reads the repository, stands up the sandbox with you, seeds it with synthetic tenants, users, and objects, and writes a stack profile: languages, frameworks, data layers, auth provider, hosting, storage, and every service that bills you per call.
2. **Plan.** The stack profile picks the checklists. The agent decides which sessions apply and lists what it still needs from you: a `wrangler login`, an approved burst count for staging, a missing container runtime.
3. **Check.** Injection, authentication, authorization and workflow state, cross-site scripting, server-side request forgery, cloud and platform configuration, API controls, and abuse and cost controls. Each check is baseline, probe, control, and each observation lands in the ledger.
4. **Prove.** In the sandbox, it joins what it found into multi-step chains and runs each one end to end, so a finding that would matter is demonstrated rather than argued.
5. **Report.** A prioritised fix list, a table of missing controls per service, detailed findings with safe reproduction steps, a "checks executed" section that says exactly what was tested, a "not checked" section that says what was not and why, and a one-page statement you can hand to someone doing due diligence.

You can also drive the CLI by hand. Measure whether an endpoint throttles a burst you have approved:

```bash
ensphere verify ratelimit --url "https://staging.example.com/api/otp" \
  --method POST --burst-count 10 --window-sec 10 --in-scope staging.example.com
```

It records ten status codes, ten timings, and any rate-limit headers. It does not say "rate limit missing". You, or the agent, read the numbers.

Find the places in your source where user input might reach a query, a shell, or an outbound fetch:

```bash
ensphere scan ./src --category sqli,ssrf,file_upload
```

Every match is a lead for review, not a finding. Check that nobody has edited an evidence file after the fact:

```bash
ensphere evidence verify --file ./evidence.jsonl
```

The full command surface, with every flag, is in [`docs/cli-reference.md`](docs/cli-reference.md).

---

## Ensphere vs. the alternatives

| | Ensphere | Typical scanner | Manual pentest |
| --- | --- | --- | --- |
| Reads your source code | Yes, alongside the live target | No | Sometimes |
| Who decides what a result means | The agent, with a written method | The tool, by threshold | The tester |
| Evidence you can re-verify | Hash-chained ledger, cited per finding | A severity label | A PDF |
| Finds missing controls, not just bugs | Yes, per billed service and storage surface | Rarely | Yes |
| Will ever say "secure" | Never | Often | No |
| Cost and cadence | Agent tokens, whenever you like | Subscription, continuous | Thousands, yearly |
| Proves a multi-step chain end to end | Yes, in a sandbox copy of your app | No | Yes |

---

## What you get back

An `ensphere-pentest/` directory in your project with one folder per session. Each holds a plan, an evidence ledger, transcripts, and a report. The final report reads in this order:

1. **Summary.** What the system is, what was assessed, the three to five things to fix first, and the material coverage limits.
2. **Fix list.** Every confirmed and likely finding by priority, one paragraph each: what, where, why it matters, the fix, how to verify the fix. Missing controls and vulnerabilities are interleaved.
3. **Missing controls by service.** A table of every service that bills you and every storage surface, with the state of each control: limiter, key, size cap, quota, budget alert.
4. **Detailed findings.** Observed facts, baseline, probe, control, root cause, safe reproduction steps, citations, remediation.
5. **Checks executed.** Every check that ran, with the endpoint, identity, and evidence IDs, and the defenses that held under the exact conditions tested. This is what you can show a reader. It is narrow by construction.
6. **Not checked.** Everything that was skipped or blocked, the missing input, and its effect on the conclusions.
7. **Scope and method.** Target, environment, dates, checklists loaded, approved request limits, tool versions.
8. **Coverage appendix.** Every OWASP WSTG category and ASVS chapter, each marked with the evidence for the checks that ran, not tested with the reason, or not covered. The gaps are written down, not implied.

Alongside the report is a one-page **Statement of Assessment**: system, dates, environment, the model and Ensphere versions that did the work, checks executed and not checked, unresolved findings by severity, and the ledger's final hash. It says in plain words that it is a self-assessment by the system owner and not an independent audit. It is the document to attach to a security questionnaire.

The report is written for the developer who has to act on it. It is also the document to hand to a pentester when you can afford one, so their hours go to the hard problems instead of the missing rate limiter.

---

## Getting started

```bash
git clone https://github.com/srank-org/ensphere.git
cd ensphere
make build            # builds bin/ensphere
make install-all      # installs the binary to /usr/local/bin and the skill to ~/.claude and ~/.codex
```

You'll need **Go 1.26+** to build, and an **agent surface that can load a skill**: Claude Code, Codex, or similar. For platform configuration checks the agent uses the provider's own CLI, so have `aws`, `gcloud`, `az`, `wrangler`, or `supabase` installed and logged in for the platforms you run on. The agent tells you which one it needs and marks the check blocked until you sign in.

Then, in the project you want to check:

```bash
ensphere run init --target "http://localhost:3000" --in-scope localhost
```

Point `--target` at a **sandbox**: a local instance of your application with synthetic data. The agent will offer to stand one up from your compose file or dev script, check that it is isolated from anything real, and seed the accounts, tenants, and objects the checks need. That is where findings get proven. Add a staging URL when you have one, for the checks a sandbox cannot show: the edge in front of your origin, deployed configuration, the shared rate-limit store. Production is never a target. If you have no way to run the app at all, omit `--target`; the assessment runs from source alone, reports every missing control it can see, and marks every live measurement as not tested.

---

## For AI agents

Ensphere ships as a skill. `make install-all` copies it to `~/.claude/skills/ensphere` and `~/.codex/skills/ensphere`; the entry point is [`skills/SKILL.md`](skills/SKILL.md), which loads the contract, the fundamentals map, and one methodology file per session. The runner writes a `next-action.md` handoff so a fresh agent context can resume without losing its place. [`AGENTS.md`](AGENTS.md) is the entry point for agents working on the Ensphere codebase itself.

---

## What it is, and isn't

- **It proves only against a copy that cannot be hurt.** Proof, including multi-step chains and state changes, happens in a sandbox: a local instance of your app with synthetic data, whose third-party calls go to test keys or stubs. On staging it measures with bounded probes, and a probe that would change state needs explicit authorization and cleanup evidence. Production is never probed. There is no data extraction and no load testing anywhere.
- **It needs your source.** Ensphere is for the person who owns the system. Source is always in scope. A live target is optional and strongly recommended.
- **It is not a pentesting firm.** It checks whether every role in your system satisfies its known invariant, then joins what it found into chains and proves them in the sandbox. What it cannot give you is independence: a firm puts its name on the result, and Ensphere's statement is signed by you. What it gives you instead is a report a reader can verify line by line, which is more than most letters offer. Use it before and between pentests, and hand its report to the pentester so their hours go to the hard problems.
- **It never says "secure".** The report says what was tested, against which assets and roles, with which controls, and what held. A missing signal is never treated as proof that a surface is absent.
- **Every request is scoped.** Each verify command requires `--in-scope` and refuses any host outside it, including redirect hops. Rate-limit probes require a burst count you approved; there is no default. Probes carry a risk level, and the default ceiling refuses the higher ones.
- **The judgment is the model's.** Ensphere holds the method and the measurements steady. The quality of the reasoning is the quality of the agent running it, which is why the methodology files are kept short enough for a mid-tier model to read alongside your code.
- **It is a proof of concept.** It is published for review and research and is not a supported product. A clean run is not a security guarantee.

---

## Contributing

Contributions are welcome under the same license. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for the engineering bar and the checks to run before opening a pull request. The short version: keep judgment out of the CLI, keep business logic out of `cli/cmd/`, and never add a command, flag, or payload whose purpose is exploitation, extraction, credential access, or load generation.

---

## License

[GNU Affero General Public License v3.0](./LICENSE). If you modify Ensphere and offer it over a network, you must offer users the corresponding source.
