# Session 02: Injection

## Objective

Resolve injection candidates across the server-side input flows selected by the
assessment plan. Prove the narrow parser or data-flow claim without extracting
sensitive data or escalating impact.

## Candidate Generation

Read the recon input/sink inventory and the checklists the plan assigned to
this session (for example `prisma-drizzle.md` names the ORM's raw-query sinks;
`go-net-http.md` names `database/sql` and `os/exec` idioms). Checklist items
are the candidates for this stack; the rules below say how to validate them.

Candidates are endpoint × input × parser/sink × identity × claim type, and
include SQL/NoSQL query construction, OS commands, templates, paths/files,
XML/external entities, object deserialization, LDAP/XPath, and response-header
construction only where recon shows relevant surface.

Source candidates require a cited source-to-sink flow, including validation,
encoding, parameterization, allowlists, and reachability in the selected
deployment. Pattern matches alone remain leads.

Live-target candidates require an inventoried input and a named parser hypothesis.
Do not spray generic payload lists across every parameter.

For each candidate state a falsifiable claim, such as: “Input `q` changes the
query predicate rather than remaining data.”

## Controlled Validation

Use the shared baseline/probe/control cycle. Keep the request method, identity,
state, and non-test fields stable. Where no verify family fits the input shape,
send the baseline, probe, and control with `ensphere verify request` and label
each with `--result`.

Choose only mechanism-specific observations:

- **Query injection**: paired true/false expressions, safe syntax-error
  controls, or bounded interleaved timing samples when the engine and noise
  model justify them.
- **Command injection**: a benign timing or fixed canary effect that does not
  execute external callbacks, write files, or return host data.
- **Template injection**: harmless arithmetic or inert render markers; do not
  access objects, files, environment variables, or commands.
- **Path handling**: owned canary files within an authorized fixture. In the
  sandbox a well-known non-sensitive system witness such as `/etc/passwd` or
  `win.ini` is acceptable as the traversal signal; on staging use only owned
  canaries. Never read application secrets, credentials, or user files
  anywhere.
- **XML/entity handling**: a controlled callback or non-sensitive local fixture;
  no file or secret retrieval.
- **Deserialization**: parser/type behavior or a benign controlled side effect;
  no gadget-chain command execution.
- **Header/LDAP/XPath**: paired inputs that distinguish structural control from
  literal treatment without enumerating records.

Variants are allowed only when tied to a named quoting, encoding,
normalization, content-type, or parser hypothesis. Do not perform open-ended
WAF evasion, use automated extraction, enumerate database structure, dump data,
or escalate to command execution for proof.

## Interpretation and Stop Rules

- Repeat/interleave enough observations to distinguish noise, caching, and
  application state; no universal timing delta or fixed trial count applies.
- Treat errors, reflection, size changes, and timing shifts as signals until an
  appropriate control excludes material alternatives.
- Parameterization or consistent literal treatment may support
  `not_supported` for the tested flow; it does not prove all inputs secure.
- Stop when the narrow claim is supported/contradicted, the request limit is
  reached, target behavior becomes unstable, or the next step only increases
  impact.
