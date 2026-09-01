# Sandbox

The sandbox is the environment tier where proof happens (contract,
Environments): a local, disposable instance of the source under assessment,
seeded with synthetic data, isolated from anything real. Session 01 stands it
up; every later session relies on the record this file produces. Session 08.7
runs only here.

## Stand it up

From Step 1 you know how the application runs: a compose file, a dev script,
`supabase start`, `wrangler dev`, a migration and seed command. Write the
exact commands you intend to run and ask the operator before running any of
them. If the runtime they need is missing (no container engine, no local
database), that is an assessment-level blocker under the contract: stop and
ask; do not install it.

Once it runs, complete the isolation check and record it in
`01-recon/sandbox.md` with the start command, the reset command, and evidence
for each line:

- the database URL, cache, and queue point at local or containerised
  instances, and no connection string in the running environment matches a
  production or staging host;
- every third-party key in the running environment is a test or sandbox key
  (payment, AI, mail, SMS, maps, analytics) or the integration is stubbed;
- outbound mail and SMS go to a local catcher or a stub;
- object storage is a local emulator or a bucket created for this sandbox;
- webhooks and callbacks resolve to localhost;
- the instance listens on localhost only.

If any line fails and cannot be fixed, the environment is not a sandbox.
Record it as `staging` or stop.

Seed synthetic fixtures. Never copy production data; an anonymised snapshot
is allowed only when the operator names it and the isolation check still
passes. The minimum set, so later sessions never have to ask for it:

- two tenants;
- in each tenant an ordinary user and an administrator, each with an API key
  where the product has them;
- for every workflow in the inventory, one owned object per user in each
  material state (draft, submitted, paid, refunded, and so on);
- one object per storage surface owned by each user;
- a way to trigger each billed operation against its stub.

Record the identities as placeholders (`[TENANT_A_USER]`) in `sandbox.md`,
and set `environment: sandbox` in the target profile.

## Reset

Record one command that returns the sandbox to its seeded state (drop and
re-migrate, restore a snapshot, `docker compose down -v && up`). Session 08.7
resets between chains; any session resets after a state-changing probe it
cannot restore by hand.

## Record

`01-recon/sandbox.md` holds: start, seed, and reset commands; the isolation
check with evidence per line; the fixture inventory as placeholders; the date
and the operator's confirmation. Cite it from every session that changes
state.
