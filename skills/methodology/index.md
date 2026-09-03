# Methodology Index

Every session inherits [../shared/contract.md](../shared/contract.md).
Open the checklists the plan assigned to the session alongside the
methodology file.

| Session | File | Primary artifact |
|---------|------|------------------|
| 01 | [Recon](01-recon.md) | Stack profile, surface inventories, `target-profile.yaml`, `hypotheses.md` |
| 01.5 | [Plan](01.5-session-plan.md) | `assessment-plan.yaml` with session decisions and assigned checklists |
| 02 | [Injection](02-injection.md) | Resolved injection claims |
| 03 | [Authentication](03-auth.md) | Resolved identity and session claims |
| 04 | [Authorization](04-authz.md) | Tested subject-object-operation matrix |
| 05 | [XSS](05-xss.md) | Tested render-context matrix |
| 06 | [SSRF](06-ssrf.md) | Tested outbound-fetch matrix |
| 07 | [Cloud and platform](07-cloud.md) | Read-only configuration findings; appendices 07a to 07f |
| 08 | [API](08-api.md) | API-control findings |
| 08.5 | [Abuse and cost](08.5-abuse.md) | Missing limiters, caps, and quotas with fixes |
| 08.7 | [Chains and workflows](08.7-chains.md) | Chains observed end to end in the sandbox, or marked as risk scenarios |
| 09 | [Report](09-report.md) | Fix list, missing controls, checks executed, registry |

Sessions 01, 01.5, and 09 always run. Sessions 02 to 08.7 run according to
the plan. Sessions 01.5 and 09 have runner gates: `ensphere run plan` and
`ensphere run report`.
