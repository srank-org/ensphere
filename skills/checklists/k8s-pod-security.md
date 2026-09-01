# Kubernetes Pod Security Checklist

Load this checklist when recon records Kubernetes manifests, Helm charts, Kustomize overlays, or a cluster in scope. It covers workload configuration that decides how far a compromised container can reach and how much of the node it can consume. Cluster identity and cloud network exposure belong to the cloud session appendices; shared abuse patterns are in `abuse-and-cost.md`.

## Prerequisites

Static review needs only the manifests: `ensphere scan ./k8s --category iac_kubernetes`. Live review uses read-only `kubectl get` against a non-production context. If `kubectl config current-context` is empty or points at production, tell the operator which context to provide and record live items as `blocked` until then. Never `kubectl exec`, `apply`, or `delete`.

## Privilege

- [ ] **Privileged container** — `securityContext.privileged: true` gives full host device and namespace access.
  - Look for: `privileged: true` in any container or init container; Helm values that enable it.
  - Measure: `ensphere scan ./k8s --category iac_kubernetes`; `manual: kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'`.
  - Fix: remove; use specific capabilities or a device plugin.

- [ ] **Host namespaces shared** — `hostNetwork`, `hostPID`, or `hostIPC` exposes host processes and interfaces.
  - Look for: those keys set true outside CNI or monitoring DaemonSets.
  - Measure: `manual: kubectl get pods -A -o json | jq '.items[] | {name:.metadata.name, ns:.metadata.namespace, hn:.spec.hostNetwork, hp:.spec.hostPID, hi:.spec.hostIPC}'`.
  - Fix: remove; use Services and sidecars.

- [ ] **Running as root or with added capabilities** — missing `runAsNonRoot: true`, `runAsUser: 0`, or `capabilities.add` with `SYS_ADMIN`, `NET_RAW`, `SYS_PTRACE`.
  - Look for: `securityContext` at pod and container level; base images that default to root.
  - Measure: `ensphere scan ./k8s --category iac_kubernetes`; `manual: kubectl get pods -A -o json | jq '.items[].spec.containers[].securityContext'`.
  - Fix: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`.

- [ ] **Writable root filesystem and unconfined seccomp** — persistence and syscall reach for a compromised process.
  - Look for: `readOnlyRootFilesystem: true`; `seccompProfile.type: RuntimeDefault`.
  - Measure: `manual: kubectl get pods -A -o json | jq '.items[].spec.containers[].securityContext | {readOnlyRootFilesystem, seccompProfile}'`.
  - Fix: read-only root with `emptyDir` for writable paths; `RuntimeDefault` seccomp.

## Identity and secrets

- [ ] **Service account token auto-mounted** — pods that never call the API still receive a credential.
  - Look for: `automountServiceAccountToken: false` on the pod or ServiceAccount; RBAC bound to the default account.
  - Measure: `manual: kubectl get pods -A -o json | jq '.items[] | select(.spec.automountServiceAccountToken!=false) | .metadata.name'`; `manual: kubectl get rolebindings,clusterrolebindings -A -o wide | grep default`.
  - Fix: disable auto-mount; dedicated ServiceAccounts with least-privilege roles.

- [ ] **Secrets in environment or ConfigMaps** — secrets as plain env vars leak through crash dumps and `kubectl describe`.
  - Look for: `env.value` containing tokens; ConfigMaps with credentials; Secrets not encrypted at rest.
  - Measure: `manual: kubectl get configmaps -A -o yaml | grep -iE 'password|secret|token|key' with values redacted`.
  - Fix: Secrets mounted as files, external secret operator, encryption at rest.

## Network

- [ ] **No default-deny NetworkPolicy** — every pod can reach every other pod and the metadata service.
  - Look for: a default-deny ingress and egress policy per namespace; egress rules blocking `169.254.169.254`.
  - Measure: `manual: kubectl get networkpolicies -A`; cloud layer with `ensphere cloud network --provider <aws|gcp|azure> --in-scope <scope>`.
  - Fix: default deny per namespace, explicit allows, metadata endpoint blocked.

- [ ] **Services exposed with type LoadBalancer or NodePort unintentionally** — internal services reachable from the internet.
  - Look for: `type: LoadBalancer` or `NodePort` on non-ingress services; ingress annotations for internal load balancers.
  - Measure: `manual: kubectl get svc -A | grep -E 'LoadBalancer|NodePort'`.
  - Fix: ClusterIP plus an ingress controller; internal annotations.

## Resource abuse

- [ ] **Missing resource requests and limits** — one pod can starve the node, and an abused endpoint scales cost without bound.
  - Look for: `resources.requests` and `resources.limits` on every container; namespace `LimitRange` and `ResourceQuota`.
  - Measure: `manual: kubectl get pods -A -o json | jq '.items[].spec.containers[] | select(.resources.limits==null) | .name'`; `manual: kubectl get limitrange,resourcequota -A`.
  - Fix: limits on every container; `LimitRange` defaults; `ResourceQuota` per namespace.

- [ ] **Autoscaler without a ceiling** — HPA or cluster autoscaler with high `maxReplicas` or no node cap turns request floods into bills.
  - Look for: `maxReplicas` in HPA manifests; cluster autoscaler max nodes; KEDA triggers on public queues.
  - Measure: `manual: kubectl get hpa -A -o json | jq '.items[] | {name:.metadata.name, max:.spec.maxReplicas}'`.
  - Fix: ceilings tied to budget; rate limiting at the ingress so scaling responds to legitimate load.

## Admission

- [ ] **Pod Security Admission not enforced** — namespaces without `pod-security.kubernetes.io/enforce` accept any of the above.
  - Look for: namespace labels; policy engines such as Kyverno or Gatekeeper.
  - Measure: `manual: kubectl get ns -o json | jq '.items[] | {name:.metadata.name, labels:.metadata.labels}'`.
  - Fix: `restricted` enforce label on application namespaces; `baseline` as the floor everywhere.
