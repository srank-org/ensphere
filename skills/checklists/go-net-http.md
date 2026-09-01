# Go net/http Backend Checklist

Load this checklist when recon finds a `go.mod` and HTTP handlers built on
`net/http`, `chi`, `gin`, `echo`, or `fiber`, including services deployed on
Cloud Run, Fly, or Kubernetes. It covers handler wiring, query construction,
request binding, server hardening, resource limits, and platform exposure. Pair
it with `abuse-and-cost.md` for billing-exposed endpoints and the relevant cloud
appendix for the deployment platform.

## Handler wiring and authentication

- [ ] **Handlers registered outside the auth middleware chain** — routes added directly on the mux, in a `chi.Group` without `Use`, or on a gin/echo group created before the auth middleware are reachable without a token.
  - Look for: every `HandleFunc` / `r.Get` / `g.POST` and the group or router it is attached to; `r.With(...)` used inconsistently; `router.Group("")` created before `Use(auth)`.
  - Measure: `ensphere verify auth --url <protected-endpoint> --token <valid-token> --technique no_token --in-scope <pattern>` for each route that must be authenticated; `ensphere verify authz --url <admin-endpoint> --low-token <user-token> --high-token <admin-token> --in-scope <pattern>` for role-gated routes.
  - Fix: apply auth middleware on the parent router before any route registration; keep public routes in one explicitly named group.

- [ ] **Debug and profiling endpoints exposed** — importing `net/http/pprof` registers `/debug/pprof/*` on `DefaultServeMux`; `expvar`, gin's debug mode, and health endpoints that dump config are similar.
  - Look for: `_ "net/http/pprof"`, `expvar`, `gin.SetMode`, `/debug` routes, handlers that return environment or config.
  - Measure: `manual: request /debug/pprof/ and /debug/vars once with no credentials and record the status.`
  - Fix: serve pprof on a separate localhost listener or behind auth; set `GIN_MODE=release`.

## Query construction

- [ ] **String-built SQL** — `fmt.Sprintf("... WHERE id = %s", id)` or `+` concatenation into `db.Query`, `db.Exec`, `sqlx.Select`, or gorm `db.Raw` / `db.Exec` / `db.Where("name = " + x)`.
  - Look for: `Sprintf` whose result is passed to a query function; `Raw(` / `Exec(` / `Where(` with a non-literal first argument; `Order(` with user input.
  - Measure: `ensphere scan ./ --category sqli`, then `ensphere verify sqli --url "<endpoint>?<param>=1" --param <param> --db postgres --technique blind_boolean --in-scope <pattern>` (use `--string-boundary numeric` for numeric IDs).
  - Fix: placeholders (`$1`, `?`) with arguments; allowlisted column names for dynamic `ORDER BY`.

- [ ] **Command execution with request input** — `exec.Command("sh", "-c", ...)` or arguments assembled from parameters.
  - Look for: `os/exec` imports and any argument that traces to a request value.
  - Measure: `ensphere verify cmdi --url "<endpoint>?<param>=x" --param <param> --in-scope <pattern>` (benign timing canary only).
  - Fix: pass arguments as separate `exec.Command` args, allowlist values, avoid shells.

## Request binding and mass assignment

- [ ] **Decoding into the persistence struct** — `json.NewDecoder(r.Body).Decode(&user)` or gin `ShouldBindJSON(&user)` where `user` has `Role`, `IsAdmin`, `OwnerID`, or `Balance` fields lets clients set them.
  - Look for: decode targets that are also database models; absence of separate request DTOs; `DisallowUnknownFields` missing.
  - Measure: `ensphere verify massassignment --url <endpoint> --method PATCH --body '<owned object json>' --watch-fields role,owner_id --token <user-token> --in-scope <pattern>` (benign field first, restore afterward).
  - Fix: decode into a request struct with only writable fields; call `dec.DisallowUnknownFields()`; copy explicitly.

- [ ] **Path traversal through `filepath.Join`** — `filepath.Join(base, name)` cleans `..` but still resolves outside `base` when `name` is absolute or the result is not prefix-checked.
  - Look for: file serving or download handlers using a request value in a path; `http.ServeFile` with joined paths; `http.Dir` roots.
  - Measure: `ensphere verify lfi --url "<endpoint>?<param>=x" --param <param> --in-scope <pattern>`.
  - Fix: `filepath.Clean`, reject absolute paths, verify `strings.HasPrefix(resolved, base+string(os.PathSeparator))`, or use `os.Root` / `fs.Sub`.

## Outbound requests

- [ ] **Server-side fetch of user-supplied URLs** — webhook testers, importers, and image proxies using `http.Get(url)` reach metadata services and internal hosts; the default client follows redirects to them too.
  - Look for: `http.Get`, `client.Do` with a URL derived from input; `CheckRedirect` unset; no IP/host allowlist.
  - Measure: `ensphere verify ssrf --url "<endpoint>?<param>=x" --param <param> --in-scope <pattern>` (add `--callback-url` for a controlled listener when the response is blind).
  - Fix: resolve and validate the host before dialing (block loopback, link-local, RFC1918, metadata), set `CheckRedirect` to re-validate, and use a dedicated client with timeouts.

- [ ] **No timeouts on outbound calls** — `http.DefaultClient` has no timeout; a slow upstream ties up goroutines and, on Cloud Run, billed instance time.
  - Look for: `http.DefaultClient`, `&http.Client{}` without `Timeout`, database and RPC calls without `context.WithTimeout`.
  - Measure: `manual: from source, list each outbound client and record its timeout value or absence.`
  - Fix: per-client `Timeout` and per-request contexts derived from `r.Context()`.

## Server and resource limits

- [ ] **`http.Server` without read/write timeouts** — `http.ListenAndServe(addr, h)` sets no `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, or `IdleTimeout`, so slow clients hold connections indefinitely.
  - Look for: `ListenAndServe(` called directly; `&http.Server{...}` missing the timeout fields.
  - Measure: `manual: read the server construction and record each timeout field; no live slow-client test.`
  - Fix: `ReadHeaderTimeout: 5s`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes`.

- [ ] **Unbounded request bodies** — JSON decoders and `r.ParseMultipartForm` read as much as the client sends unless `http.MaxBytesReader` wraps `r.Body`; `ParseMultipartForm(n)` only bounds memory, not total size.
  - Look for: `MaxBytesReader` usage per route; upload handlers; `ParseMultipartForm(` and `FormFile(` without a body cap; file count limits.
  - Measure (planned): `ensphere verify limits --technique upload_size --url <upload-endpoint> --sizes 1048576,10485760 --in-scope <pattern>` with operator-approved sizes; `ensphere verify fileupload --url <upload-endpoint> --filename test.svg --mime-type image/svg+xml --technique content_type_mismatch --in-scope <pattern>` for type validation.
  - Fix: `r.Body = http.MaxBytesReader(w, r.Body, limit)` first in the handler; for large objects issue presigned URLs constrained by content length and type and let clients upload directly to storage.

- [ ] **No rate limiting, or per-instance limiting only** — an in-process limiter (`golang.org/x/time/rate` map, `ulule/limiter` memory store) resets per instance, so on Cloud Run or any autoscaled service the effective limit multiplies with instances and disappears on cold start.
  - Look for: limiter middleware and its store; `rate.NewLimiter` keyed by IP or user; absence of any limiter on login, signup, OTP, upload, search, export, or routes calling paid APIs.
  - Measure: `ensphere verify ratelimit --url <endpoint> --method POST --body '<benign body>' --burst-count <operator-approved N> --window-sec 10 --in-scope <pattern>`; record the first 429 position, if any.
  - Fix: a shared store (Redis / Memorystore / Upstash) for the limiter, or an edge rule (Cloud Armor, Cloudflare) in front, plus per-user quotas for expensive operations. See `abuse-and-cost.md`.

- [ ] **Goroutines doing unbounded work per request** — `go process(item)` for every request element, or worker fan-out with no semaphore, lets one request consume the instance.
  - Look for: `go func` inside handlers; `errgroup` without `SetLimit`; loops over request arrays without a length cap.
  - Measure: `manual: from source, record each fan-out site and whether input length and concurrency are capped.`
  - Fix: cap input sizes in validation; `errgroup.SetLimit(n)` or a buffered semaphore; propagate `r.Context()` for cancellation.

## Cross-origin and platform exposure

- [ ] **CORS wildcard with credentials** — `rs/cors` with `AllowedOrigins: []string{"*"}` plus `AllowCredentials: true`, or an `AllowOriginFunc` that returns true, exposes authenticated responses cross-site.
  - Look for: `cors.New(cors.Options{...})`, gin `cors.Config`, echo `CORSConfig`.
  - Measure: `ensphere verify cors --url <endpoint> --in-scope <pattern>`.
  - Fix: explicit origin allowlist; never wildcard with credentials.

- [ ] **Internal Cloud Run services deployed with unauthenticated invocation** — `--allow-unauthenticated` on a service that should only be called by another service or a scheduler makes it a public, billed endpoint.
  - Look for: deployment scripts, `gcloud run deploy` flags, Terraform `google_cloud_run_service_iam_member` with `allUsers`, and whether callers use an ID token.
  - Measure: `manual: request the service root once without credentials and record the status (403 expected for internal services).`
  - Fix: remove `allUsers` invoker binding, require an ID token from the calling service account, set ingress to internal where possible.

- [ ] **Secrets in structured logs** — logging the request struct, headers, or `DATABASE_URL` at startup writes tokens into Cloud Logging.
  - Look for: `log.Printf("%+v", req)`, `slog.Any("headers", r.Header)`, logging of `Authorization`, and config dumps.
  - Measure: `manual: review logging call sites that receive request or config objects; record file:line, not values.`
  - Fix: log allowlisted fields only; redact `Authorization` and cookies in middleware.
