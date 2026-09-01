# FastAPI Checklist

Load this checklist when recon records `fastapi` in `requirements.txt` or
`pyproject.toml`, `FastAPI()` or `APIRouter()` in source, or a `uvicorn`
entry point. Shared endpoint classes for rate limiting live in
[abuse-and-cost.md](abuse-and-cost.md).

## Data layer

- [ ] **Raw SQL through SQLAlchemy** — `text()` or `execute()` built with f-strings bypasses parameterization.
  - Look for: `text(f"`, `execute(f"`, `.format(` inside query strings in `**/*.py`.
  - Measure: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./ --category sqli`.
  - Fix: bind parameters with `text("... :name")` and a dict.

- [ ] **Unbounded list endpoints** — `limit` query parameter without an upper bound, or none at all.
  - Look for: `limit: int = Query(100)` without `le=`; `.all()` on user-facing list routes.
  - Measure: `ensphere verify limits --technique pagination --param limit --values 1,100,10000 --in-scope <pattern> (planned)`; otherwise `manual: request with a large limit and record returned count and body bytes`.
  - Fix: `Query(100, le=200)`; cursor pagination.

## Authentication and authorization

- [ ] **Route without an auth dependency** — path operations that omit `Depends(get_current_user)` are public.
  - Look for: routers included without `dependencies=[Depends(...)]`; individual routes missing the dependency.
  - Measure: `ensphere verify auth --technique no_token --url <endpoint> --token <valid-jwt> --in-scope <pattern>`.
  - Fix: attach the dependency at `APIRouter(dependencies=...)` level; deny by default.

- [ ] **JWT decode without `algorithms`** — `jose.jwt.decode` / `PyJWT` accepting `none` or a symmetric secret in an asymmetric flow.
  - Look for: `jwt.decode(token, key)` with no `algorithms=[...]`; `verify_signature=False`.
  - Measure: `ensphere verify jwt --technique alg_none --url <endpoint> --token <valid-jwt> --in-scope <pattern>`.
  - Fix: always pass `algorithms`; verify `aud` and `iss`.

- [ ] **Object access without ownership filter** — `session.get(Model, id)` on user-owned rows with no tenant or owner condition.
  - Look for: `db.get(`, `select(Model).where(Model.id == id)` with no user filter.
  - Measure: `ensphere verify idor --url <endpoint>/<other-user-id> --id <other-user-id> --token <user-token> --in-scope <pattern>`.
  - Fix: filter by the authenticated principal in the query.

- [ ] **Pydantic extra fields allowed** — `extra="allow"` or ORM writes from `model.dict()` let a client set `is_admin`, `role`, `owner_id`.
  - Look for: `ConfigDict(extra="allow")`, `Model(**payload.dict())` where the schema includes privileged fields.
  - Measure: `ensphere verify massassignment --url <endpoint> --method PATCH --body '{"is_admin":true}' --watch-fields is_admin --token <user-token> --in-scope <pattern>`.
  - Fix: separate input and output schemas; `extra="forbid"`.

## Configuration

- [ ] **Docs exposed in production** — `/docs`, `/redoc`, `/openapi.json` reveal every route and schema.
  - Look for: `FastAPI(docs_url=`, `openapi_url=` values by environment.
  - Measure: `ensphere verify auth --technique no_token --url <target>/openapi.json --token <valid-jwt> --in-scope <pattern>`.
  - Fix: disable or protect docs outside development. Treat exposure as informational unless the schema reveals unprotected routes.

- [ ] **Permissive `CORSMiddleware`** — `allow_origins=["*"]` with `allow_credentials=True`.
  - Look for: `add_middleware(CORSMiddleware, ...)` arguments.
  - Measure: `ensphere verify cors --url <endpoint> --in-scope <pattern>`.
  - Fix: explicit origins; no credentials with wildcards.

## Input handling

- [ ] **Path or query value used in file access** — `Path(...)` parameters joined into filesystem paths.
  - Look for: `open(f"{base}/{name}"`, `FileResponse(path)` built from request data.
  - Measure: `ensphere verify lfi --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./ --category lfi`.
  - Fix: resolve and verify the path stays under the base directory.

- [ ] **Background task with shell or file side effects** — `BackgroundTasks.add_task` or Celery tasks receiving raw request strings that reach `subprocess` or paths.
  - Look for: `subprocess.run(`, `os.system(` with request-derived arguments.
  - Measure: `ensphere verify cmdi --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./ --category cmdi`.
  - Fix: argument lists without a shell; strict validation.

- [ ] **`UploadFile` without validation** — no size cap, content-type check, or filename sanitization.
  - Look for: `UploadFile` parameters; `file.filename` used in a path; no size check on `file.read()`.
  - Measure: `ensphere verify fileupload --technique content_type_mismatch --url <upload-endpoint> --filename test.html --field file --in-scope <pattern>`.
  - Fix: stream with a byte cap; validate magic bytes; random server-side names.

## Rate limiting and abuse

- [ ] **No limiter on auth endpoints** — FastAPI ships no limiter; login, signup, reset, and OTP verify accept unlimited attempts.
  - Look for: `slowapi` (`Limiter`, `@limiter.limit`), `fastapi-limiter`, or a gateway limiter in front of the app.
  - Measure: `ensphere verify ratelimit --url <login-endpoint> --method POST --body '<invalid-credentials-json>' --burst-count <approved> --window-sec 10 --in-scope <pattern>`.
  - Fix: `slowapi` with a Redis storage URI; key by IP and by account.

- [ ] **No limiter on expensive or billed endpoints** — uploads, search, export, email/SMS send, LLM or third-party API calls without per-user caps.
  - Look for: routes invoking `smtplib`, `boto3`, `openai`, `httpx` to paid APIs, image or PDF generation.
  - Measure: `ensphere verify ratelimit` with an approved burst on one endpoint per class; record `429` onset or its absence.
  - Fix: per-route `@limiter.limit`; queue heavy work with per-user concurrency.

- [ ] **Limiter counts per worker** — `slowapi` default in-memory storage is per process; `uvicorn --workers N` or replicas multiply the limit.
  - Look for: `Limiter(storage_uri=` absent while the deployment runs multiple workers or replicas.
  - Measure: `manual: source and deployment review`.
  - Fix: `storage_uri="redis://..."`.

- [ ] **Body size limits** — no request size cap in the ASGI server or reverse proxy.
  - Look for: `client_max_body_size` (nginx), `--limit-max-requests` is not a size limit; a middleware checking `Content-Length`.
  - Measure: `ensphere verify limits --technique upload_size --sizes 1048576,10485760 --field file (planned)`; otherwise `manual: post one approved oversized body and record the status`.
  - Fix: enforce a size cap at the proxy and reject early in a middleware.
