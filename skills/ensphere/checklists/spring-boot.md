# Spring Boot Checklist

Load this checklist when recon records `spring-boot-starter-*` in `pom.xml`
or `build.gradle`, an `@SpringBootApplication` class, or
`application.yml`/`application.properties`. Shared endpoint classes for rate
limiting live in [abuse-and-cost.md](abuse-and-cost.md).

## Data layer

- [ ] **String-built JPQL or native queries** — `createQuery("... " + input)`, `@Query` with SpEL over request values, `JdbcTemplate` with concatenation.
  - Look for: `createQuery(` / `createNativeQuery(` with `+`; `jdbcTemplate.query(String.format(`.
  - Measure: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`; `ensphere scan ./src --category sqli`.
  - Fix: named parameters; `Specification` or Criteria API for dynamic filters.

- [ ] **Unbounded list endpoints** — `findAll()` returned directly, or `Pageable` accepted with no `max-page-size`.
  - Look for: `repository.findAll()` in controllers; `spring.data.web.pageable.max-page-size` unset.
  - Measure: `ensphere verify limits --technique pagination --param size --values 1,100,10000 --in-scope <pattern> (planned)`; otherwise `manual: request with a large size and record returned count and body bytes`.
  - Fix: `Pageable` everywhere with `max-page-size` configured.

## Actuator and consoles

- [ ] **Actuator endpoints exposed** — `/actuator/env`, `/actuator/heapdump`, `/actuator/configprops` reachable without authentication.
  - Look for: `management.endpoints.web.exposure.include=*`; actuator paths in `SecurityFilterChain` `permitAll()`.
  - Measure: `ensphere verify auth --technique no_token --url <target>/actuator/env --token <valid-jwt> --in-scope <pattern>`.
  - Fix: expose only `health`; require an admin role; separate management port.

- [ ] **H2 console enabled** — `/h2-console` gives SQL and file access.
  - Look for: `spring.h2.console.enabled=true` in non-dev profiles.
  - Measure: `ensphere verify auth --technique no_token --url <target>/h2-console --token <valid-jwt> --in-scope <pattern>`.
  - Fix: disable outside local development.

## Security filter chain

- [ ] **`permitAll()` too broad or matcher mismatch** — trailing slash, case, or `/**` patterns exposing protected paths.
  - Look for: `requestMatchers(` lists in `SecurityConfig`; `anyRequest().permitAll()`.
  - Measure: `ensphere verify auth --technique no_token --url <endpoint> --token <valid-jwt> --in-scope <pattern>`.
  - Fix: `anyRequest().authenticated()` last; explicit public paths.

- [ ] **CSRF disabled on session-authenticated apps** — `csrf().disable()` without a stateless-token justification.
  - Look for: `.csrf(csrf -> csrf.disable())`; session cookie still issued.
  - Measure: `ensphere verify csrf --url <endpoint> --method POST --in-scope <pattern>`.
  - Fix: keep CSRF for cookie sessions; disable only for pure bearer-token APIs.

- [ ] **Missing security headers** — HSTS, `X-Content-Type-Options`, `frame-ancestors`, CSP absent.
  - Look for: `.headers(` configuration.
  - Measure: `ensphere verify clickjacking --url <endpoint> --in-scope <pattern>`; `manual: record response headers`.
  - Fix: Spring Security defaults plus a CSP.

- [ ] **Permissive CORS** — `allowedOrigins("*")` or `@CrossOrigin` with `allowCredentials = "true"`.
  - Look for: `CorsConfiguration`, `@CrossOrigin(origins = "*")`.
  - Measure: `ensphere verify cors --url <endpoint> --in-scope <pattern>`.
  - Fix: explicit origins; `allowedOriginPatterns` only with care.

## Binding and serialization

- [ ] **`@ModelAttribute` mass assignment** — every request parameter binds to the target object.
  - Look for: `@ModelAttribute` on entities; `@InitBinder` with `setDisallowedFields` absent.
  - Measure: `ensphere verify massassignment --url <endpoint> --method POST --body 'role=ADMIN' --watch-fields role --token <user-token> --in-scope <pattern>`.
  - Fix: dedicated DTOs; `setAllowedFields`.

- [ ] **Jackson polymorphic typing** — `enableDefaultTyping()`, `activateDefaultTyping`, or `@JsonTypeInfo(use = Id.CLASS)` on request models.
  - Look for: those calls and annotations.
  - Measure: `manual: source review; confirm no request model uses class-name typing`.
  - Fix: explicit `@JsonSubTypes` with name-based typing.

- [ ] **SpEL or Thymeleaf evaluation of user input** — `SpelExpressionParser.parseExpression(input)`, template names from request data, `__${...}__` preprocessing.
  - Look for: `parseExpression(`, `return "redirect:" + input`, `th:fragment` names from parameters.
  - Measure: `ensphere verify ssti --url <endpoint> --param <param> --engine freemarker --in-scope <pattern>` (adjust `--engine`); `ensphere scan ./src --category ssti`.
  - Fix: never evaluate user strings; fixed view names.

- [ ] **Log4j 2 below 2.17.0 or lookups enabled** — JNDI lookup on logged input.
  - Look for: dependency versions; `log4j2.formatMsgNoLookups`.
  - Measure: `manual: dependency version review`.
  - Fix: upgrade; remove `JndiLookup`.

## Rate limiting and abuse

- [ ] **No limiter on auth endpoints** — login, signup, reset, OTP verify without throttling.
  - Look for: `Bucket4j` filters, `resilience4j-ratelimiter`, a gateway limiter (Spring Cloud Gateway `RequestRateLimiter`), or an `OncePerRequestFilter` keyed by IP.
  - Measure: `ensphere verify ratelimit --url <login-endpoint> --method POST --body '<invalid-credentials>' --burst-count <approved> --window-sec 10 --in-scope <pattern>`.
  - Fix: Bucket4j with a Redis or Hazelcast backend keyed by IP and username.

- [ ] **No limiter on expensive or billed endpoints** — uploads, search, export, `JavaMailSender`, SMS, payment, and third-party API calls without per-user caps.
  - Look for: services calling `JavaMailSender`, `RestTemplate`/`WebClient` to paid APIs, S3 SDK, report generation; a matching limiter.
  - Measure: `ensphere verify ratelimit` with an approved burst on one endpoint per class; record `429` onset or its absence.
  - Fix: per-endpoint buckets keyed by principal; async queues with concurrency caps.

- [ ] **Limiter state is per JVM** — in-memory Bucket4j or Guava `RateLimiter` does not share counts across replicas.
  - Look for: `Bucket4j.builder()` without a `ProxyManager`; Guava `RateLimiter`.
  - Measure: `manual: source and deployment review`.
  - Fix: distributed buckets (Redis, Hazelcast) or gateway-level limiting.

- [ ] **Body size limits** — `spring.servlet.multipart.max-file-size` / `max-request-size` raised globally; `server.max-http-request-header-size` and proxy limits unset.
  - Look for: those properties; nginx or ingress `client_max_body_size`.
  - Measure: `ensphere verify limits --technique upload_size --sizes 1048576,10485760 --field file (planned)`; otherwise `manual: post one approved oversized body and record the status`.
  - Fix: small global caps; larger caps only on upload endpoints.
