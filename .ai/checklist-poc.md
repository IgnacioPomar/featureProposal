# Checklist — Zaleos Certificate Starter PoC

> Full specification: `doc/specs/zaleos-certificate-starter.md`

---

## Core: PEM Normalization

- [x] Multi-format input: PEM, DER, PKCS#12, ZIP, TAR
- [x] Canonical output: `certificate.pem`, `chain.pem`, `fullchain.pem`, `private-key.pem`
- [x] Encrypted private key output (PKCS#8 + AES-256)
- [x] `writeUnencryptedPrivateKey` option with WARN log
- [x] `chmod 600` on `private-key.pem`, `chmod 700` on target directory (POSIX; skipped silently on Windows)

## Core: Validation Policy

- [x] `sameRootCa` — root CA fingerprint comparison
- [x] `sameChain` — ordered intermediate fingerprints
- [x] `sameSubject` — Subject DN
- [x] `sameSan` — Subject Alternative Names
- [x] `samePublicKey` — public key encoding
- [x] `minimumKeyAlgorithm` — e.g. RSA (NENA required)
- [x] `minimumKeySize` — e.g. 2048 (NENA required)
- [x] `expectedRootCa` — explicit PCA trust anchor; enforced even for bootstrap placeholder replacements
- [x] Bootstrap placeholder detection (`.installation.local` CN suffix); `same-*` checks skipped, `expectedRootCa` still applied

## Core: Safe Write and Rollback

- [x] Staging to temp directory before swap
- [x] Atomic rename swap (with non-atomic fallback)
- [x] `.bak` backup of current active files
- [x] Automatic restore from `.bak` on any write/swap failure

## Bootstrap

- [x] `ZaleosCertificateBootstrapInitializer` — generates placeholder on startup if no usable material exists
- [x] RSA-2048, SHA256withRSA, 365 days, `<app>.<target>.installation.local` CN
- [x] `only-if-missing` guard — skips if valid material already exists
- [x] Opt-in per non-SSL target via `bootstrap-enabled: true`

## Spring Boot Starter: Wiring

- [x] `@ConfigurationProperties("zaleos.certificate")` with full nested model
- [x] `@ConditionalOnMissingBean` on all beans — fully overridable
- [x] `ZaleosCertificateTargetResolver` — resolves paths from config, SSL bundle, or fallback
- [x] `ZaleosCertificatePolicyResolver` — merges global policy with per-target overrides; loads `expectedRootCa` via Spring `ResourceLoader`
- [x] `ZaleosCertificateSecurityAutoConfiguration` — separate class for `JwtDecoder` bean to avoid introspection failure when Spring Security is absent

## Spring Boot Starter: Operation Service

- [x] `ZaleosCertificateOperationService` — JVM-local mutex (`ReentrantLock`); one import at a time
- [x] `TlsMaterialActivatedEvent` published after every successful activation and rollback
- [x] Rollback via `.bak` files triggered from API
- [ ] `SslBundleRegistry.updateBundle()` for immediate synchronous HTTPS reload from API path (TODO: pending Spring Boot 4 PemSslBundle API investigation; file watcher covers the use case)

## Spring Boot Starter: JWS Verification

- [x] `ZaleosCertificateJwsVerifier` interface
- [x] `DefaultZaleosCertificateJwsVerifier` — verifies `x5c` chain against `expectedRootCa`; falls back to installed public key when `x5c` absent
- [x] Auto-reload on `TlsMaterialActivatedEvent` (read-write lock)
- [x] `ZaleosCertificateJwtDecoder` — Spring Security `JwtDecoder` adapter (conditional on classpath)

## Spring Boot Starter: Maintenance API

- [x] `POST import-from-folder` — JWS authenticated, individually toggleable
- [x] `POST import-upload` — multipart, JWS authenticated, individually toggleable
- [x] `POST rollback` — JWS authenticated, individually toggleable
- [x] Master switch `zaleos.certificate.maintenance.enabled`
- [x] Per-endpoint `enabled` flag + configurable `path`
- [x] Required claim: `zaleos.certificates.maintenance: true`
- [ ] `exp`, `iat`, `jti` claim enforcement in JWS verifier
- [ ] `op` claim per operation type
- [ ] `sha256` payload hash claim for upload operations
- [ ] `upload.max-size` configuration

## HTTPS Hot-Reload

- [x] `spring.ssl.bundle.pem.server.reload-on-update: true` — file watcher, ~10s latency
- [ ] Immediate `SslBundleRegistry.updateBundle()` from API path (see above)

## CLI

- [x] `--setup` — interactive, generates bootstrap material, runs Liquibase, writes `config/application.properties`
- [x] `--check-installation` — verifies PEM files, DB, Liquibase tables; HTML report; runs without Spring context
- [x] `--import-tls-material` — delegates to `ZaleosCertificateOperationService` (mutex + event)
- [x] `--renew-certificate` — legacy alias

## Demo Application

- [x] HTTPS on `8443` via Spring SSL bundle PEM
- [x] `TlsMaterialPageController` — web UI for status display and import
- [x] Task CRUD API (Liquibase + JPA + H2/PostgreSQL)
- [x] OpenAPI docs at `/api-docs`, Swagger UI at `/swagger-ui.html`

## Tests

- [x] `PemTlsMaterialValidatorTests` — `same-public-key` rejection; placeholder bypass
- [x] `ZaleosCertificateBootstrapInitializerTests` — generates material when files missing
- [x] `SslApplicationTests` — Spring context loads

## Phase 2 Pending

- [ ] Inbox folder watcher (certbot/ACME post-hook)
- [ ] Dry-run mode (validate without activating)
- [ ] Actuator metrics: `days-until-expiry`, `last-rotation-timestamp`
- [ ] Actuator endpoint `GET /actuator/certificates`

## Phase 3 Pending

- [ ] `import-only` mode: write to `<output-dir>/.staged/<timestamp>/` without activating
- [ ] `activate-staged` mode: activate the most recent staged material
- [ ] BouncyCastle FIPS edition migration
- [ ] ACME/certbot integration guide
- [ ] Adoption in other ecosystem applications
