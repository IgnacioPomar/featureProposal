# Zaleos Certificate Starter — Technical Specification

> **Version**: 1.2-draft
> **Date**: 2026-03-23
> **Scope**: Reusable Spring Boot starter for PEM TLS material management, targeting Java applications compliant with the NENA i3 standard.

---

## 1. Problem Statement

Java applications in the Zaleos ecosystem share a structural problem in TLS material management:

- HTTPS has historically been configured using PKCS12/JKS keystores — a legacy format incompatible with most modern CAs and the PEM-based delivery model that CAs and operators prefer.
- Certificate import logic is application-specific, with no reuse across projects.
- First deployment requires real TLS material, blocking initial startup.
- There is no shared validation contract to enforce corporate security policies consistently.
- Non-HTTPS uses (JWT/JWS signing and verification) lack a standard rotation mechanism.

The client ticket captures the core ask:

> *"INECRF should not use p12 keystores. Configure standard PEM certificates. Investigate automatic certificate hot-reload and API-based reload triggers, reducing element downtime."*

---

## 2. Solution Scope

The starter is a **consumer of TLS material, not an issuer**. It shall:

1. Accept TLS material in multiple input formats and normalize it to canonical PEM.
2. Validate candidate material against configurable corporate policies before activation.
3. Activate material safely, with atomic swap and rollback on failure.
4. Reload the HTTPS server without application restart (hot-reload).
5. Notify internal application components when new material has been activated (for non-HTTPS uses such as JWT).
6. Generate a self-signed placeholder certificate on first deployment to allow startup without a real CA-issued certificate.

The starter shall **not**:
- Issue certificates or generate CSRs toward external CAs.
- Manage DNS or ACME challenges.
- Distribute certificates across nodes in a cluster.
- Replace a secrets manager.

> **Scope boundary**: the starter targets single-node deployments or multi-node deployments with shared persistent storage. Stateless containerized replicas with ephemeral filesystems require an external certificate distribution mechanism outside this scope.

---

## 3. NENA i3 Compliance Requirements

Applications implementing the NENA i3 standard are subject to the following cryptographic requirements. The starter shall enforce these through its policy engine.

| Requirement | NENA mandate | Starter enforcement |
|---|---|---|
| Key algorithm | RSA-2048 minimum | `minimumKeyAlgorithm=RSA`, `minimumKeySize=2048` (policy defaults) |
| Trust chain | Must be rooted in the PCA (PSAP Credentialing Authority) | `sameRootCa=true` + configurable explicit trust anchor |
| Key storage | FIPS-140-2 | See §8 |

### Trust anchor for first import

The `sameRootCa` policy compares the candidate's root CA against the currently installed material. This comparison is skipped when the current material is a bootstrap placeholder. To enforce NENA PCA compliance from the very first real import, operators shall be able to configure an explicit expected root CA certificate:

```yaml
zaleos.certificate.policy.expected-root-ca: file:./config/nena-pca.pem
```

When configured, all imports — including the first — shall validate that the candidate chain terminates at this certificate.

---

## 4. Module Architecture

### Maven structure

```
es.zaleos.certificate.renewer  (parent pom)
├── certificate-renewer-core
└── certificate-renewer-spring-boot-starter
```

`core` is a pure Java library with no Spring dependency. It is independently testable and usable in non-Spring contexts (CLI tools, integration tests, standalone utilities). The `spring-boot-starter` depends on `core` and provides Spring Boot integration.

### `certificate-renewer-core` — responsibilities

| Component | Responsibility |
|---|---|
| `PemTlsImportAndActivateService` | Orchestration facade: import → validate → write → activate |
| `PemTlsMaterialImporter` | Format detection, parsing, key/cert/chain extraction |
| `PemTlsMaterialValidator` | Policy-based validation against current installed material |
| `PemTlsMaterialWriter` | Atomic write with staging, swap, and `.bak` preservation |
| `PemTlsCurrentMaterialLoader` | Loads currently active material for comparison |
| `InstallationTlsMaterialGenerator` | Generates self-signed bootstrap placeholder |
| `PemTlsValidationPolicy` | Immutable record defining active validation rules |
| `PemTlsValidationException` | Thrown when candidate material fails a policy check |

### `certificate-renewer-spring-boot-starter` — responsibilities

| Component | Responsibility |
|---|---|
| `ZaleosCertificateAutoConfiguration` | Conditional bean registration |
| `ZaleosCertificateProperties` | `@ConfigurationProperties` model under `zaleos.certificate.*` |
| `ZaleosCertificateBootstrapInitializer` | Triggers bootstrap generation on startup if needed |
| `ZaleosCertificatePolicyResolver` | Merges global policy with per-target overrides |
| `ZaleosCertificateTargetResolver` | Resolves file paths per named target |
| `TlsMaterialActivatedEvent` | Spring `ApplicationEvent` published after successful activation |
| `ZaleosCertificateJwsVerifier` | Verifies JWS signature and `x5c` certificate chain against configured trust anchor |
| `JwtDecoder` (adapter) | Spring Security `JwtDecoder` backed by `ZaleosCertificateJwsVerifier`; auto-reloads on activation |
| Maintenance endpoints | Authenticated REST API for remote import (individually configurable) |

---

## 5. Canonical Output Format

All input material shall be normalized to four PEM files:

| File | Contents |
|---|---|
| `certificate.pem` | Leaf certificate only |
| `chain.pem` | Intermediate chain without the leaf |
| `fullchain.pem` | Leaf + full chain (used by Spring SSL bundle) |
| `private-key.pem` | Private key, encrypted by default |

### Supported input formats

| Format | Extensions | Notes |
|---|---|---|
| PEM | `.pem`, `.crt`, `.cer` | May contain cert + key + chain in a single file |
| DER binary | `.der`, `.cer` | Automatically converted to PEM |
| Private key PEM | `.key` | Encrypted (PKCS#8 + AES) or unencrypted |
| PKCS#12 | `.p12`, `.pfx` | Password required |
| Archive | `.zip`, `.tar`, `.tar.gz` | Extracted and searched for valid material |

If no usable private key can be extracted, the operation shall fail with a descriptive error before any file is written.

---

## 6. Validation Policy Engine

Before activating any new material, the starter shall compare the candidate against the currently installed material using a set of configurable policies.

### Available policies

| Policy | Property | Default | Description |
|---|---|---|---|
| Same root CA | `sameRootCa` | `true` | Candidate must share the same trust root. **Required by NENA.** |
| Same intermediate chain | `sameChain` | `true` | Intermediate fingerprints must match |
| Same Subject DN | `sameSubject` | `true` | CN and subject attributes must not change |
| Same SANs | `sameSan` | `true` | Subject Alternative Names must not change |
| Same public key | `samePublicKey` | `true` | Public key must not change (renewal, not replacement) |
| Minimum key algorithm | `minimumKeyAlgorithm` | `RSA` | **Required by NENA.** |
| Minimum key size | `minimumKeySize` | `2048` | **Required by NENA.** |
| Expected root CA | `expectedRootCa` | _(unset)_ | Explicit PCA trust anchor for NENA compliance on first import |

Policies shall be configurable globally and overridable per named target.

### Bootstrap placeholder exception

Material generated by the bootstrap mechanism is marked with the `.installation.local` suffix in the CN. When the validator detects that the **currently installed** material is a placeholder, all `same-*` comparisons shall be skipped, allowing the first real certificate to be imported without restrictions. If `expectedRootCa` is configured, it shall still be enforced.

---

## 7. Hot-Reload Architecture

### 7.1 HTTPS server reload

Hot-reload for the HTTPS server shall use two complementary mechanisms:

**File watcher** (`reload-on-update: true`)

Spring Boot 3.1+ monitors the PEM files referenced in `spring.ssl.bundle.pem.*`. When it detects a change, it reloads the `SslBundle` and updates the Tomcat `SSLContext` without restarting the JVM. Any process that updates the canonical PEM files triggers this reload automatically, with a latency of up to the polling interval (~10 seconds).

**Programmatic reload** (`SslBundleRegistry.updateBundle()`)

The import API endpoint, after writing validated material to disk, shall call `SslBundleRegistry.updateBundle("server", newBundle)` directly. This provides an **immediate, synchronous** reload: the API response confirms that the new certificate is active before returning. This path applies only when the import is triggered via the REST API.

Both mechanisms coexist: CLI and crontab-triggered imports rely on the file watcher; API-triggered imports use the programmatic reload for immediate confirmation.

### 7.2 Non-HTTPS hot-reload (JWT/JWS)

Spring Boot has no native reload mechanism for non-SSL material. After every successful activation, the starter shall publish a `TlsMaterialActivatedEvent` via Spring's `ApplicationEventPublisher`. Application components that consume signing or verification material shall subscribe to this event and reload their state:

```java
@EventListener
public void onCertificateActivated(TlsMaterialActivatedEvent event) {
    if ("jwt-signer".equals(event.getTargetName())) {
        this.signingKey = reloadSigningKeyFromDisk();
    }
}
```

The starter provides the event contract; each application is responsible for implementing the reload logic for its own consumers.

### 7.3 Import delivery paths

The following paths shall be supported. They are complementary and all converge on writing the canonical PEM files:

| Path | Trigger | Authentication | Typical use |
|---|---|---|---|
| CLI `--import-tls-material` | Operator runs command on server | OS (SSH access) | Manual rotation, maintenance |
| Crontab → CLI | Scheduled OS job | OS | Periodic automated renewal |
| REST API (folder) | `POST /internal/certificates/import-from-folder` | JWT/JWS (see §9) | Remote rotation, CI/CD automation |
| REST API (upload) | `POST /internal/certificates/import-upload` (multipart) | JWT/JWS (see §9) | Remote rotation when server path is not shared |
| Inbox folder watcher | New files appear in a configured directory | OS (directory permissions) | certbot/ACME post-hook integration |

The inbox folder watcher enables the most natural integration with ACME clients: the certbot post-hook deposits files into the watched directory and the starter auto-imports without requiring API access.

---

## 8. Key Storage and FIPS-140-2

### What FIPS-140-2 requires

FIPS-140-2 certifies that cryptographic operations are performed within a validated module. Level 1 (software) requires a FIPS-validated cryptographic provider. Level 3 (hardware) requires a tamper-resistant HSM.

### Implementation tiers

| Tier | Implementation | FIPS status | Notes |
|---|---|---|---|
| **Current** | Encrypted private key on disk (PKCS#8 + AES-256); password via env var | FIPS-aligned intent, not certified | Protects key at rest; JVM crypto provider is not FIPS-validated |
| **Near-term** | BouncyCastle FIPS edition as crypto provider | Level 1 software | Drop-in replacement; no API changes |
| **Future** | PKCS#11 with an HSM | Level 3 hardware | Requires hardware; key never leaves the HSM |

The starter API shall be designed to support all three tiers without changes to application code. Cryptographic operations shall be isolated behind internal interfaces to allow provider substitution.

### Private key file permissions

The starter shall enforce restrictive filesystem permissions when writing key material:

- `private-key.pem`: mode `600` (owner read/write only).
- Target directory: mode `700`.

### Unencrypted private key option

Writing the private key without encryption (`writeUnencryptedPrivateKey: true`) is supported for environments where the JVM cannot access a password during startup. When enabled:

- File permissions are enforced automatically (`600`).
- A `WARN`-level log entry is emitted at startup.
- **This option is not recommended for NENA-compliant deployments.**

---

## 9. Maintenance API

### 9.1 Endpoint availability

All maintenance REST endpoints shall be individually configurable. Each endpoint can be enabled or disabled independently. When disabled, the application does not register the route at all — the path simply does not exist. This allows deployments to expose only the delivery paths that fit their operational model (e.g., a server behind a firewall may expose the folder-based endpoint but not the upload endpoint).

```yaml
zaleos.certificate.maintenance:
  enabled: true                          # master switch — disables all endpoints when false
  import-from-folder:
    enabled: true
    path: /internal/certificates/import-from-folder
  import-upload:
    enabled: true
    path: /internal/certificates/import-upload
  rollback:
    enabled: true
    path: /internal/certificates/rollback
```

### 9.2 Authentication

The active maintenance endpoints shall be protected with JWS tokens (see §10). The token shall be signed with the **currently installed TLS certificate**. This creates a natural trust bootstrap: only a party that already holds the active certificate can authorize a rotation.

Required claim: `zaleos.certificates.maintenance: true`

Constraints:
- The first import after bootstrap must use an alternative mechanism (CLI or direct file placement), since no real CA-issued certificate is yet available to sign a JWS token with.
- Subsequent rotations can be fully remote and automated.
- If `maintenance.enabled` is `false`, all import operations must go through the CLI or the inbox folder watcher.

---

## 10. JWS Verification

The starter shall provide a reusable JWS verification capability backed by the currently installed certificate material. This frees application components from implementing certificate-aware signature verification themselves.

### 10.1 Verification model

A JWS token may carry the signer's certificate chain in the `x5c` header parameter. When present, full verification proceeds in two steps:

1. **Chain validation**: the certificate in `x5c[0]` (leaf) must chain up to the configured `expectedRootCa` trust anchor. Each certificate in the chain must be valid (not expired, not revoked by basic constraints).
2. **Signature verification**: the JWS signature is verified against the public key of the leaf certificate extracted from `x5c`.

When the `x5c` header is absent, the verifier falls back to verifying the signature against the public key of the currently installed certificate.

### 10.2 Exposed beans

The starter shall register two beans:

**`ZaleosCertificateJwsVerifier`**

```java
public interface ZaleosCertificateJwsVerifier {
    /**
     * Verifies the JWS compact serialization.
     * Validates the x5c chain against the configured trust anchor (if present)
     * and verifies the signature.
     * @throws JwsVerificationException if the chain or signature is invalid.
     */
    void verify(String jwsCompact) throws JwsVerificationException;

    /**
     * Verifies and returns the parsed claims.
     */
    Map<String, Object> verifyAndExtractClaims(String jwsCompact) throws JwsVerificationException;
}
```

**`JwtDecoder`** (Spring Security adapter)

A `JwtDecoder` implementation backed by `ZaleosCertificateJwsVerifier`. Applications using Spring Security can configure it as their decoder without any additional code:

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                               JwtDecoder jwtDecoder) throws Exception {
    http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)));
    return http.build();
}
```

Both beans are registered as `@ConditionalOnMissingBean`, allowing applications to override them with custom implementations.

### 10.3 Automatic reload

When a `TlsMaterialActivatedEvent` is published (after any successful import), the `ZaleosCertificateJwsVerifier` shall reload its internal trust material automatically. No application restart or manual intervention is required.

### 10.4 Internal use

The starter uses `ZaleosCertificateJwsVerifier` internally to authenticate calls to the maintenance endpoints (§9). This ensures a single, consistent verification path for both internal and application-level use.

---

## 11. Safe Write and Rollback

All write operations shall follow an atomic staging protocol to prevent partial writes from leaving the application in an inconsistent state:

```
1. Write all new PEM files to a temporary staging directory
2. Verify all staged files are readable and cryptographically valid
3. Copy current active files to <filename>.bak
4. Rename staging directory contents to the active target paths (atomic on same filesystem)
5. On any failure in steps 1–4: restore from .bak files
```

Constraints:
- One `.bak` copy is retained per file — sufficient for immediate rollback.
- Concurrent import operations shall be prevented by a JVM-local mutex (one active import at a time per application instance).
- A dedicated rollback endpoint (`POST /internal/certificates/rollback`) shall allow operators to revert to the previous material without re-importing.

---

## 11. Bootstrap Mechanism

On startup, if no usable TLS material is found for a configured target, the starter shall generate a self-signed placeholder certificate to allow the application to start with HTTPS active.

### Placeholder certificate specification

| Attribute | Value |
|---|---|
| Key algorithm | RSA-2048 |
| Signature algorithm | SHA256withRSA |
| Validity | 365 days from generation |
| Subject CN | `<app-name>.<target-name>.installation.local` |
| Extensions | Basic Constraints: non-CA; Key Usage: digitalSignature, keyEncipherment |

The `.installation.local` suffix in the CN is the marker used by the validator to identify placeholder material and skip `same-*` policy checks on first real import.

### Bootstrap conditions

Bootstrap generation shall be skipped if:
- `zaleos.certificate.bootstrap.enabled` is `false`.
- `zaleos.certificate.bootstrap.only-if-missing` is `true` and valid material already exists on disk.

---

## 12. Configuration Reference

```yaml
zaleos:
  certificate:
    enabled: true

    bootstrap:
      enabled: true
      only-if-missing: true
      default-common-name: installation.local

    output:
      write-unencrypted-private-key: false
      private-key-password: ${APP_TLS_PRIVATE_KEY_PASSWORD}

    policy:                              # global defaults
      same-root-ca: true                 # NENA required
      same-chain: true
      same-subject: true
      same-san: true
      same-public-key: true
      minimum-key-algorithm: RSA         # NENA required
      minimum-key-size: 2048             # NENA required
      expected-root-ca:                  # explicit PCA trust anchor (NENA)

    maintenance:
      enabled: true                      # master switch
      import-from-folder:
        enabled: true
        path: /internal/certificates/import-from-folder
      import-upload:
        enabled: true
        path: /internal/certificates/import-upload
      rollback:
        enabled: true
        path: /internal/certificates/rollback

    targets:
      web-server:                        # built-in target for HTTPS
        type: filesystem
        output-dir: ./ssl
        activate: true

      jwt-signer:                        # example non-HTTPS target
        type: filesystem
        output-dir: ./ssl/jwt
        activate: true
        policy:
          same-public-key: false         # key rotation is the main use case here
```

### Key environment variables

| Variable | Description |
|---|---|
| `APP_TLS_PRIVATE_KEY_PASSWORD` | Private key password for the server TLS bundle |
| `APP_TLS_TARGET_DIR` | Override for the TLS material target directory |
| `TLS_SOURCE_DIR` | Source directory for `--import-tls-material` |
| `TLS_SOURCE_PASSWORD` | Password for source material during import |

---

## 13. Spring Boot Integration

The HTTPS server shall be configured using Spring Boot's standard SSL bundle mechanism:

```yaml
spring:
  ssl:
    bundle:
      pem:
        server:
          keystore:
            certificate: file:./ssl/fullchain.pem
            private-key: file:./ssl/private-key.pem
            private-key-password: ${APP_TLS_PRIVATE_KEY_PASSWORD}
          reload-on-update: true
server:
  ssl:
    bundle: server
```

This configuration requires no proprietary Tomcat APIs and is portable across Spring Boot-supported embedded servers.

---

## 14. CLI Commands

The demo application exposes the following CLI commands for operator use:

| Command | Description |
|---|---|
| `--setup` | Configures a new installation: generates bootstrap material, runs Liquibase, writes `config/application.properties` |
| `--check-installation` | Verifies installation state: PEM files, database, Liquibase tables. Produces an HTML report. Runs without a Spring context for fast execution. |
| `--import-tls-material` | Imports and activates TLS material from a local directory or file |
| `--renew-certificate` | Legacy alias for `--import-tls-material` |

---

## 15. Named Targets

### `web-server` (built-in)

- Manages the HTTPS certificate for the embedded server.
- Output: `fullchain.pem` + `private-key.pem` read by Spring SSL bundle.
- Hot-reload: file watcher (always) + `SslBundleRegistry.updateBundle()` (API path).

### `jwt-signer` / `jwt-verifier` (application-defined)

- Manages certificates used for JWT/JWS signing or verification.
- Output: PEM files in a configured directory.
- Hot-reload: `ZaleosCertificateJwsVerifier` bean reloads automatically on `TlsMaterialActivatedEvent` (§10). Applications using Spring Security receive the updated `JwtDecoder` transparently.
- Applications that do not use Spring Security can inject `ZaleosCertificateJwsVerifier` directly and call `verify()` / `verifyAndExtractClaims()` without managing key reload themselves.
- Suggested policy override: `same-public-key: false` (key rotation is the intended use case).

### Generic integration targets (application-defined)

- For mTLS client certificates, message signing, or any other certificate use.
- Supports `activate: false` mode: import and normalize without replacing active files.
- Supports `import-only` mode for staging before a planned maintenance window.

---

## 16. Observability

The starter shall expose the following via Spring Boot Actuator:

| Metric / endpoint | Description |
|---|---|
| `zaleos.certificate.days-until-expiry` (gauge) | Days until the active leaf certificate expires, per target |
| `zaleos.certificate.last-rotation-timestamp` (gauge) | Unix timestamp of last successful activation, per target |
| `GET /actuator/certificates` | Current certificate details per target (subject, issuer, serial, SANs, expiry, SHA-256) |

These metrics enable alerting on approaching expiry and verification that rotations completed successfully.

---

## 17. Roadmap

### Phase 1 — Consolidation

- [ ] `ZaleosCertificateJwsVerifier` bean with `x5c` chain validation and signature verification
- [ ] `JwtDecoder` Spring Security adapter backed by the verifier
- [ ] Import API endpoints protected by `ZaleosCertificateJwsVerifier` (individually enable/disable per endpoint)
- [ ] `SslBundleRegistry.updateBundle()` called from the API path
- [ ] JVM-local mutex preventing concurrent imports
- [ ] `TlsMaterialActivatedEvent` published after each successful activation
- [ ] `expectedRootCa` policy for explicit PCA trust anchor
- [ ] Filesystem permission enforcement on private key files (`600`)
- [ ] Manual rollback endpoint
- [ ] Starter property documentation for library consumers

### Phase 2 — Operational Safety

- [ ] Inbox folder watcher for certbot/ACME post-hook integration
- [ ] Dry-run mode: validate without activating
- [ ] Actuator metrics (expiry days, last rotation timestamp)
- [ ] Actuator endpoint for current certificate status

### Phase 3 — Broader Adoption

- [ ] `import-only` and `activate-only` flows for non-HTTPS targets
- [ ] Adoption in other ecosystem applications
- [ ] BouncyCastle FIPS edition migration (FIPS Level 1)
- [ ] ACME/certbot integration guide
