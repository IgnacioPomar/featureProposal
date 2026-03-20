# Zaleos Certificate Starter Design v1

## 1. Goal

Design a reusable Spring Boot starter, with package root `es.zaleos.certificate.renewer`, that can:

- import externally issued TLS material from many input formats
- normalize the result to standard PEM files
- validate the imported material against configurable security policies
- activate the material using standard Spring Boot SSL mechanisms when the target is the web server
- replace non-SSL application certificates too, using explicit target file paths
- rollback safely on failure
- bootstrap installation-only fake certificates on first startup if no usable material exists

This starter does **not** issue certificates. It only imports and activates new TLS material.

## 2. Non-goals

- ACME client behavior
- public CA integration
- certificate issuance
- concurrency support for multiple simultaneous maintenance operations
- custom Tomcat-only APIs or Tomcat-specific public configuration

## 3. Module Structure

### 3.1 `es.zaleos.certificate.renewer.core`

Responsibilities:

- detect and parse input formats
- extract private key, leaf certificate, full chain, trust material
- normalize to PEM output files
- validate configured policies
- perform safe write/swap/rollback
- provide operation locking
- expose result metadata

### 3.2 `es.zaleos.certificate.renewer.spring.boot.starter`

Responsibilities:

- `@ConfigurationProperties("zaleos.certificate")`
- Spring Boot auto-configuration
- endpoint exposure
- target resolution from Spring SSL configuration
- startup bootstrap logic
- JWT/JWS verification wiring

### 3.3 `runtime adapter`

Responsibilities:

- activate imported material in the effective target
- use Spring Boot standard SSL bundle reload when the target is the embedded web server
- support generic filesystem targets for non-SSL materials

## 4. Standard Output Format

The canonical internal and output format is PEM.

Logical output files:

- `certificate.pem`
- `chain.pem`
- `fullchain.pem`
- `private-key.pem`

Notes:

- `private-key.pem` should be written encrypted when a password is configured for that target.
- If no output key password is configured, `private-key.pem` can be written unencrypted, but this should raise a warning unless explicitly allowed.
- `fullchain.pem` is leaf certificate + intermediate/root chain in the correct order for consumers that expect a single file.

For Spring Boot web server SSL, the standard target configuration is:

- `spring.ssl.bundle.pem.<bundle>.keystore.certificate=file:/.../fullchain.pem`
- `spring.ssl.bundle.pem.<bundle>.keystore.private-key=file:/.../private-key.pem`
- `spring.ssl.bundle.pem.<bundle>.reload-on-update=true`
- `server.ssl.bundle=<bundle>`

Source:

- https://docs.spring.io/spring-boot/reference/features/ssl.html

## 5. Supported Input Formats

Version 1 must support:

- `.pem`
- `.crt`
- `.cer`
- `.der`
- `.key`
- `.pfx`
- `.p12`
- `.zip`
- `.tar`

Supported combinations:

- certificate only -> fail, because private key is required
- certificate + private key
- certificate + private key + chain
- PKCS#12 with embedded private key and chain
- encrypted and unencrypted private keys
- encrypted and unencrypted PKCS#12
- PEM bundle with key/cert/chain in the same file
- archive files containing any of the supported combinations

Version 1 behavior:

- if no usable private key can be extracted, import fails
- if multiple candidate materials exist in the same archive/folder, selection rules must be deterministic and documented

## 6. Security Policy Model

Two authorization/validation modes exist:

### 6.1 JWT/JWS operation authorization

If configured, the maintenance endpoint requires a valid signed JWT/JWS.

Chosen claim name:

- `zaleos.certificates.maintenance`

Reason:

- more explicit than `zaleos.certificates`
- clearly scoped to maintenance operations
- leaves room for future certificate-related scopes

JWT requirements for v1:

- signed token, asymmetric preferred
- validated against configured certificate/public key
- mandatory `exp`
- mandatory `iat`
- mandatory `jti`
- mandatory scope/claim `zaleos.certificates.maintenance`
- mandatory operation claim, example `op=import-and-activate` or `op=import-only`
- mandatory payload hash claim for upload operations, example `sha256`

Header transport:

- `Authorization: Bearer <token>`

### 6.2 Certificate validation policy

If JWT/JWS authorization is not configured, or after it passes, the imported material must satisfy configured policies.

Default mode:

- `all-of`

Default enabled policies:

- `same-root-ca`
- `same-chain`
- `same-subject`
- `same-san`
- `same-public-key`
- `minimum-key-algorithm`
- `minimum-key-size`

Version 1 should also enforce:

- private key present
- private key matches imported leaf certificate public key

### 6.3 Key algorithm policy

Version 1 examples:

- `RSA-2048`
- `RSA-2048-or-higher`
- `EC-P256`

Chosen implementation:

- `minimum-key-algorithm`
- `minimum-key-size`

## 7. Target Model

The starter must not be conceptually tied to Tomcat.

Targets:

- `web-server-default`
- `ssl-bundle:<name>`
- `file:<property-name>`
- `explicit-filesystem`

### 7.1 Web server target resolution

Resolution order:

1. if an explicit Zaleos target is configured, use it
2. if Spring SSL bundle is configured, use the bundle
3. otherwise try `server.ssl.*`
4. if nothing usable exists, bootstrap fake installation material

### 7.2 Generic filesystem targets

The application may use certificates for non-HTTPS purposes too, such as:

- JWS verification
- JWT verification
- external protocol trust checks
- custom application integrations

For these targets, the user can configure a property-backed path, for example:

- `zaleos.certificate.targets.jwt-verifier.certificate-path=${public.key.path}`

The starter then replaces the file at that resolved path, applying the target-specific validation rules.

## 8. Zaleos Configuration Model

Public prefix:

- `zaleos.certificate.*`

### 8.1 Top-level properties

- `zaleos.certificate.enabled=true`
- `zaleos.certificate.bootstrap.enabled=true`
- `zaleos.certificate.bootstrap.only-if-missing=true`
- `zaleos.certificate.maintenance.lock-enabled=true`
- `zaleos.certificate.maintenance.allow-post=false`
- `zaleos.certificate.maintenance.endpoint-path=/internal/certificates/import`
- `zaleos.certificate.maintenance.folder-endpoint-path=/internal/certificates/import-from-folder`
- `zaleos.certificate.maintenance.upload.max-size=20MB`
- `zaleos.certificate.maintenance.jwt.enabled=false`
- `zaleos.certificate.maintenance.jwt.required-claim=zaleos.certificates.maintenance`
- `zaleos.certificate.maintenance.jwt.verifier-certificate=file:/.../jwt-verifier.pem`
- `zaleos.certificate.maintenance.jwt.clock-skew=30s`

### 8.2 Source properties

- `zaleos.certificate.source.folder=/some/path`
- `zaleos.certificate.source.archive-pattern=*`
- `zaleos.certificate.source.private-key-password=...`
- `zaleos.certificate.source.pkcs12-password=...`

### 8.3 Output properties

- `zaleos.certificate.output.base-directory=/var/lib/zaleos/certificates/<target>`
- `zaleos.certificate.output.private-key-password=...`
- `zaleos.certificate.output.write-unencrypted-private-key=false`

### 8.4 Policy properties

- `zaleos.certificate.policy.mode=all-of`
- `zaleos.certificate.policy.same-root-ca=true`
- `zaleos.certificate.policy.same-chain=true`
- `zaleos.certificate.policy.same-subject=true`
- `zaleos.certificate.policy.same-san=true`
- `zaleos.certificate.policy.same-public-key=true`
- `zaleos.certificate.policy.minimum-key-algorithm=RSA`
- `zaleos.certificate.policy.minimum-key-size=2048`

### 8.5 Targets

- `zaleos.certificate.targets.web-server.type=auto`
- `zaleos.certificate.targets.web-server.bundle-name=server`
- `zaleos.certificate.targets.web-server.output-dir=/var/lib/zaleos/certificates/web-server`
- `zaleos.certificate.targets.web-server.activate=true`

- `zaleos.certificate.targets.jwt-verifier.type=filesystem`
- `zaleos.certificate.targets.jwt-verifier.certificate-path=${public.key.path}`
- `zaleos.certificate.targets.jwt-verifier.chain-path=/opt/app/security/jwt-chain.pem`
- `zaleos.certificate.targets.jwt-verifier.activate=true`

Each target may override common policy defaults.

## 9. Operation Modes

Supported operations:

- `import-and-activate`
- `import-only`
- `activate-staged`

Default operation:

- `import-and-activate`

Behavior:

- `import-only` writes validated material into the configured target staging location, but does not trigger runtime activation
- `activate-staged` activates already imported staged material

## 10. Endpoint Design

The web API must be optional and disabled unless the starter is enabled.

Version 1 should expose separate endpoints:

- folder import endpoint
- upload endpoint

Endpoints:

- `POST /internal/certificates/import-from-folder`
- `POST /internal/certificates/import-upload`

The upload endpoint must remain disabled by default:

- `zaleos.certificate.maintenance.allow-post=false`

Upload payload support:

- multipart certificate/key files
- zip/tar archives

Request parameters:

- `target`
- `operation`
- `privateKeyPassword` when needed
- optional target override only if that target is declared as overrideable

## 11. Locking And Concurrency

Concurrency is not supported in v1.

Behavior:

- use a single maintenance lock per application instance
- if another maintenance operation is in progress, fail fast with a clear response

## 12. Rollback And Safe Swap

The write strategy is:

1. extract and validate material
2. write new files into a temporary directory
3. verify resulting target material
4. move current target material to backup
5. atomically move new material into place when possible
6. activate runtime target
7. if activation fails, rollback from backup

Backup naming:

- `.bak`

Temporary workspace:

- system temp directory or configured work directory

## 13. Bootstrap Installation Material

Bootstrap is intended only to make the application start on first installation when no usable certificate material exists yet.

Rules:

- only run on startup
- only generate missing material
- do not overwrite valid existing material
- apply independently per target
- bootstrap result must be clearly marked as installation-only/fake

For web server SSL:

- if no bundle or `server.ssl.*` material exists, generate fake installation PEM material and wire startup to it

For generic targets:

- bootstrap is opt-in per target
- if target bootstrap is enabled and required files do not exist, generate fake placeholder material for that target

## 14. Activation Strategy

### 14.1 Web server SSL

Use the standard Spring Boot PEM SSL bundle reload mechanism.

Preferred effective runtime configuration:

- `spring.ssl.bundle.pem.server.keystore.certificate=file:/.../fullchain.pem`
- `spring.ssl.bundle.pem.server.keystore.private-key=file:/.../private-key.pem`
- `spring.ssl.bundle.pem.server.reload-on-update=true`
- `server.ssl.bundle=server`

This avoids a Tomcat-specific public API while still allowing embedded Tomcat reload via Spring Boot standard support.

### 14.2 Generic certificate targets

For non-web-server materials, activation means:

- replace the configured files
- optionally notify a listener/bean if one is registered

Version 1 does not require a general in-memory hot reload contract for arbitrary application consumers.

## 15. Context Regenerated

The project is evolving from a PoC HTTPS app with CLI utilities into a reusable starter:

- current PoC already has certificate import and replacement logic
- current PoC already has setup/bootstrap ideas and installation checks
- the new target is a generic starter under `es.zaleos.certificate.renewer`
- runtime output should move toward standard PEM and Spring Boot SSL bundles
- certificate maintenance must also support non-SSL application certificate files
- maintenance API security should be JWT/JWS-based when configured
- rollback, locking, and first-install bootstrap are mandatory behaviors

## 16. Closed Decisions For v1

### 16.1 Archive selection rules

When multiple candidate materials are found in the same archive or source folder, selection is deterministic:

1. prefer a PKCS#12 container if exactly one valid container with private key is present
2. otherwise prefer a complete PEM bundle containing private key + leaf certificate
3. otherwise combine:
   - one private key
   - one leaf certificate
   - zero or more chain certificates
4. if more than one equally valid candidate set remains, fail with an explicit ambiguity error

### 16.2 `same-chain` semantics

For v1, `same-chain` means:

- same root CA fingerprint
- same ordered intermediate certificate fingerprints

The leaf certificate is not part of this check because it is covered by the rest of the policy set.

### 16.3 Private key PEM encryption

For v1:

- if `zaleos.certificate.output.private-key-password` is configured, `private-key.pem` is written encrypted
- if it is not configured, writing an unencrypted `private-key.pem` is allowed only when:
  - `zaleos.certificate.output.write-unencrypted-private-key=true`
- default is:
  - `zaleos.certificate.output.write-unencrypted-private-key=false`

If encryption is required and no output key password is available, the operation fails.

### 16.4 Staging directory for `import-only`

For v1, staged material lives under:

- `<output-dir>/.staged/<timestamp-or-operation-id>/`

`activate-staged` only operates on the most recent valid staged material unless a specific staged operation id is provided.

### 16.5 Bootstrap for non-SSL targets

For v1:

- bootstrap is automatic for the default web-server target when no usable material exists
- bootstrap is disabled by default for non-SSL targets
- non-SSL targets must explicitly opt in with:
  - `zaleos.certificate.targets.<name>.bootstrap-enabled=true`

### 16.6 Future revocation checks

CRL/OCSP is out of scope for v1 and explicitly deferred to a future version.

## 17. Final v1 Contract

The v1 implementation contract is:

- package root: `es.zaleos.certificate.renewer`
- architecture: `core`, `spring.boot.starter`, `runtime adapter`
- supported outputs: `certificate.pem`, `chain.pem`, `fullchain.pem`, `private-key.pem`
- supported inputs: `pem`, `crt`, `cer`, `der`, `key`, `pfx`, `p12`, `zip`, `tar`
- private key is mandatory
- canonical output format is PEM
- default policy mode is `all-of`
- default policy set is:
  - `same-root-ca`
  - `same-chain`
  - `same-subject`
  - `same-san`
  - `same-public-key`
  - `minimum-key-algorithm`
  - `minimum-key-size`
- JWT/JWS claim for maintenance authorization is:
  - `zaleos.certificates.maintenance`
- web-server activation uses Spring Boot PEM SSL bundle reload
- generic non-SSL certificate targets are supported through configured filesystem paths
- rollback and application-wide locking are mandatory
- bootstrap fake material is mandatory for the default web-server target on first install when nothing usable exists
