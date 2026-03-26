# Zaleos Certificate Starter — PoC

A multi-module Maven project demonstrating a reusable Spring Boot starter for PEM-based TLS material management. Built as a response to the client requirement to replace PKCS12/JKS keystores with standard PEM certificates and support hot-reload without downtime.

Full technical specification: [`doc/specs/zaleos-certificate-starter.md`](doc/specs/zaleos-certificate-starter.md)

---

## What It Solves

Java applications need TLS certificates for HTTPS, and need to rotate them safely without restarting. They also need certificates for JWT/JWS signing and verification. Today that logic is duplicated across applications, tied to legacy keystores, and requires downtime.

This starter solves it once, reusably, for any Spring Boot application.

---

## Modules

| Module | Purpose |
|---|---|
| `certificate-renewer-core` | Pure Java library. Parses any certificate format, normalises to PEM, validates against policies, writes atomically with rollback. No Spring dependency. |
| `certificate-renewer-spring-boot-starter` | Spring Boot auto-configuration on top of `core`. Provides bootstrap on first startup, hot-reload integration, JWS verification bean, and authenticated REST endpoints for remote rotation. |
| `ssl-application` | Demo application. Shows the starter in use: HTTPS server, CLI commands, and a web page for certificate management. |

---

## Key Capabilities

**PEM normalisation.** Accepts PEM, DER, direct PKCS#12 files, and ZIP/TAR/TAR.GZ archives. Activates the runtime PEM pair: `fullchain.pem` and `private-key.pem`.

**Hot-reload.** The running HTTPS server reloads when certificate files change — no JVM restart. API-triggered rotations reload synchronously and confirm the new certificate in the response.

**Policy validation.** Before activating any new material, the starter checks algorithm (RSA-2048 minimum), chain root, subject, SANs, and public key against the currently installed certificate. All rules are configurable per target.

**Bootstrap.** On first startup with no certificate present, the starter generates a self-signed placeholder so the application can start with HTTPS active. The placeholder is automatically replaced when real material arrives.

**JWS verification.** The starter exposes a `TlsMaterialJwsVerifier` bean. If the token carries an `x5c` chain, it validates the full chain before checking the signature. Spring Security applications get a `JwtDecoder` adapter at no extra cost.

**Safe rotation.** All writes go through a staging area. The active files are backed up before swap. Any failure triggers automatic rollback.

---

## Running the Demo

**Start:**
```bash
./mvnw -q -pl ssl-application -am spring-boot:run
```

**Quick checks:**
```bash
curl -k https://localhost:8443/
curl -k https://localhost:8443/hello
curl -k https://localhost:8443/api-docs
curl -k https://localhost:8443/certificate-renewal
```

---

## CLI Commands

**First-time setup** — configures DB, generates bootstrap certificate, writes `config/application.properties`:
```bash
./mvnw -q -pl ssl-application -am spring-boot:run \
  -Dspring-boot.run.arguments="--setup"
```

**Installation check** — verifies PEM files, DB connection, and Liquibase state:
```bash
./mvnw -q -pl ssl-application -am spring-boot:run \
  -Dspring-boot.run.arguments="--check-installation"
```

**Import TLS material** — imports and activates new certificate from a local directory:
```bash
./mvnw -q -pl ssl-application -am spring-boot:run \
  -Dspring-boot.run.arguments="--import-tls-material \
    --tls.import.target-name=jwt-signer \
    --tls-source-dir=/path/to/certs \
    --tls-source-password=changeit"
```

**Browser test index** — open `https://localhost:8443/` to find:
- direct links for `hello`, Swagger/OpenAPI, CRUD, actuator, and metrics checks,
- a single certificate renewal demo page that can run local import, JWS/JWT remote import, bad-signature checks, and rollback for the selected target.

---

## Configuration

Minimal configuration to activate the starter:

```yaml
zaleos:
  certificate:
    targets:
      web-server:
        output-dir: ${APP_TLS_TARGET_DIR:./ssl}

spring:
  ssl:
    bundle:
      pem:
        server:
          keystore:
            certificate: file:./ssl/fullchain.pem
            private-key: file:./ssl/private-key.pem
          reload-on-update: true
server:
  ssl:
    bundle: server
```

Key environment variables:

| Variable | Purpose |
|---|---|
| `APP_TLS_PRIVATE_KEY_PASSWORD` | Private key password |
| `APP_TLS_TARGET_DIR` | Override for the active PEM output directory used by the `web-server` target |
| `TLS_SOURCE_DIR` | Source directory for `--import-tls-material` |
| `TLS_SOURCE_PASSWORD` | Source material password during import |

---

## Tests

```bash
./mvnw -q test
```
