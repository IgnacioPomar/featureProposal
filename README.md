# SSL Application PoC

A **Spring Boot 3 + Java 21** proof of concept that runs an HTTPS service, exposes OpenAPI documentation, provides a simple Hibernate CRUD, and includes certificate maintenance utilities.

## What this project does

1. Runs an HTTPS API on port `8443`.
2. Exposes OpenAPI docs (`/api-docs`) and Swagger UI (`/swagger-ui.html`).
3. Implements a simple Task CRUD with **Hibernate (JPA)**.
4. Manages schema evolution with **Liquibase**.
5. Includes CLI tools for installation checks and certificate renewal.

## Main endpoints

### Base API

- `GET /hello`

### Task CRUD

- `POST /api/tasks`
- `GET /api/tasks`
- `GET /api/tasks/{id}`
- `PUT /api/tasks/{id}`
- `DELETE /api/tasks/{id}`

Example payload (create/update):

```json
{
  "title": "My first task",
  "done": false
}
```

### OpenAPI

- OpenAPI JSON: `GET /api-docs`
- Swagger UI: `GET /swagger-ui.html`

### Certificate Renewal Page

- `GET /certificate-renewal`
  - Returns an HTML form (`directory`, `password`) and shows current certificate details.
- `POST /certificate-renewal`
  - Renews the keystore certificate and shows a before/after comparison plus a refresh link.

## Database and migrations

- Default DB: **H2** file database at `./target/db/sslapp`.
- Main CRUD table: `task_item` (UUID id).
- YAML comparison table: `archive` (same fields, UUID id).
- Liquibase changelogs:
  - `src/main/resources/db/changelog/db.changelog-master.json`
  - `src/main/resources/db/changelog/changes/001-create-task-table.json`

Main columns:

- `id` (UUID primary key)
- `title` (varchar 120, not null)
- `done` (boolean, not null)
- `created_at` (timestamp)
- `updated_at` (timestamp)

## Configuration

Common variables:

- `SSL_KEYSTORE_PASSWORD` (default: `changeit`)
- `APP_DATASOURCE_URL`
- `APP_DATASOURCE_USERNAME`
- `APP_DATASOURCE_PASSWORD`

Certificate page settings (`application.yml`):

- `app.certificate-page.path` (default: `/certificate-renewal`)
- `app.certificate-page.target-keystore` (default: `./target/classes/ssl/keystore.p12`)
- `app.certificate-page.alias` (default: `ssl-app`)

## Run

### Start HTTPS server

```bash
./mvnw spring-boot:run
```

### Quick endpoint checks

```bash
curl -k https://localhost:8443/hello
curl -k https://localhost:8443/api/tasks
curl -k https://localhost:8443/api-docs
curl -k https://localhost:8443/certificate-renewal
```

### Run tests

```bash
./mvnw test
```

## CLI commands

Available flags:

- `--check-installation`
- `--setup`
- `--renew-certificate`

Examples:

```bash
./mvnw spring-boot:run -Dspring-boot.run.arguments="--check-installation"
./mvnw spring-boot:run -Dspring-boot.run.arguments="--setup"
./mvnw spring-boot:run -Dspring-boot.run.arguments="--renew-certificate --renew-directory=/workspace/testdata/certs/180d-pem --renew-password=changeit"
```

`--renew-certificate` accepts input via:

- CLI args: `--renew-directory`, `--renew-password`
- Environment variables: `RENEW_DIRECTORY`, `RENEW_PASSWORD`

## Relevant structure

- `src/main/java/com/example/ssl/crud/`: entity, repository, service, and CRUD controller.
- `src/main/java/com/example/ssl/openapi/OpenApiConfiguration.java`: OpenAPI metadata.
- `src/main/java/com/example/ssl/web/CertificateRenewalPageController.java`: HTML certificate renewal endpoint.
- `src/main/java/com/example/ssl/cli/`: setup, install checks, certificate import/renew utilities.
- `src/main/resources/db/changelog/`: Liquibase migrations.
- `src/main/resources/application.yml`: SSL, datasource, JPA, Liquibase, springdoc, and certificate-page settings.

## PoC status

- HTTPS + CRUD + OpenAPI + Liquibase + certificate renewal (web/CLI): implemented.
- Full installation wizard and deeper DB validation workflow: partially implemented / pending hardening.
