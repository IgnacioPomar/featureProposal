# SSL Application PoC

PoC en **Spring Boot 3 + Java 21** para ejecutar un servicio web HTTPS, exponer documentación OpenAPI y ofrecer operaciones CLI.

## Qué hace este proyecto

1. Expone API HTTPS en `8443`.
2. Publica OpenAPI (`/api-docs`) y Swagger UI (`/swagger-ui.html`).
3. Implementa un CRUD sencillo de tareas usando **Hibernate (JPA)**.
4. Crea y versiona la tabla del CRUD con **Liquibase**.
5. Mantiene utilidades CLI para checks/renovación de certificados.

## Endpoints principales

### API base

- `GET /hello`

### CRUD tasks

- `POST /api/tasks`
- `GET /api/tasks`
- `GET /api/tasks/{id}`
- `PUT /api/tasks/{id}`
- `DELETE /api/tasks/{id}`

Payload ejemplo (create/update):

```json
{
  "title": "Mi primera tarea",
  "done": false
}
```

### OpenAPI

- JSON OpenAPI: `GET /api-docs`
- Swagger UI: `GET /swagger-ui.html`

## Base de datos y migraciones

- Motor por defecto: **H2** en archivo local `./target/db/sslapp`.
- Tabla CRUD principal: `task_item` (id UUID).
- Tabla comparativa en YAML: `archive` (mismos campos, id UUID).
- Migración Liquibase:
  - `src/main/resources/db/changelog/db.changelog-master.json`
  - `src/main/resources/db/changelog/changes/001-create-task-table.json`

Columnas creadas:

- `id` (PK UUID)
- `title` (varchar 120, not null)
- `done` (boolean, not null)
- `created_at` (timestamp)
- `updated_at` (timestamp)

## Configuración

Variables soportadas:

- `SSL_KEYSTORE_PASSWORD` (default: `changeit`)
- `APP_DATASOURCE_URL`
- `APP_DATASOURCE_USERNAME`
- `APP_DATASOURCE_PASSWORD`

## Ejecución

### Levantar servidor HTTPS

```bash
./mvnw spring-boot:run
```

### Probar endpoints

```bash
curl -k https://localhost:8443/hello
curl -k https://localhost:8443/api/tasks
curl -k https://localhost:8443/api-docs
```

### Ejecutar tests

```bash
./mvnw test
```

## Comandos CLI disponibles

- `--check-installation`
- `--setup`
- `--renew-certificate`

Ejemplos:

```bash
./mvnw spring-boot:run -Dspring-boot.run.arguments="--check-installation"
./mvnw spring-boot:run -Dspring-boot.run.arguments="--setup"
./mvnw spring-boot:run -Dspring-boot.run.arguments="--renew-certificate"
```

## Estructura relevante

- `src/main/java/com/example/ssl/crud/`: entidad, repositorio, servicio y controlador CRUD.
- `src/main/java/com/example/ssl/openapi/OpenApiConfiguration.java`: metadatos OpenAPI.
- `src/main/resources/db/changelog/`: migraciones Liquibase.
- `src/main/resources/application.yml`: SSL, datasource, JPA, Liquibase y springdoc.

## Estado PoC

- CRUD + OpenAPI + Liquibase: implementado.
- Check real de instalación BBDD e instalador interactivo CLI: pendiente de completar.
