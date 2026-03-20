# Checklist PoC

## SSL Web
- [x] Servidor HTTPS en `8443`.
- [x] Keystore configurado en `application.yml`.
- [ ] Endpoint de health SSL validado con certificado real de entorno.

## CLI paralelo al servidor
- [x] Modo CLI sin web server (`WebApplicationType.NONE`).
- [ ] Documentar comandos de arranque concurrente (web + CLI separado).

## Check de instalación BBDD
- [ ] Configurar datasource real (driver + URL + credenciales).
- [ ] Verificar conexión a BBDD desde `--check-installation`.
- [ ] Verificar tablas obligatorias.
- [ ] Verificar columnas obligatorias.
- [ ] Devolver exit code de error cuando falle un chequeo.

## Instalador (bonus)
- [ ] Flujo interactivo para pedir parámetros.
- [ ] Validar parámetros en el momento.
- [ ] Crear esquema/tablas si faltan.
- [ ] Cargar datos iniciales opcionales.

## Calidad
- [ ] Tests unitarios para validaciones de instalación.
- [ ] Tests de integración contra BBDD temporal (Testcontainers/H2 según objetivo).
- [ ] Documentación de uso y troubleshooting.
