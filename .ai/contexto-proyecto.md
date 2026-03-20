# Contexto del proyecto (PoC SSL + CLI + instalación)

## Objetivo general
Proyecto de pruebas en Java/Spring Boot que debe cubrir:

1. Servicio web bajo SSL.
2. Tareas CLI ejecutables sin arrancar el servidor web.
3. Comprobación de instalación desde CLI:
- conexión a BBDD,
- tablas requeridas,
- campos requeridos por tabla.
4. Bonus: instalador interactivo que pida datos, valide, cree estructura BBDD y opcionalmente cargue datos iniciales.

## Estado actual observado
- Hay endpoint web `/hello`.
- SSL está configurado en `application.yml` (puerto 8443 + keystore PKCS12).
- Existen comandos CLI:
- `--check-installation` (actualmente placeholder, sin chequeos reales de BBDD).
- `--setup` (actualmente placeholder).
- `--renew-certificate` (flujo real de importación/rotación de certificados).
- Hay test de endpoint `/hello` y arranque de contexto.

## Criterios mínimos de aceptación para esta PoC

1. `--check-installation` devuelve código de salida != 0 si falla cualquiera de:
- conexión a BBDD,
- tabla obligatoria inexistente,
- columna obligatoria inexistente.
2. `--check-installation` imprime informe claro por cada chequeo.
3. Ejecución CLI no levanta servidor web.
4. Arranque normal sí levanta servidor HTTPS correctamente.
5. Existe documentación de uso (comandos y propiedades requeridas).

## Convenciones de trabajo
- Evitar hardcode de secretos.
- Preferir propiedades/env vars para credenciales.
- Mantener lógica de validación desacoplada y testeable.
