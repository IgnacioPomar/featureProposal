# `certificate-renewer-spring-boot-starter` Class Map

This file describes the Java packages and classes that make up the Maven artifact
`es.zaleos:certificate-renewer-spring-boot-starter`.

Unless explicitly marked otherwise, classes under `runtime`, `bootstrap`, and `rest`
are internal starter implementation details and are not intended to be used directly
by application code.

## Package Overview

| Package | Purpose |
|---|---|
| `es.zaleos.certificate.renewer.spring.boot.autoconfigure` | Spring Boot auto-configuration entry points and public configuration properties |
| `es.zaleos.certificate.renewer.spring.boot.bootstrap` | Bootstrap logic that creates installation TLS material when no usable PEM files exist |
| `es.zaleos.certificate.renewer.spring.boot.event` | Spring events emitted by the starter |
| `es.zaleos.certificate.renewer.spring.boot.rest` | HTTP endpoints exposed by the starter |
| `es.zaleos.certificate.renewer.spring.boot.runtime` | Internal runtime services and resolvers used by the starter |
| `es.zaleos.certificate.renewer.spring.boot.security` | JWS/JWT verification and Spring Security integration |

## `es.zaleos.certificate.renewer.spring.boot.autoconfigure`

| Class | For what it is used | Intended use | Activation / conditions |
|---|---|---|---|
| `CertificateRenewerAutoConfiguration` | Registers the starter's core beans: resolvers, TLS service, bootstrap components, JWS verifier, and optional maintenance controller. | Public Spring Boot entry point. Applications usually use it indirectly through auto-configuration. | Active only when `PemTlsImportAndActivateService` is on the classpath and `zaleos.certificate.enabled=true` or missing. |
| `CertificateRenewerProperties` | Binds all `zaleos.certificate.*` configuration, including bootstrap, maintenance, output, policy, and targets. | Public configuration model. Safe for application use. | Always bindable when the starter auto-configuration is active. |
| `CertificateRenewerSecurityAutoConfiguration` | Registers the `JwtDecoder` adapter backed by the starter's JWS verifier. | Public Spring Boot entry point. Applications usually use it indirectly. | Active only when Spring Security `JwtDecoder` is on the classpath. |

## `es.zaleos.certificate.renewer.spring.boot.bootstrap`

| Class | For what it is used | Intended use | Activation / conditions |
|---|---|---|---|
| `InstallationTlsEnvironmentPostProcessor` | Early startup hook that creates installation PEM files before Spring Boot initializes the configured SSL bundle and file watcher. | Internal starter implementation. | Runs during environment processing. It only generates material when `zaleos.certificate.enabled=true`, `zaleos.certificate.bootstrap.enabled=true`, and the web-server PEM files are missing or unusable. |
| `InstallationTlsMaterialBootstrapper` | Bootstrap component that ensures usable installation TLS material exists once the Spring context is being created. It supports the default web-server target and explicit targets with bootstrap enabled. | Internal starter implementation. | Registered by auto-configuration. It becomes a no-op when bootstrap is disabled or when usable material already exists and `bootstrap.only-if-missing=true`. |

## `es.zaleos.certificate.renewer.spring.boot.event`

| Class | For what it is used | Intended use | Activation / conditions |
|---|---|---|---|
| `TlsMaterialActivatedEvent` | Spring `ApplicationEvent` published after TLS material activation or rollback so dependent components can reload certificates or keys. | Public extension point. Applications may listen to this event. | Published by `TlsMaterialService` after successful activation and rollback operations. |

## `es.zaleos.certificate.renewer.spring.boot.rest`

| Class | For what it is used | Intended use | Activation / conditions |
|---|---|---|---|
| `TlsMaterialMaintenanceController` | Exposes HTTP endpoints for maintenance operations: import from folder, import from upload, and rollback. It authenticates requests using the starter's JWS verification flow. | Internal starter implementation exposed as a web service. Applications normally consume the endpoints, not the controller class itself. | Registered only when `zaleos.certificate.maintenance.enabled=true`. Each endpoint can also be disabled individually through its own `zaleos.certificate.maintenance.*.enabled` property. |

## `es.zaleos.certificate.renewer.spring.boot.runtime`

| Class | For what it is used | Intended use | Activation / conditions |
|---|---|---|---|
| `TargetPathsResolver` | Resolves the filesystem paths for the PEM files of a named target, using either explicit target configuration or Spring SSL bundle defaults. | Internal starter implementation. | Registered as a bean by `CertificateRenewerAutoConfiguration`. |
| `TlsMaterialService` | Orchestrates import, activation, rollback, event publication, and integration with Spring SSL bundle reload behavior. | Internal starter implementation. This is the main runtime service behind the starter. | Registered as a bean by `CertificateRenewerAutoConfiguration`. |
| `ValidationPolicyResolver` | Builds the effective validation policy for a target by merging global defaults and per-target overrides, including optional trust-anchor loading. | Internal starter implementation. | Registered as a bean by `CertificateRenewerAutoConfiguration`. |

## `es.zaleos.certificate.renewer.spring.boot.security`

| Class | For what it is used | Intended use | Activation / conditions |
|---|---|---|---|
| `InstalledTlsMaterialJwsVerifier` | Concrete implementation of the starter JWS verifier. It validates compact JWS tokens, supports `x5c` chains, and reloads trust material on `TlsMaterialActivatedEvent`. | Internal implementation of a public contract. Applications should prefer the `TlsMaterialJwsVerifier` interface. | Registered as a bean by `CertificateRenewerAutoConfiguration` when no custom `TlsMaterialJwsVerifier` bean exists. |
| `JwsVerificationException` | Signals JWS signature, certificate-chain, or token-validation failures. | Public exception type for callers that use the verifier directly. | Thrown by the verifier and reused by the REST maintenance layer. |
| `TlsMaterialJwsVerifier` | Public contract used to verify JWS compact tokens and extract claims using the installed TLS material. | Public extension and integration point. Safe for application use. | Registered by `CertificateRenewerAutoConfiguration` when no custom verifier bean exists. |
| `TlsMaterialJwtDecoder` | Spring Security `JwtDecoder` adapter backed by `TlsMaterialJwsVerifier`. | Public integration type, although most applications use it indirectly through Spring Security auto-configuration. | Registered by `CertificateRenewerSecurityAutoConfiguration` only when `JwtDecoder` is on the classpath and no custom `JwtDecoder` bean exists. |
