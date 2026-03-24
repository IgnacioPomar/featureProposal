package es.zaleos.certificate.renewer.core;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Summary of a PEM import and activation operation.
 *
 * <p>The core activation flow writes the active PEM pair consumed by runtime SSL integrations:
 * {@code fullchain.pem} and {@code private-key.pem}.
 */
public record PemActivationResult(
        Path sourcePath,
        Path fullChainPath,
        Path privateKeyPath,
        Instant expirationDate
) {
}
