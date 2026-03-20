package es.zaleos.certificate.renewer.core;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Summary of a PEM import and activation operation.
 */
public record PemActivationResult(
        Path sourcePath,
        Path certificatePath,
        Path fullChainPath,
        Path privateKeyPath,
        Instant expirationDate
) {
}
