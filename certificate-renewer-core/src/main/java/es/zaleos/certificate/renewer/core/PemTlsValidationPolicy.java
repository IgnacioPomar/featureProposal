package es.zaleos.certificate.renewer.core;

import java.security.cert.X509Certificate;

/**
 * Effective validation policy applied before TLS material is activated.
 * <p>
 * {@code expectedRootCa}: when non-null, the candidate chain root must match this certificate.
 * This check runs even when the current material is a bootstrap placeholder, enforcing the NENA PCA
 * trust anchor from the very first real import.
 */
public record PemTlsValidationPolicy(
        boolean sameRootCa,
        boolean sameChain,
        boolean sameSubject,
        boolean sameSan,
        boolean samePublicKey,
        String minimumKeyAlgorithm,
        Integer minimumKeySize,
        X509Certificate expectedRootCa
) {
}
