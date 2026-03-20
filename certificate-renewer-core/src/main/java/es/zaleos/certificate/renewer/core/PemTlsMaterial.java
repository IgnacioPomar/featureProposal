package es.zaleos.certificate.renewer.core;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * Normalized TLS material ready to be written as PEM files.
 */
public record PemTlsMaterial(
        Path sourcePath,
        X509Certificate leafCertificate,
        PrivateKey privateKey,
        List<X509Certificate> orderedChain
) {

    public PemTlsMaterial {
        orderedChain = List.copyOf(orderedChain);
    }

    public Instant expirationDate() {
        return leafCertificate.getNotAfter().toInstant();
    }
}
