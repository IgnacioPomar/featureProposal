package es.zaleos.certificate.renewer.core;

/**
 * Raised when candidate TLS material does not satisfy the configured validation policy.
 */
public class PemTlsValidationException extends IllegalArgumentException {

    public PemTlsValidationException(String message) {
        super(message);
    }
}
