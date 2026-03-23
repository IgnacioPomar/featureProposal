package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

/**
 * Thrown when a JWS token fails signature or certificate chain verification.
 */
public class JwsVerificationException extends RuntimeException {

    public JwsVerificationException(String message) {
        super(message);
    }

    public JwsVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
