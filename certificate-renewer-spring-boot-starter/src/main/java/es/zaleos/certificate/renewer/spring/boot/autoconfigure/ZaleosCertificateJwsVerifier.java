package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import java.util.Map;

/**
 * Verifies JWS compact serializations against the currently installed TLS material.
 *
 * <p>When the JWS header contains an {@code x5c} parameter, the full certificate chain
 * is validated against the configured PCA trust anchor before checking the signature.
 * When {@code x5c} is absent, verification falls back to the currently installed
 * certificate's public key.
 *
 * <p>Implementations reload their internal trust material automatically on
 * {@link TlsMaterialActivatedEvent}.
 */
public interface ZaleosCertificateJwsVerifier {

    /**
     * Verifies the JWS. Throws {@link JwsVerificationException} if the chain or signature is invalid.
     */
    void verify(String jwsCompact);

    /**
     * Verifies the JWS and returns the decoded payload claims.
     *
     * @throws JwsVerificationException if the chain or signature is invalid
     */
    Map<String, Object> verifyAndExtractClaims(String jwsCompact);
}
