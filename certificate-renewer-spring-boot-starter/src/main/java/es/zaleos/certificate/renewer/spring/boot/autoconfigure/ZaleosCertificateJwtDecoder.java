package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Spring Security {@link JwtDecoder} backed by {@link ZaleosCertificateJwsVerifier}.
 *
 * <p>Registered as a bean when {@code spring-security-oauth2-resource-server} is on the classpath.
 * Applications using Spring Security resource server configuration can use this decoder
 * with no additional verification code.
 *
 * <p>Reloads automatically via {@link TlsMaterialActivatedEvent} handled by the underlying verifier.
 */
public class ZaleosCertificateJwtDecoder implements JwtDecoder {

    private final ZaleosCertificateJwsVerifier verifier;

    public ZaleosCertificateJwtDecoder(ZaleosCertificateJwsVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        Map<String, Object> claims;
        try {
            claims = verifier.verifyAndExtractClaims(token);
        } catch (JwsVerificationException e) {
            throw new JwtException("JWS verification failed: " + e.getMessage(), e);
        }

        String[] parts = token.split("\\.");
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "RS256"); // default; real value is in the JWS header already verified

        Instant issuedAt = extractInstant(claims, "iat");
        Instant expiresAt = extractInstant(claims, "exp");

        return new Jwt(token, issuedAt, expiresAt, headers, claims);
    }

    private Instant extractInstant(Map<String, Object> claims, String claim) {
        Object value = claims.get(claim);
        if (value instanceof Long l) {
            return Instant.ofEpochSecond(l);
        }
        if (value instanceof Number n) {
            return Instant.ofEpochSecond(n.longValue());
        }
        return null;
    }
}
