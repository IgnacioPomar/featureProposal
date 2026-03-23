package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

class ZaleosCertificateJwtDecoderTests {

    @Test
    void decodeReturnsJwtWithStandardTimeClaims() {
        ZaleosCertificateJwsVerifier verifier = new ZaleosCertificateJwsVerifier() {
            @Override
            public void verify(String jwsCompact) {
            }

            @Override
            public Map<String, Object> verifyAndExtractClaims(String jwsCompact) {
                return Map.of("sub", "alice", "iat", 10L, "exp", 20L);
            }
        };
        ZaleosCertificateJwtDecoder decoder = new ZaleosCertificateJwtDecoder(verifier);

        Jwt jwt = decoder.decode("header.payload.signature");

        assertThat(jwt.getSubject()).isEqualTo("alice");
        assertThat(jwt.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(10L));
        assertThat(jwt.getExpiresAt()).isEqualTo(Instant.ofEpochSecond(20L));
    }

    @Test
    void decodeWrapsVerifierFailuresAsJwtException() {
        ZaleosCertificateJwsVerifier verifier = new ZaleosCertificateJwsVerifier() {
            @Override
            public void verify(String jwsCompact) {
                throw new JwsVerificationException("invalid signature");
            }

            @Override
            public Map<String, Object> verifyAndExtractClaims(String jwsCompact) {
                throw new JwsVerificationException("invalid signature");
            }
        };
        ZaleosCertificateJwtDecoder decoder = new ZaleosCertificateJwtDecoder(verifier);

        assertThatThrownBy(() -> decoder.decode("header.payload.signature"))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("invalid signature");
    }
}
