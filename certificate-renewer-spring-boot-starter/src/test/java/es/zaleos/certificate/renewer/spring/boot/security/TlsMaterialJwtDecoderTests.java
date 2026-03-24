package es.zaleos.certificate.renewer.spring.boot.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

class TlsMaterialJwtDecoderTests {

    @Test
    void decodeReturnsJwtWithStandardTimeClaims() {
        TlsMaterialJwsVerifier verifier = new TlsMaterialJwsVerifier() {
            @Override
            public void verify(String jwsCompact) {
            }

            @Override
            public Map<String, Object> verifyAndExtractClaims(String jwsCompact) {
                return Map.of("sub", "alice", "iat", 10L, "exp", 20L);
            }
        };
        TlsMaterialJwtDecoder decoder = new TlsMaterialJwtDecoder(verifier);

        Jwt jwt = decoder.decode("header.payload.signature");

        assertThat(jwt.getSubject()).isEqualTo("alice");
        assertThat(jwt.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(10L));
        assertThat(jwt.getExpiresAt()).isEqualTo(Instant.ofEpochSecond(20L));
    }

    @Test
    void decodeWrapsVerifierFailuresAsJwtException() {
        TlsMaterialJwsVerifier verifier = new TlsMaterialJwsVerifier() {
            @Override
            public void verify(String jwsCompact) {
                throw new JwsVerificationException("invalid signature");
            }

            @Override
            public Map<String, Object> verifyAndExtractClaims(String jwsCompact) {
                throw new JwsVerificationException("invalid signature");
            }
        };
        TlsMaterialJwtDecoder decoder = new TlsMaterialJwtDecoder(verifier);

        assertThatThrownBy(() -> decoder.decode("header.payload.signature"))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("invalid signature");
    }
}
