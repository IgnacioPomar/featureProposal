package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import es.zaleos.certificate.renewer.spring.boot.security.TlsMaterialJwtDecoder;
import es.zaleos.certificate.renewer.spring.boot.security.TlsMaterialJwsVerifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Conditionally registers the Spring Security {@link JwtDecoder} adapter.
 * Only active when {@code spring-security-oauth2-resource-server} is on the classpath.
 */
@AutoConfiguration(after = CertificateRenewerAutoConfiguration.class)
@ConditionalOnClass(JwtDecoder.class)
public class CertificateRenewerSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    public TlsMaterialJwtDecoder zaleosCertificateJwtDecoder(TlsMaterialJwsVerifier verifier) {
        return new TlsMaterialJwtDecoder(verifier);
    }
}
