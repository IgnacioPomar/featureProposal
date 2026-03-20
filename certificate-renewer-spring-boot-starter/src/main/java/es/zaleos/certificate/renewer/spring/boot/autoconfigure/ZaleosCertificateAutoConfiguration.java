package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import es.zaleos.certificate.renewer.core.PemTlsImportAndActivateService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Auto-configuration entry point for the Zaleos certificate starter.
 */
@AutoConfiguration
@ConditionalOnClass(PemTlsImportAndActivateService.class)
@ConditionalOnProperty(prefix = "zaleos.certificate", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ZaleosCertificateProperties.class)
public class ZaleosCertificateAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PemTlsImportAndActivateService pemTlsImportAndActivateService() {
        return new PemTlsImportAndActivateService();
    }

    @Bean
    @ConditionalOnMissingBean
    public ZaleosCertificateTargetResolver zaleosCertificateTargetResolver(
            Environment environment,
            ZaleosCertificateProperties properties
    ) {
        return new ZaleosCertificateTargetResolver(environment, properties);
    }
}
