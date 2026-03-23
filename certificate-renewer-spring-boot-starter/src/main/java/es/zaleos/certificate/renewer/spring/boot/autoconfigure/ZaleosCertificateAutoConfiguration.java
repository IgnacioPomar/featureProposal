package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import es.zaleos.certificate.renewer.core.PemTlsCurrentMaterialLoader;
import es.zaleos.certificate.renewer.core.PemTlsImportAndActivateService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundleRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
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
    public PemTlsCurrentMaterialLoader pemTlsCurrentMaterialLoader() {
        return new PemTlsCurrentMaterialLoader();
    }

    @Bean
    @ConditionalOnMissingBean
    public ZaleosCertificateTargetResolver zaleosCertificateTargetResolver(
            Environment environment,
            ZaleosCertificateProperties properties
    ) {
        return new ZaleosCertificateTargetResolver(environment, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZaleosCertificatePolicyResolver zaleosCertificatePolicyResolver(
            ZaleosCertificateProperties properties
    ) {
        return new ZaleosCertificatePolicyResolver(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public InstallationTlsMaterialGenerator installationTlsMaterialGenerator() {
        return new InstallationTlsMaterialGenerator();
    }

    @Bean
    @ConditionalOnMissingBean
    public ZaleosCertificateOperationService zaleosCertificateOperationService(
            PemTlsImportAndActivateService coreService,
            ZaleosCertificateTargetResolver targetResolver,
            ZaleosCertificatePolicyResolver policyResolver,
            ZaleosCertificateProperties properties,
            ApplicationEventPublisher eventPublisher,
            ObjectProvider<SslBundleRegistry> sslBundleRegistryProvider
    ) {
        return new ZaleosCertificateOperationService(
                coreService, targetResolver, policyResolver, properties, eventPublisher,
                sslBundleRegistryProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public ZaleosCertificateBootstrapInitializer zaleosCertificateBootstrapInitializer(
            Environment environment,
            ZaleosCertificateProperties properties,
            ZaleosCertificateTargetResolver targetResolver,
            InstallationTlsMaterialGenerator generator
    ) {
        return new ZaleosCertificateBootstrapInitializer(environment, properties, targetResolver, generator);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZaleosCertificateJwsVerifier zaleosCertificateJwsVerifier(
            ZaleosCertificateTargetResolver targetResolver,
            ZaleosCertificateProperties properties,
            PemTlsCurrentMaterialLoader materialLoader
    ) {
        return new DefaultZaleosCertificateJwsVerifier(targetResolver, properties, materialLoader);
    }

    @Bean
    @ConditionalOnProperty(prefix = "zaleos.certificate.maintenance", name = "enabled", havingValue = "true")
    @ConditionalOnMissingBean
    public ZaleosCertificateMaintenanceController zaleosCertificateMaintenanceController(
            ZaleosCertificateOperationService operationService,
            ZaleosCertificateJwsVerifier jwsVerifier,
            ZaleosCertificateProperties properties
    ) {
        return new ZaleosCertificateMaintenanceController(operationService, jwsVerifier, properties);
    }
}
