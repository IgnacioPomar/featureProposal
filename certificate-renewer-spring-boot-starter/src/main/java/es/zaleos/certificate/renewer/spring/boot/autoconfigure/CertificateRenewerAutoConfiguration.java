package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import es.zaleos.certificate.renewer.core.PemTlsCurrentMaterialLoader;
import es.zaleos.certificate.renewer.core.PemTlsImportAndActivateService;
import es.zaleos.certificate.renewer.spring.boot.bootstrap.InstallationTlsMaterialBootstrapper;
import es.zaleos.certificate.renewer.spring.boot.rest.TlsMaterialMaintenanceController;
import es.zaleos.certificate.renewer.spring.boot.runtime.TargetPathsResolver;
import es.zaleos.certificate.renewer.spring.boot.runtime.TlsMaterialService;
import es.zaleos.certificate.renewer.spring.boot.runtime.ValidationPolicyResolver;
import es.zaleos.certificate.renewer.spring.boot.security.InstalledTlsMaterialJwsVerifier;
import es.zaleos.certificate.renewer.spring.boot.security.TlsMaterialJwsVerifier;
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
@EnableConfigurationProperties(CertificateRenewerProperties.class)
public class CertificateRenewerAutoConfiguration {

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
    public TargetPathsResolver zaleosCertificateTargetResolver(
            Environment environment,
            CertificateRenewerProperties properties
    ) {
        return new TargetPathsResolver(environment, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public ValidationPolicyResolver zaleosCertificatePolicyResolver(
            CertificateRenewerProperties properties
    ) {
        return new ValidationPolicyResolver(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public InstallationTlsMaterialGenerator installationTlsMaterialGenerator() {
        return new InstallationTlsMaterialGenerator();
    }

    @Bean
    @ConditionalOnMissingBean
    public TlsMaterialService zaleosCertificateOperationService(
            PemTlsImportAndActivateService coreService,
            TargetPathsResolver targetResolver,
            ValidationPolicyResolver policyResolver,
            CertificateRenewerProperties properties,
            ApplicationEventPublisher eventPublisher,
            ObjectProvider<SslBundleRegistry> sslBundleRegistryProvider
    ) {
        return new TlsMaterialService(
                coreService, targetResolver, policyResolver, properties, eventPublisher,
                sslBundleRegistryProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public InstallationTlsMaterialBootstrapper zaleosCertificateBootstrapInitializer(
            Environment environment,
            CertificateRenewerProperties properties,
            TargetPathsResolver targetResolver,
            InstallationTlsMaterialGenerator generator
    ) {
        return new InstallationTlsMaterialBootstrapper(environment, properties, targetResolver, generator);
    }

    @Bean
    @ConditionalOnMissingBean
    public TlsMaterialJwsVerifier zaleosCertificateJwsVerifier(
            TargetPathsResolver targetResolver,
            CertificateRenewerProperties properties,
            PemTlsCurrentMaterialLoader materialLoader
    ) {
        return new InstalledTlsMaterialJwsVerifier(targetResolver, properties, materialLoader);
    }

    @Bean
    @ConditionalOnProperty(prefix = "zaleos.certificate.maintenance", name = "enabled", havingValue = "true")
    @ConditionalOnMissingBean
    public TlsMaterialMaintenanceController zaleosCertificateMaintenanceController(
            TlsMaterialService operationService,
            TlsMaterialJwsVerifier jwsVerifier,
            CertificateRenewerProperties properties
    ) {
        return new TlsMaterialMaintenanceController(operationService, jwsVerifier, properties);
    }
}
