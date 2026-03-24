package es.zaleos.certificate.renewer.spring.boot.runtime;

import es.zaleos.certificate.renewer.core.PemTlsValidationPolicy;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

/**
 * Resolves the effective validation policy for a target by merging global defaults
 * with per-target overrides and loading any referenced certificate resources.
 */
public class ValidationPolicyResolver {

    private static final Log LOG = LogFactory.getLog(ValidationPolicyResolver.class);

    private final CertificateRenewerProperties properties;
    private final ResourceLoader resourceLoader;

    public ValidationPolicyResolver(CertificateRenewerProperties properties) {
        this.properties = properties;
        this.resourceLoader = new DefaultResourceLoader();
    }

    public PemTlsValidationPolicy resolve(String targetName) {
        CertificateRenewerProperties.Policy defaults = properties.getPolicy();
        CertificateRenewerProperties.Target target = properties.getTargets().get(targetName);
        CertificateRenewerProperties.TargetPolicy overrides = target != null ? target.getPolicy() : null;

        String expectedRootCaLocation = overrides != null && overrides.getExpectedRootCa() != null
                ? overrides.getExpectedRootCa()
                : defaults.getExpectedRootCa();

        return new PemTlsValidationPolicy(
                overrideBoolean(defaults.isSameRootCa(), overrides == null ? null : overrides.getSameRootCa()),
                overrideBoolean(defaults.isSameChain(), overrides == null ? null : overrides.getSameChain()),
                overrideBoolean(defaults.isSameSubject(), overrides == null ? null : overrides.getSameSubject()),
                overrideBoolean(defaults.isSameSan(), overrides == null ? null : overrides.getSameSan()),
                overrideBoolean(defaults.isSamePublicKey(), overrides == null ? null : overrides.getSamePublicKey()),
                overrideString(defaults.getMinimumKeyAlgorithm(), overrides == null ? null : overrides.getMinimumKeyAlgorithm()),
                overrideInteger(defaults.getMinimumKeySize(), overrides == null ? null : overrides.getMinimumKeySize()),
                loadCertificate(expectedRootCaLocation)
        );
    }

    private X509Certificate loadCertificate(String resourceLocation) {
        if (resourceLocation == null || resourceLocation.isBlank()) {
            return null;
        }
        try {
            Resource resource = resourceLoader.getResource(resourceLocation);
            if (!resource.exists()) {
                LOG.warn("expectedRootCa resource not found: " + resourceLocation + " — PCA trust anchor will not be enforced");
                return null;
            }
            try (InputStream inputStream = resource.getInputStream()) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                return (X509Certificate) factory.generateCertificate(inputStream);
            }
        } catch (Exception exception) {
            LOG.warn("Failed to load expectedRootCa from " + resourceLocation + ": " + exception.getMessage());
            return null;
        }
    }

    private boolean overrideBoolean(boolean defaultValue, Boolean overrideValue) {
        return overrideValue == null ? defaultValue : overrideValue;
    }

    private String overrideString(String defaultValue, String overrideValue) {
        return overrideValue == null ? defaultValue : overrideValue;
    }

    private Integer overrideInteger(Integer defaultValue, Integer overrideValue) {
        return overrideValue == null ? defaultValue : overrideValue;
    }
}
