package es.zaleos.certificate.renewer.spring.boot.runtime;

import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.core.PemTlsImportAndActivateService;
import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import es.zaleos.certificate.renewer.core.PemTlsValidationPolicy;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.event.TlsMaterialActivatedEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.ssl.PemSslBundleProperties;
import org.springframework.boot.autoconfigure.ssl.PropertiesSslBundle;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleRegistry;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

/**
 * Spring-layer facade over {@link PemTlsImportAndActivateService}.
 *
 * <p>Adds:
 * <ul>
 *   <li>JVM-local mutex — one active import at a time per application instance.</li>
 *   <li>Immediate SSL bundle reload via {@link SslBundleRegistry} (API path).</li>
 *   <li>{@link TlsMaterialActivatedEvent} publishing after every successful activation.</li>
 * </ul>
 */
public class TlsMaterialService {

    private static final Log LOG = LogFactory.getLog(TlsMaterialService.class);

    private final PemTlsImportAndActivateService coreService;
    private final TargetPathsResolver targetResolver;
    private final ValidationPolicyResolver policyResolver;
    private final CertificateRenewerProperties properties;
    private final Environment environment;
    private final ApplicationEventPublisher eventPublisher;
    private final SslBundleRegistry sslBundleRegistry; // nullable — injected as optional
    private final ReentrantLock importLock = new ReentrantLock();

    public TlsMaterialService(
            PemTlsImportAndActivateService coreService,
            TargetPathsResolver targetResolver,
            ValidationPolicyResolver policyResolver,
            CertificateRenewerProperties properties,
            Environment environment,
            ApplicationEventPublisher eventPublisher,
            SslBundleRegistry sslBundleRegistry
    ) {
        this.coreService = coreService;
        this.targetResolver = targetResolver;
        this.policyResolver = policyResolver;
        this.properties = properties;
        this.environment = environment;
        this.eventPublisher = eventPublisher;
        this.sslBundleRegistry = sslBundleRegistry;
    }

    /**
     * Imports and activates TLS material for the given target.
     *
     * @param targetName      named target (e.g. "web-server")
     * @param sourcePath      source directory or archive
     * @param externalKeyPath optional separate private key file
     * @param sourcePassword  password for source material
     * @param fromApi         when {@code true}, triggers an immediate {@link SslBundleRegistry} reload
     */
    public PemActivationResult importAndActivate(
            String targetName,
            Path sourcePath,
            Path externalKeyPath,
            char[] sourcePassword,
            boolean fromApi
    ) throws Exception {
        if (!importLock.tryLock()) {
            throw new IllegalStateException(
                    "Another import operation is already in progress. Only one concurrent import is allowed.");
        }
        try {
            PemTlsTargetPaths targetPaths = targetResolver.resolve(targetName);
            PemTlsValidationPolicy policy = policyResolver.resolve(targetName);
            char[] outputPassword = resolveOutputPassword();

            PemActivationResult result = coreService.importAndActivate(
                    sourcePath,
                    externalKeyPath,
                    sourcePassword,
                    targetPaths,
                    outputPassword,
                    properties.getOutput().isWriteUnencryptedPrivateKey(),
                    policy
            );

            if (fromApi && sslBundleRegistry != null && "web-server".equals(targetName)) {
                reloadSslBundle(targetPaths);
            }

            eventPublisher.publishEvent(new TlsMaterialActivatedEvent(this, targetName, result));
            return result;
        } finally {
            importLock.unlock();
        }
    }

    /**
     * Restores the previous material from {@code .bak} files for the given target.
     */
    public void rollback(String targetName) throws Exception {
        rollback(targetName, false);
    }

    /**
     * Restores the previous material from {@code .bak} files for the given target.
     *
     * @param immediateReload when {@code true}, reloads the active Spring SSL bundle before returning
     */
    public void rollback(String targetName, boolean immediateReload) throws Exception {
        if (!importLock.tryLock()) {
            throw new IllegalStateException(
                    "An import operation is in progress. Cannot rollback while an import is running.");
        }
        try {
            PemTlsTargetPaths targetPaths = targetResolver.resolve(targetName);
            boolean restored = false;
            for (Path activePath : targetPaths.activePaths()) {
                Path bakPath = Path.of(activePath + ".bak");
                if (Files.exists(bakPath)) {
                    Files.move(bakPath, activePath, StandardCopyOption.REPLACE_EXISTING);
                    restored = true;
                    LOG.info("Rolled back: " + activePath);
                }
            }
            if (!restored) {
                throw new IllegalStateException("No backup files found for target '" + targetName + "'.");
            }
            if (immediateReload && sslBundleRegistry != null && "web-server".equals(targetName)) {
                reloadSslBundle(targetPaths);
            }
            eventPublisher.publishEvent(new TlsMaterialActivatedEvent(this, targetName, null));
        } finally {
            importLock.unlock();
        }
    }

    private void reloadSslBundle(PemTlsTargetPaths targetPaths) {
        if (!(this.sslBundleRegistry instanceof SslBundles sslBundles)) {
            throw new IllegalStateException("Immediate SSL reload requires an SslBundleRegistry that also exposes SslBundles");
        }

        String bundleName = this.environment.getProperty("server.ssl.bundle");
        if (!StringUtils.hasText(bundleName)) {
            throw new IllegalStateException("Immediate SSL reload requires server.ssl.bundle to be configured");
        }
        if (targetPaths.fullChainPath() == null || targetPaths.privateKeyPath() == null) {
            throw new IllegalStateException("Immediate SSL reload requires both fullchain and private key paths");
        }

        SslBundle currentBundle = sslBundles.getBundle(bundleName);
        LOG.info("Requesting immediate SSL bundle reload for target 'web-server' using bundle '" + bundleName + "'.");
        PemSslBundleProperties bundleProperties = createUpdatedPemBundleProperties(bundleName, currentBundle, targetPaths);
        SslBundle updatedBundle = PropertiesSslBundle.get(bundleProperties);
        this.sslBundleRegistry.updateBundle(bundleName, updatedBundle);
    }

    private PemSslBundleProperties createUpdatedPemBundleProperties(
            String bundleName,
            SslBundle currentBundle,
            PemTlsTargetPaths targetPaths
    ) {
        PemSslBundleProperties bundleProperties = new PemSslBundleProperties();
        bundleProperties.setProtocol(currentBundle.getProtocol());
        bundleProperties.getOptions().setCiphers(SslOptions.asSet(currentBundle.getOptions().getCiphers()));
        bundleProperties.getOptions().setEnabledProtocols(
                SslOptions.asSet(currentBundle.getOptions().getEnabledProtocols()));
        bundleProperties.getKey().setAlias(currentBundle.getKey().getAlias());
        bundleProperties.getKey().setPassword(currentBundle.getKey().getPassword());

        String prefix = "spring.ssl.bundle.pem." + bundleName + ".";
        bundleProperties.getKeystore().setType(this.environment.getProperty(prefix + "keystore.type"));
        bundleProperties.getKeystore().setCertificate(asFileLocation(targetPaths.fullChainPath()));
        bundleProperties.getKeystore().setPrivateKey(asFileLocation(targetPaths.privateKeyPath()));
        bundleProperties.getKeystore().setPrivateKeyPassword(resolvePrivateKeyPassword(prefix));
        setVerifyKeysIfConfigured(bundleProperties.getKeystore(), prefix + "keystore.verify-keys");

        copyStoreIfConfigured(bundleProperties.getTruststore(), prefix + "truststore.");
        return bundleProperties;
    }

    private void copyStoreIfConfigured(PemSslBundleProperties.Store store, String prefix) {
        store.setType(this.environment.getProperty(prefix + "type"));
        store.setCertificate(this.environment.getProperty(prefix + "certificate"));
        store.setPrivateKey(this.environment.getProperty(prefix + "private-key"));
        store.setPrivateKeyPassword(this.environment.getProperty(prefix + "private-key-password"));
        setVerifyKeysIfConfigured(store, prefix + "verify-keys");
    }

    private void setVerifyKeysIfConfigured(PemSslBundleProperties.Store store, String propertyName) {
        String verifyKeys = this.environment.getProperty(propertyName);
        if (StringUtils.hasText(verifyKeys)) {
            store.setVerifyKeys(Boolean.parseBoolean(verifyKeys));
        }
    }

    private String resolvePrivateKeyPassword(String prefix) {
        String bundlePrivateKeyPassword = this.environment.getProperty(prefix + "keystore.private-key-password");
        if (StringUtils.hasText(bundlePrivateKeyPassword)) {
            return bundlePrivateKeyPassword;
        }
        return StringUtils.hasText(this.properties.getOutput().getPrivateKeyPassword())
                ? this.properties.getOutput().getPrivateKeyPassword()
                : null;
    }

    private String asFileLocation(Path path) {
        return path.toAbsolutePath().toUri().toString();
    }

    private char[] resolveOutputPassword() {
        String pwd = properties.getOutput().getPrivateKeyPassword();
        return (pwd != null && !pwd.isBlank()) ? pwd.toCharArray() : new char[0];
    }
}
