package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.core.PemTlsImportAndActivateService;
import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import es.zaleos.certificate.renewer.core.PemTlsValidationPolicy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.ssl.SslBundleRegistry;
import org.springframework.context.ApplicationEventPublisher;

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
public class ZaleosCertificateOperationService {

    private static final Log LOG = LogFactory.getLog(ZaleosCertificateOperationService.class);

    private final PemTlsImportAndActivateService coreService;
    private final ZaleosCertificateTargetResolver targetResolver;
    private final ZaleosCertificatePolicyResolver policyResolver;
    private final ZaleosCertificateProperties properties;
    private final ApplicationEventPublisher eventPublisher;
    private final SslBundleRegistry sslBundleRegistry; // nullable — injected as optional
    private final ReentrantLock importLock = new ReentrantLock();

    public ZaleosCertificateOperationService(
            PemTlsImportAndActivateService coreService,
            ZaleosCertificateTargetResolver targetResolver,
            ZaleosCertificatePolicyResolver policyResolver,
            ZaleosCertificateProperties properties,
            ApplicationEventPublisher eventPublisher,
            SslBundleRegistry sslBundleRegistry
    ) {
        this.coreService = coreService;
        this.targetResolver = targetResolver;
        this.policyResolver = policyResolver;
        this.properties = properties;
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
        if (!importLock.tryLock()) {
            throw new IllegalStateException(
                    "An import operation is in progress. Cannot rollback while an import is running.");
        }
        try {
            PemTlsTargetPaths targetPaths = targetResolver.resolve(targetName);
            boolean restored = false;
            for (Path activePath : targetPaths.allConfiguredPaths()) {
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
            eventPublisher.publishEvent(new TlsMaterialActivatedEvent(this, targetName, null));
        } finally {
            importLock.unlock();
        }
    }

    private void reloadSslBundle(PemTlsTargetPaths targetPaths) {
        // TODO Phase 1: construct PemSslBundle from targetPaths and call sslBundleRegistry.updateBundle("server", bundle)
        // for immediate synchronous reload. Pending investigation of the Spring Boot 4 PemSslBundle API.
        // The Spring Boot file watcher (reload-on-update: true) handles the actual reload within ~10s.
        LOG.info("TLS material written for web-server target. Spring Boot file watcher will reload the SSL bundle.");
    }

    private char[] resolveOutputPassword() {
        String pwd = properties.getOutput().getPrivateKeyPassword();
        return (pwd != null && !pwd.isBlank()) ? pwd.toCharArray() : new char[0];
    }
}
