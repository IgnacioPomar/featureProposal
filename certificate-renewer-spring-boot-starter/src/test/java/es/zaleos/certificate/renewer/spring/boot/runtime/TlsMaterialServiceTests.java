package es.zaleos.certificate.renewer.spring.boot.runtime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.core.PemTlsImportAndActivateService;
import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import es.zaleos.certificate.renewer.core.PemTlsValidationPolicy;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.event.TlsMaterialActivatedEvent;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.ssl.PemSslBundleProperties;
import org.springframework.boot.autoconfigure.ssl.PropertiesSslBundle;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleRegistry;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.env.MockEnvironment;

class TlsMaterialServiceTests {

    @Test
    void publishesActivationEventAfterSuccessfulImport(@TempDir Path tempDir) throws Exception {
        Path outputDir = tempDir.resolve("web-server");
        PemActivationResult expectedResult = new PemActivationResult(
                tempDir.resolve("source"),
                outputDir.resolve("certificate.pem"),
                outputDir.resolve("fullchain.pem"),
                outputDir.resolve("private-key.pem"),
                Instant.parse("2030-01-01T00:00:00Z")
        );
        List<Object> events = new CopyOnWriteArrayList<>();

        TlsMaterialService service = createService(
                tempDir,
                new MockEnvironment(),
                event -> events.add(event),
                null,
                new StubCoreService((sourcePath, externalKeyPath, sourcePassword, targetPaths,
                        outputPassword, allowUnencryptedPrivateKey, validationPolicy) -> expectedResult)
        );

        PemActivationResult actualResult = service.importAndActivate(
                "web-server",
                tempDir.resolve("source"),
                null,
                new char[0],
                false
        );

        assertThat(actualResult).isEqualTo(expectedResult);
        assertThat(events).hasSize(1);
        assertThat(events.getFirst()).isInstanceOf(TlsMaterialActivatedEvent.class);
        TlsMaterialActivatedEvent event = (TlsMaterialActivatedEvent) events.getFirst();
        assertThat(event.getTargetName()).isEqualTo("web-server");
        assertThat(event.getResult()).isEqualTo(expectedResult);
    }

    @Test
    void rollbackRestoresBackupFilesAndPublishesActivationEvent(@TempDir Path tempDir) throws Exception {
        Path outputDir = tempDir.resolve("web-server");
        Files.createDirectories(outputDir);
        Files.writeString(outputDir.resolve("fullchain.pem"), "new-fullchain");
        Files.writeString(outputDir.resolve("private-key.pem"), "new-private-key");
        Files.writeString(outputDir.resolve("fullchain.pem.bak"), "old-fullchain");
        Files.writeString(outputDir.resolve("private-key.pem.bak"), "old-private-key");

        List<Object> events = new CopyOnWriteArrayList<>();
        TlsMaterialService service = createService(
                tempDir,
                new MockEnvironment(),
                event -> events.add(event),
                null,
                new StubCoreService((sourcePath, externalKeyPath, sourcePassword, targetPaths,
                        outputPassword, allowUnencryptedPrivateKey, validationPolicy) -> {
                    throw new UnsupportedOperationException("Not used in rollback test");
                })
        );

        service.rollback("web-server");

        assertThat(Files.readString(outputDir.resolve("fullchain.pem"))).isEqualTo("old-fullchain");
        assertThat(Files.readString(outputDir.resolve("private-key.pem"))).isEqualTo("old-private-key");
        assertThat(outputDir.resolve("fullchain.pem.bak")).doesNotExist();
        assertThat(outputDir.resolve("private-key.pem.bak")).doesNotExist();
        assertThat(events).hasSize(1);
        assertThat(((TlsMaterialActivatedEvent) events.getFirst()).getTargetName()).isEqualTo("web-server");
    }

    @Test
    void rejectsConcurrentImportsWhileAnotherImportIsInProgress(@TempDir Path tempDir) throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        TlsMaterialService service = createService(
                tempDir,
                new MockEnvironment(),
                event -> { },
                null,
                new StubCoreService((sourcePath, externalKeyPath, sourcePassword, targetPaths,
                        outputPassword, allowUnencryptedPrivateKey, validationPolicy) -> {
                    entered.countDown();
                    if (!release.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to release the blocked import");
                    }
                    return new PemActivationResult(
                            sourcePath,
                            targetPaths.certificatePath(),
                            targetPaths.fullChainPath(),
                            targetPaths.privateKeyPath(),
                            Instant.now()
                    );
                })
        );

        ExecutorService executorService = Executors.newSingleThreadExecutor();
        try {
            Future<PemActivationResult> runningImport = executorService.submit(() -> service.importAndActivate(
                    "web-server",
                    tempDir.resolve("source"),
                    null,
                    new char[0],
                    false
            ));

            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();

            assertThatThrownBy(() -> service.importAndActivate(
                    "web-server",
                    tempDir.resolve("another-source"),
                    null,
                    new char[0],
                    false
            ))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Another import operation is already in progress");

            release.countDown();
            runningImport.get(5, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            executorService.shutdownNow();
        }
    }

    @Test
    void apiImportReloadsTheConfiguredSslBundleImmediately(@TempDir Path tempDir) throws Exception {
        Path outputDir = tempDir.resolve("web-server");
        InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
        generator.generate(outputDir, new char[0], "initial.installation.local", true);

        DefaultSslBundleRegistry sslBundleRegistry = new DefaultSslBundleRegistry();
        sslBundleRegistry.registerBundle("server", createPemBundle(outputDir));

        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("server.ssl.bundle", "server");

        TlsMaterialService service = createService(
                tempDir,
                environment,
                event -> { },
                sslBundleRegistry,
                new StubCoreService((sourcePath, externalKeyPath, sourcePassword, targetPaths,
                        outputPassword, allowUnencryptedPrivateKey, validationPolicy) -> {
                    generator.generate(outputDir, new char[0], "updated.installation.local", true);
                    return new PemActivationResult(
                            sourcePath,
                            targetPaths.certificatePath(),
                            targetPaths.fullChainPath(),
                            targetPaths.privateKeyPath(),
                            Instant.parse("2035-01-01T00:00:00Z")
                    );
                })
        );

        service.importAndActivate("web-server", tempDir.resolve("source"), null, new char[0], true);

        assertThat(readLeafSubject(sslBundleRegistry.getBundle("server")))
                .contains("CN=updated.installation.local");
    }

    @Test
    void apiRollbackReloadsTheConfiguredSslBundleImmediately(@TempDir Path tempDir) throws Exception {
        Path outputDir = tempDir.resolve("web-server");
        InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
        generator.generate(outputDir, new char[0], "current.installation.local", true);
        Files.copy(outputDir.resolve("fullchain.pem"), outputDir.resolve("fullchain.pem.bak"));
        Files.copy(outputDir.resolve("private-key.pem"), outputDir.resolve("private-key.pem.bak"));
        generator.generate(outputDir, new char[0], "next.installation.local", true);

        DefaultSslBundleRegistry sslBundleRegistry = new DefaultSslBundleRegistry();
        sslBundleRegistry.registerBundle("server", createPemBundle(outputDir));

        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("server.ssl.bundle", "server");

        TlsMaterialService service = createService(
                tempDir,
                environment,
                event -> { },
                sslBundleRegistry,
                new StubCoreService((sourcePath, externalKeyPath, sourcePassword, targetPaths,
                        outputPassword, allowUnencryptedPrivateKey, validationPolicy) -> {
                    throw new UnsupportedOperationException("Not used in rollback test");
                })
        );

        service.rollback("web-server", true);

        assertThat(readLeafSubject(sslBundleRegistry.getBundle("server")))
                .contains("CN=current.installation.local");
    }

    private TlsMaterialService createService(
            Path tempDir,
            MockEnvironment environment,
            ApplicationEventPublisher eventPublisher,
            SslBundleRegistry sslBundleRegistry,
            PemTlsImportAndActivateService coreService
    ) {
        CertificateRenewerProperties properties = new CertificateRenewerProperties();
        properties.getOutput().setWriteUnencryptedPrivateKey(true);
        properties.getTargets().computeIfAbsent("web-server", ignored -> new CertificateRenewerProperties.Target())
                .setOutputDir(tempDir.resolve("web-server").toString());

        TargetPathsResolver targetResolver =
                new TargetPathsResolver(environment, properties);
        ValidationPolicyResolver policyResolver = new ValidationPolicyResolver(properties);

        return new TlsMaterialService(
                coreService,
                targetResolver,
                policyResolver,
                properties,
                environment,
                eventPublisher,
                sslBundleRegistry
        );
    }

    private SslBundle createPemBundle(Path outputDir) {
        PemSslBundleProperties bundleProperties = new PemSslBundleProperties();
        bundleProperties.getKeystore().setCertificate(outputDir.resolve("fullchain.pem").toUri().toString());
        bundleProperties.getKeystore().setPrivateKey(outputDir.resolve("private-key.pem").toUri().toString());
        return PropertiesSslBundle.get(bundleProperties);
    }

    private String readLeafSubject(SslBundle sslBundle) throws Exception {
        KeyStore keyStore = sslBundle.getStores().getKeyStore();
        assertThat(keyStore).isNotNull();
        String alias = keyStore.aliases().nextElement();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        assertThat(certificate).isNotNull();
        return certificate.getSubjectX500Principal().getName();
    }

    private static final class StubCoreService extends PemTlsImportAndActivateService {

        private final ImportHandler handler;

        private StubCoreService(ImportHandler handler) {
            this.handler = handler;
        }

        @Override
        public PemActivationResult importAndActivate(
                Path sourcePath,
                Path externalPrivateKeyPath,
                char[] sourcePassword,
                PemTlsTargetPaths targetPaths,
                char[] outputPrivateKeyPassword,
                boolean allowUnencryptedPrivateKey,
                PemTlsValidationPolicy validationPolicy
        ) throws Exception {
            return handler.handle(
                    sourcePath,
                    externalPrivateKeyPath,
                    sourcePassword,
                    targetPaths,
                    outputPrivateKeyPassword,
                    allowUnencryptedPrivateKey,
                    validationPolicy
            );
        }
    }

    @FunctionalInterface
    private interface ImportHandler {
        PemActivationResult handle(
                Path sourcePath,
                Path externalPrivateKeyPath,
                char[] sourcePassword,
                PemTlsTargetPaths targetPaths,
                char[] outputPrivateKeyPassword,
                boolean allowUnencryptedPrivateKey,
                PemTlsValidationPolicy validationPolicy
        ) throws Exception;
    }
}
