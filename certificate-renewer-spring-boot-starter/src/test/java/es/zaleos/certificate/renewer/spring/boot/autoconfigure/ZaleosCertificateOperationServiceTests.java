package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.core.PemTlsImportAndActivateService;
import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import es.zaleos.certificate.renewer.core.PemTlsValidationPolicy;
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
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.env.MockEnvironment;

class ZaleosCertificateOperationServiceTests {

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

        ZaleosCertificateOperationService service = createService(
                tempDir,
                event -> events.add(event),
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
        ZaleosCertificateOperationService service = createService(
                tempDir,
                event -> events.add(event),
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

        ZaleosCertificateOperationService service = createService(
                tempDir,
                event -> { },
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

    private ZaleosCertificateOperationService createService(
            Path tempDir,
            ApplicationEventPublisher eventPublisher,
            PemTlsImportAndActivateService coreService
    ) {
        ZaleosCertificateProperties properties = new ZaleosCertificateProperties();
        properties.getOutput().setWriteUnencryptedPrivateKey(true);
        properties.getTargets().computeIfAbsent("web-server", ignored -> new ZaleosCertificateProperties.Target())
                .setOutputDir(tempDir.resolve("web-server").toString());

        ZaleosCertificateTargetResolver targetResolver =
                new ZaleosCertificateTargetResolver(new MockEnvironment(), properties);
        ZaleosCertificatePolicyResolver policyResolver = new ZaleosCertificatePolicyResolver(properties);

        return new ZaleosCertificateOperationService(
                coreService,
                targetResolver,
                policyResolver,
                properties,
                eventPublisher,
                null
        );
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
