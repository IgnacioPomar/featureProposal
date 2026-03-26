package es.zaleos.ssl.web;

import static org.assertj.core.api.Assertions.assertThat;

import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.core.PemTlsImportAndActivateService;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.runtime.TargetPathsResolver;
import es.zaleos.certificate.renewer.spring.boot.runtime.TlsMaterialService;
import es.zaleos.certificate.renewer.spring.boot.runtime.ValidationPolicyResolver;
import es.zaleos.ssl.cli.TlsMaterialImporter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;

class TlsMaterialPageControllerTests {

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();

    @Test
    void pageShowsUnifiedControlsAndRollbackWhenBackupExists(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("web-server");
        generator.generate(targetDir, new char[0], "current.installation.local", true);
        Files.copy(targetDir.resolve("fullchain.pem"), targetDir.resolve("fullchain.pem.bak"));

        TlsMaterialPageController controller = createController(targetDir, null, new CapturingTlsMaterialImporter(targetDir));

        String html = controller.page(request(), null).getBody();

        assertThat(html).contains("Certificate Renewal Demo");
        assertThat(html).contains("Authentication");
        assertThat(html).contains("Use incorrect certificate");
        assertThat(html).contains("Destination target");
        assertThat(html).contains("Import from directory");
        assertThat(html).contains("Import uploaded PEM");
        assertThat(html).contains("Rollback current backup");
        assertThat(html).contains("Configured validation policy");
        assertThat(html).contains("same-root-ca");
        assertThat(html).contains("Scenario guide for generated test certificates");
        assertThat(html).contains("Recommended scenarios per target");
        assertThat(html).contains("jwt-signer");
        assertThat(html).contains("jwt-verifier");
        assertThat(html).contains("180d-pem");
        assertThat(html).contains("Bootstrap placeholder certificates ending in");
        assertThat(html).doesNotContain("JWS maintenance");
    }

    @Test
    void noAuthFolderImportUsesLocalImporterFlow(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("web-server");
        generator.generate(targetDir, new char[0], "before.installation.local", true);

        CapturingTlsMaterialImporter importer = new CapturingTlsMaterialImporter(targetDir);
        importer.setUpdatedCommonName("after.installation.local");
        TlsMaterialPageController controller = createController(targetDir, null, importer);

        String html = controller.submit(
                request(),
                null,
                "no-auth",
                false,
                "import-folder",
                tempDir.resolve("source").toString(),
                "",
                emptyFile("fullchain"),
                emptyFile("privateKey")
        ).getBody();

        assertThat(importer.lastTargetName).isEqualTo("web-server");
        assertThat(importer.lastImmediateReload).isTrue();
        assertThat(html).contains("same Spring-managed import flow as the CLI command");
        assertThat(html).contains("before.installation.local");
        assertThat(html).contains("after.installation.local");
    }

    @Test
    void remoteFolderImportUsesRequestedAuthModeAndWrongCertificateToggle(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("web-server");
        generator.generate(targetDir, new char[0], "before.installation.local", true);

        RecordingMaintenanceJwsRequestService maintenanceService = new RecordingMaintenanceJwsRequestService();
        TlsMaterialPageController controller = createController(
                targetDir,
                maintenanceService,
                new CapturingTlsMaterialImporter(targetDir)
        );

        String html = controller.submit(
                request(),
                null,
                "jwt",
                true,
                "import-folder",
                tempDir.resolve("source").toString(),
                "",
                emptyFile("fullchain"),
                emptyFile("privateKey")
        ).getBody();

        assertThat(maintenanceService.lastAuthMode).isEqualTo(MaintenanceJwsRequestService.AuthMode.JWT);
        assertThat(maintenanceService.lastUsedWrongCertificate).isTrue();
        assertThat(html).contains("Remote maintenance response");
        assertThat(html).contains("JWT");
        assertThat(html).contains("Detected change");
    }

    @Test
    void rollbackUsesLocalRollbackWhenBackupExists(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("web-server");
        generator.generate(targetDir, new char[0], "rolled-back.installation.local", true);
        Files.copy(targetDir.resolve("fullchain.pem"), targetDir.resolve("fullchain.pem.bak"));
        Files.copy(targetDir.resolve("private-key.pem"), targetDir.resolve("private-key.pem.bak"));
        generator.generate(targetDir, new char[0], "current.installation.local", true);

        RecordingTlsMaterialService rollbackService = new RecordingTlsMaterialService(targetDir);
        TlsMaterialPageController controller = createController(
                targetDir,
                new RecordingMaintenanceJwsRequestService(),
                new CapturingTlsMaterialImporter(targetDir),
                rollbackService
        );

        String html = controller.submit(
                request(),
                null,
                "no-auth",
                false,
                "rollback",
                "",
                "",
                emptyFile("fullchain"),
                emptyFile("privateKey")
        ).getBody();

        assertThat(rollbackService.lastRollbackTarget).isEqualTo("web-server");
        assertThat(html).contains("Rollback completed");
        assertThat(html).contains("rolled-back.installation.local");
    }

    private TlsMaterialPageController createController(
            Path targetDir,
            RecordingMaintenanceJwsRequestService maintenanceService,
            CapturingTlsMaterialImporter importer
    ) {
        return createController(targetDir, maintenanceService, importer, new RecordingTlsMaterialService(targetDir));
    }

    private TlsMaterialPageController createController(
            Path targetDir,
            RecordingMaintenanceJwsRequestService maintenanceService,
            CapturingTlsMaterialImporter importer,
            RecordingTlsMaterialService tlsMaterialService
    ) {
        CertificateRenewerProperties properties = new CertificateRenewerProperties();
        properties.getTargets().computeIfAbsent("web-server", ignored -> new CertificateRenewerProperties.Target())
                .setOutputDir(targetDir.toString());

        TargetPathsResolver targetResolver = new TargetPathsResolver(new MockEnvironment(), properties);
        TlsMaterialPageController controller = new TlsMaterialPageController(
                importer,
                tlsMaterialService,
                maintenanceService == null ? new RecordingMaintenanceJwsRequestService() : maintenanceService,
                targetResolver,
                properties
        );
        ReflectionTestUtils.setField(controller, "defaultTargetName", "web-server");
        return controller;
    }

    private MockMultipartFile emptyFile(String name) {
        return new MockMultipartFile(name, new byte[0]);
    }

    private MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("localhost");
        request.setServerPort(8443);
        request.setRequestURI("/certificate-renewal");
        return request;
    }

    private final class CapturingTlsMaterialImporter extends TlsMaterialImporter {

        private final Path targetDir;
        private boolean lastImmediateReload;
        private String lastTargetName;
        private String updatedCommonName = "after.installation.local";

        private CapturingTlsMaterialImporter(Path targetDir) {
            super(new MockEnvironment(), null, new CertificateRenewerProperties());
            this.targetDir = targetDir;
        }

        private void setUpdatedCommonName(String updatedCommonName) {
            this.updatedCommonName = updatedCommonName;
        }

        @Override
        public PemActivationResult importAndActivate(
                String targetName,
                Path sourceDirectory,
                Path externalKeyPath,
                char[] externalMaterialPassword,
                boolean immediateReload
        ) throws Exception {
            this.lastTargetName = targetName;
            this.lastImmediateReload = immediateReload;
            generator.generate(this.targetDir, new char[0], this.updatedCommonName, true);
            return new PemActivationResult(
                    sourceDirectory,
                    this.targetDir.resolve("fullchain.pem"),
                    this.targetDir.resolve("private-key.pem"),
                    Instant.parse("2035-01-01T00:00:00Z")
            );
        }
    }

    private static final class RecordingMaintenanceJwsRequestService extends MaintenanceJwsRequestService {

        private AuthMode lastAuthMode;
        private boolean lastUsedWrongCertificate;

        private RecordingMaintenanceJwsRequestService() {
            super(
                    new TargetPathsResolver(new MockEnvironment(), new CertificateRenewerProperties()),
                    new CertificateRenewerProperties(),
                    new MockEnvironment()
            );
        }

        @Override
        public InvocationResult importFromFolder(
                String baseUrl,
                String targetName,
                String sourceDirectory,
                String password,
                AuthMode authMode,
                boolean useWrongCertificate
        ) {
            this.lastAuthMode = authMode;
            this.lastUsedWrongCertificate = useWrongCertificate;
            return new InvocationResult(
                    baseUrl + "/internal/certificates/import-from-folder",
                    401,
                    java.util.Map.of("target", targetName),
                    "{\"error\":\"invalid token\"}",
                    authMode,
                    useWrongCertificate
            );
        }
    }

    private static final class RecordingTlsMaterialService extends TlsMaterialService {

        private final Path targetDir;
        private String lastRollbackTarget;

        private RecordingTlsMaterialService(Path targetDir) {
            super(
                    new PemTlsImportAndActivateService(),
                    new TargetPathsResolver(new MockEnvironment(), new CertificateRenewerProperties()),
                    new ValidationPolicyResolver(new CertificateRenewerProperties()),
                    new CertificateRenewerProperties(),
                    new MockEnvironment(),
                    event -> { },
                    null
            );
            this.targetDir = targetDir;
        }

        @Override
        public void rollback(String targetName, boolean immediateReload) throws Exception {
            this.lastRollbackTarget = targetName;
            Files.copy(this.targetDir.resolve("fullchain.pem.bak"), this.targetDir.resolve("fullchain.pem"),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Files.copy(this.targetDir.resolve("private-key.pem.bak"), this.targetDir.resolve("private-key.pem"),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
