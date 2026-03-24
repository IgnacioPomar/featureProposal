package es.zaleos.ssl.web;

import static org.assertj.core.api.Assertions.assertThat;

import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.runtime.TargetPathsResolver;
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
    void pageShowsCurrentCertificateAndUploadForm(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("target");
        generator.generate(targetDir, new char[0], "current.installation.local", true);

        CapturingTlsMaterialImporter importer = new CapturingTlsMaterialImporter(targetDir);
        TlsMaterialPageController controller = createController(targetDir, importer);

        String html = controller.page(request()).getBody();

        assertThat(html).contains("Variables affecting the certificate and its renewal");
        assertThat(html).contains("Current certificate");
        assertThat(html).contains("Upload PEM files");
        assertThat(html).doesNotContain("Copy link for another browser");
        assertThat(html).contains("<h2>Import</h2>");
        assertThat(html).doesNotContain("Comparison after POST");
        assertThat(html).doesNotContain("Refresh page");
        assertThat(indexOf(html, "<h2>Import</h2>"))
                .isLessThan(indexOf(html, "Variables affecting the certificate and its renewal"));
    }

    @Test
    void directoryImportExplainsFreshBrowserVerificationAndHidesCurrentSection(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("target");
        generator.generate(targetDir, new char[0], "before.installation.local", true);

        CapturingTlsMaterialImporter importer = new CapturingTlsMaterialImporter(targetDir);
        importer.setUpdatedCommonName("after.installation.local");
        TlsMaterialPageController controller = createController(targetDir, importer);

        String html = controller.importTlsMaterial(request(), tempDir.resolve("source").toString(), "").getBody();

        assertThat(importer.lastImmediateReload).isTrue();
        assertThat(html).contains("another browser, a private window, or a fresh TLS client connection");
        assertThat(html).contains("Certificate comparison");
        assertThat(html).contains("before.installation.local");
        assertThat(html).contains("after.installation.local");
        assertThat(html).doesNotContain("Variables affecting the certificate and its renewal");
        assertThat(html).doesNotContain("Refresh page");
        assertThat(indexOf(html, "<h2>Verification</h2>"))
                .isLessThan(indexOf(html, "<h2>Certificate comparison</h2>"));
    }

    @Test
    void uploadImportsPemFilesAndUsesImmediateReload(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("target");
        generator.generate(targetDir, new char[0], "before-upload.installation.local", true);

        Path uploadSource = tempDir.resolve("upload-source");
        generator.generate(uploadSource, new char[0], "uploaded.installation.local", true);

        CapturingTlsMaterialImporter importer = new CapturingTlsMaterialImporter(targetDir);
        TlsMaterialPageController controller = createController(targetDir, importer);

        MockMultipartFile fullchain = new MockMultipartFile(
                "fullchain",
                "fullchain.pem",
                "application/x-pem-file",
                Files.readAllBytes(uploadSource.resolve("fullchain.pem"))
        );
        MockMultipartFile privateKey = new MockMultipartFile(
                "privateKey",
                "private-key.pem",
                "application/x-pem-file",
                Files.readAllBytes(uploadSource.resolve("private-key.pem"))
        );

        String html = controller.uploadTlsMaterial(request(), fullchain, privateKey, "").getBody();

        assertThat(importer.lastImmediateReload).isTrue();
        assertThat(importer.lastImportedFullchainPem).contains("BEGIN CERTIFICATE");
        assertThat(importer.lastImportedPrivateKeyPem).contains("PRIVATE KEY");
        assertThat(html).contains("Upload import completed");
        assertThat(html).contains("uploaded.installation.local");
        assertThat(html).contains("Copy link for another browser");
        assertThat(indexOf(html, "<h2>Verification</h2>"))
                .isLessThan(indexOf(html, "<h2>Certificate comparison</h2>"));
    }

    private int indexOf(String html, String needle) {
        return html.indexOf(needle);
    }

    private TlsMaterialPageController createController(Path targetDir, CapturingTlsMaterialImporter importer) {
        CertificateRenewerProperties properties = new CertificateRenewerProperties();
        properties.getTargets().computeIfAbsent("web-server", ignored -> new CertificateRenewerProperties.Target())
                .setOutputDir(targetDir.toString());
        TargetPathsResolver targetResolver = new TargetPathsResolver(new MockEnvironment(), properties);
        TlsMaterialPageController controller = new TlsMaterialPageController(importer, targetResolver);
        ReflectionTestUtils.setField(controller, "targetName", "web-server");
        return controller;
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
        private String lastImportedFullchainPem;
        private String lastImportedPrivateKeyPem;
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
                Path sourceDirectory,
                Path externalKeyPath,
                char[] externalMaterialPassword,
                boolean immediateReload
        ) throws Exception {
            this.lastImmediateReload = immediateReload;
            Path uploadedFullchain = sourceDirectory.resolve("fullchain.pem");
            Path uploadedPrivateKey = sourceDirectory.resolve("private-key.pem");
            if (Files.exists(uploadedFullchain) && Files.exists(uploadedPrivateKey)) {
                this.lastImportedFullchainPem = Files.readString(uploadedFullchain);
                this.lastImportedPrivateKeyPem = Files.readString(uploadedPrivateKey);
                Files.createDirectories(this.targetDir);
                Files.copy(uploadedFullchain, this.targetDir.resolve("fullchain.pem"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                Files.copy(uploadedPrivateKey, this.targetDir.resolve("private-key.pem"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } else {
                generator.generate(this.targetDir, new char[0], this.updatedCommonName, true);
            }
            return new PemActivationResult(
                    sourceDirectory,
                    this.targetDir.resolve("fullchain.pem"),
                    this.targetDir.resolve("private-key.pem"),
                    Instant.parse("2035-01-01T00:00:00Z")
            );
        }
    }
}
