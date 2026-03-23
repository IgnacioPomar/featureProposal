package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import es.zaleos.certificate.renewer.core.PemTlsMaterial;
import es.zaleos.certificate.renewer.core.PemTlsMaterialImporter;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class ZaleosCertificateBootstrapInitializerTests {

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
    private final PemTlsMaterialImporter importer = new PemTlsMaterialImporter();
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ZaleosCertificateAutoConfiguration.class));

    @Test
    void createsInstallationMaterialWhenWebServerPemFilesAreMissing(@TempDir Path tempDir) {
        Path fullChain = tempDir.resolve("fullchain.pem");
        Path privateKey = tempDir.resolve("private-key.pem");

        contextRunner
                .withPropertyValues(
                        "spring.application.name=test-app",
                        "server.ssl.bundle=server",
                        "spring.ssl.bundle.pem.server.keystore.certificate=file:" + fullChain,
                        "spring.ssl.bundle.pem.server.keystore.private-key=file:" + privateKey,
                        "zaleos.certificate.output.write-unencrypted-private-key=true"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(Files.exists(fullChain)).isTrue();
                    assertThat(Files.exists(privateKey)).isTrue();
                });
    }

    @Test
    void doesNotOverwriteUsableWebServerMaterialWhenOnlyIfMissingIsTrue(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("ssl");
        generator.generate(targetDir, new char[0], "existing.local", true);
        String originalFullChain = Files.readString(targetDir.resolve("fullchain.pem"));
        String originalPrivateKey = Files.readString(targetDir.resolve("private-key.pem"));

        contextRunner
                .withPropertyValues(
                        "spring.application.name=test-app",
                        "server.ssl.bundle=server",
                        "spring.ssl.bundle.pem.server.keystore.certificate=file:" + targetDir.resolve("fullchain.pem"),
                        "spring.ssl.bundle.pem.server.keystore.private-key=file:" + targetDir.resolve("private-key.pem"),
                        "zaleos.certificate.bootstrap.only-if-missing=true",
                        "zaleos.certificate.output.write-unencrypted-private-key=true"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(Files.readString(targetDir.resolve("fullchain.pem"))).isEqualTo(originalFullChain);
                    assertThat(Files.readString(targetDir.resolve("private-key.pem"))).isEqualTo(originalPrivateKey);
                });
    }

    @Test
    void createsInstallationMaterialForExplicitBootstrapEnabledTarget(@TempDir Path tempDir) {
        Path jwtTargetDir = tempDir.resolve("jwt-signer");

        contextRunner
                .withPropertyValues(
                        "spring.application.name=test-app",
                        "zaleos.certificate.output.write-unencrypted-private-key=true",
                        "zaleos.certificate.targets.jwt-signer.output-dir=" + jwtTargetDir,
                        "zaleos.certificate.targets.jwt-signer.bootstrap-enabled=true"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(jwtTargetDir.resolve("fullchain.pem")).isRegularFile();
                    assertThat(jwtTargetDir.resolve("private-key.pem")).isRegularFile();

                    PemTlsMaterial material = importer.importFrom(jwtTargetDir, null, new char[0]);
                    assertThat(material.leafCertificate().getSubjectX500Principal().getName())
                            .contains("CN=test-app-jwt-signer.installation.local");
                });
    }
}
