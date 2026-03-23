package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class ZaleosCertificateBootstrapInitializerTests {

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
}
