package es.zaleos.certificate.renewer.spring.boot.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.mock.env.MockEnvironment;

class InstallationTlsEnvironmentPostProcessorTests {

    @Test
    void createsPemFilesAtConfiguredSslBundleLocationAfterConfigDataIsApplied(@TempDir Path tempDir) throws Exception {
        Path configDir = tempDir.resolve("config");
        Files.createDirectories(configDir);
        Path sslDir = tempDir.resolve("ssl");
        Path applicationYaml = configDir.resolve("application.yml");
        Files.writeString(applicationYaml, """
                spring:
                  application:
                    name: test-app
                  ssl:
                    bundle:
                      pem:
                        server:
                          keystore:
                            certificate: file:%s/fullchain.pem
                            private-key: file:%s/private-key.pem
                server:
                  ssl:
                    bundle: server
                zaleos:
                  certificate:
                    output:
                      write-unencrypted-private-key: true
                """.formatted(sslDir, sslDir));

        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("spring.config.location", applicationYaml.toUri().toString());

        ConfigDataEnvironmentPostProcessor.applyTo(environment);
        new InstallationTlsEnvironmentPostProcessor().postProcessEnvironment(environment, new SpringApplication());

        assertThat(sslDir.resolve("fullchain.pem")).isRegularFile();
        assertThat(sslDir.resolve("private-key.pem")).isRegularFile();
    }
}
