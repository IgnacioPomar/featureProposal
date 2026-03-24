package es.zaleos.ssl;

import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(properties = {
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.datasource.url=jdbc:h2:mem:sslapp;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
class SslApplicationTests {

    private static final Path TEST_SSL_DIR = createTestSslDirectory();

    @DynamicPropertySource
    static void registerDynamicProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.ssl.bundle.pem.server.keystore.certificate",
                () -> "file:" + TEST_SSL_DIR.resolve("fullchain.pem"));
        registry.add("spring.ssl.bundle.pem.server.keystore.private-key",
                () -> "file:" + TEST_SSL_DIR.resolve("private-key.pem"));
        registry.add("zaleos.certificate.targets.web-server.output-dir", TEST_SSL_DIR::toString);
    }

    @Test
    void contextLoads() {
        // Validates Spring context startup, including generated OpenAPI API wiring.
    }

    private static Path createTestSslDirectory() {
        try {
            Path sslDir = Files.createTempDirectory("ssl-application-test-ssl-");
            new InstallationTlsMaterialGenerator().generate(sslDir, new char[0], "ssl-application-test.local", true);
            return sslDir;
        } catch (Exception exception) {
            throw new IllegalStateException("Failed to prepare test SSL material", exception);
        }
    }
}
