package es.zaleos.certificate.renewer.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class InstallationTlsMaterialGeneratorTests {

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
    private final PemTlsMaterialImporter importer = new PemTlsMaterialImporter();

    @Test
    void generatedInstallationCertificateContainsDemoSubjectAndLocalhostSans(@TempDir Path tempDir) throws Exception {
        Path outputDir = tempDir.resolve("installation");
        generator.generate(outputDir, new char[0], "service.installation.local", true);

        X509Certificate certificate = importer.importFrom(outputDir, null, new char[0]).leafCertificate();

        assertThat(certificate.getSubjectX500Principal().getName())
                .contains("CN=service.installation.local")
                .contains("OU=Demo Installation TLS")
                .contains("O=Zaleos");
        assertThat(certificate.getSubjectAlternativeNames())
                .isNotNull()
                .satisfies(subjectAlternativeNames -> {
                    assertThat(hasSubjectAlternativeName(subjectAlternativeNames, 2, "localhost")).isTrue();
                    assertThat(hasSubjectAlternativeName(subjectAlternativeNames, 7, "127.0.0.1")).isTrue();
                    assertThat(hasSubjectAlternativeName(subjectAlternativeNames, 7, "0:0:0:0:0:0:0:1")).isTrue();
                });
    }

    private boolean hasSubjectAlternativeName(
            Collection<? extends List<?>> subjectAlternativeNames,
            int type,
            String value
    ) {
        return subjectAlternativeNames.stream()
                .filter(entry -> entry.size() >= 2)
                .anyMatch(entry -> type == ((Number) entry.get(0)).intValue() && value.equals(entry.get(1)));
    }
}
