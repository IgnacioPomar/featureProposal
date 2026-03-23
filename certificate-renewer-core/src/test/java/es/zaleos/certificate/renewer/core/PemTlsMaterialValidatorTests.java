package es.zaleos.certificate.renewer.core;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PemTlsMaterialValidatorTests {

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
    private final PemTlsCurrentMaterialLoader loader = new PemTlsCurrentMaterialLoader();
    private final PemTlsMaterialValidator validator = new PemTlsMaterialValidator();

    @Test
    void failsWhenSamePublicKeyIsRequiredAndCandidateUsesDifferentKey(@TempDir Path tempDir) throws Exception {
        Path currentDir = tempDir.resolve("current");
        Path candidateDir = tempDir.resolve("candidate");

        generator.generate(currentDir, new char[0], "service-a.local", true);
        generator.generate(candidateDir, new char[0], "service-b.local", true);

        PemTlsMaterial current = loader.load(toPaths(currentDir)).orElseThrow();
        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                false, false, false, false, true, null, null, null
        );

        assertThatThrownBy(() -> validator.validate(candidate, current, policy))
                .isInstanceOf(PemTlsValidationException.class)
                .hasMessageContaining("same-public-key");
    }

    @Test
    void allowsFirstRealImportWhenCurrentMaterialIsBootstrapPlaceholder(@TempDir Path tempDir) throws Exception {
        Path currentDir = tempDir.resolve("current");
        Path candidateDir = tempDir.resolve("candidate");

        generator.generate(currentDir, new char[0], "demo-web-server.installation.local", true);
        generator.generate(candidateDir, new char[0], "service.example.com", true);

        PemTlsMaterial current = loader.load(toPaths(currentDir)).orElseThrow();
        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                true, true, true, true, true, "RSA", 2048, null
        );

        validator.validate(candidate, current, policy);
    }

    private PemTlsTargetPaths toPaths(Path dir) {
        return new PemTlsTargetPaths(
                dir.resolve("certificate.pem"),
                dir.resolve("chain.pem"),
                dir.resolve("fullchain.pem"),
                dir.resolve("private-key.pem")
        );
    }
}
