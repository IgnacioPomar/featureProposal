package es.zaleos.certificate.renewer.core;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Pending specification tests for importer behavior that remains documented in the
 * technical specification but is not implemented yet.
 */
@Disabled("Enable these tests when the remaining importer requirements from the specification are implemented.")
class PemTlsMaterialImporterPendingSpecificationTests {

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
    private final PemTlsMaterialImporter importer = new PemTlsMaterialImporter();

    @Test
    void importFailsWithExplicitAmbiguityErrorWhenMultipleCandidateSetsRemain(@TempDir Path tempDir) throws Exception {
        Path sourceA = tempDir.resolve("source-a");
        Path sourceB = tempDir.resolve("source-b");
        generator.generate(sourceA, new char[0], "service-a.local", true);
        generator.generate(sourceB, new char[0], "service-b.local", true);

        Path combined = tempDir.resolve("combined");
        Files.createDirectories(combined);
        Files.copy(sourceA.resolve("fullchain.pem"), combined.resolve("service-a-fullchain.pem"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(sourceA.resolve("private-key.pem"), combined.resolve("service-a-private-key.pem"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(sourceB.resolve("fullchain.pem"), combined.resolve("service-b-fullchain.pem"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(sourceB.resolve("private-key.pem"), combined.resolve("service-b-private-key.pem"), StandardCopyOption.REPLACE_EXISTING);

        assertThatThrownBy(() -> importer.importFrom(combined, null, new char[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ambiguous");
    }
}
