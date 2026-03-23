package es.zaleos.certificate.renewer.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.Certificate;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Pending specification tests for importer behavior that is documented in the
 * technical specification but not implemented yet.
 */
@Disabled("Enable these tests when the remaining importer requirements from the specification are implemented.")
class PemTlsMaterialImporterPendingSpecificationTests {

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
    private final PemTlsMaterialImporter importer = new PemTlsMaterialImporter();

    @Test
    void importFromDirectPkcs12File_returnsValidMaterial(@TempDir Path tempDir) throws Exception {
        Path sourceDir = tempDir.resolve("source");
        generator.generate(sourceDir, new char[0], "service.local", true);
        PemTlsMaterial generated = importer.importFrom(sourceDir, null, new char[0]);

        char[] password = "pkcs12-password".toCharArray();
        Path p12Path = tempDir.resolve("material.p12");
        writePkcs12(p12Path, generated, password);

        PemTlsMaterial material = importer.importFrom(p12Path, null, password);

        assertThat(material.leafCertificate().getSubjectX500Principal())
                .isEqualTo(generated.leafCertificate().getSubjectX500Principal());
    }

    @Test
    void importFromTarGzArchive_returnsValidMaterial(@TempDir Path tempDir) throws Exception {
        Path sourceDir = tempDir.resolve("source");
        generator.generate(sourceDir, new char[0], "service.local", true);
        Path archivePath = tempDir.resolve("certs.tar.gz");
        createTarGz(archivePath, sourceDir, "fullchain.pem", "private-key.pem");

        PemTlsMaterial material = importer.importFrom(archivePath, null, new char[0]);

        assertThat(material.leafCertificate()).isNotNull();
        assertThat(material.privateKey()).isNotNull();
    }

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

    private void writePkcs12(Path target, PemTlsMaterial material, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("leaf", material.privateKey(), password, new Certificate[]{material.leafCertificate()});
        try (OutputStream outputStream = Files.newOutputStream(target)) {
            keyStore.store(outputStream, password);
        }
    }

    private void createTarGz(Path target, Path sourceDir, String... fileNames) throws Exception {
        try (OutputStream outputStream = Files.newOutputStream(target);
             GzipCompressorOutputStream gzip = new GzipCompressorOutputStream(outputStream);
             TarArchiveOutputStream tar = new TarArchiveOutputStream(gzip)) {
            for (String fileName : fileNames) {
                byte[] content = Files.readAllBytes(sourceDir.resolve(fileName));
                TarArchiveEntry entry = new TarArchiveEntry(fileName);
                entry.setSize(content.length);
                tar.putArchiveEntry(entry);
                tar.write(content);
                tar.closeArchiveEntry();
            }
        }
    }
}
