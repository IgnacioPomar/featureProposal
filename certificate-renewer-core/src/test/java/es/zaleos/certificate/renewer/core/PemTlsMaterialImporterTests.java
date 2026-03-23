package es.zaleos.certificate.renewer.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PemTlsMaterialImporterTests {

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
    private final PemTlsMaterialImporter importer = new PemTlsMaterialImporter();

    // -------------------------------------------------------------------------
    // happy paths
    // -------------------------------------------------------------------------

    @Test
    void importFromPemDirectory_returnsValidMaterial(@TempDir Path tempDir) throws Exception {
        Path sourceDir = tempDir.resolve("source");
        generator.generate(sourceDir, new char[0], "service.local", true);

        PemTlsMaterial material = importer.importFrom(sourceDir, null, new char[0]);

        assertThat(material.leafCertificate()).isNotNull();
        assertThat(material.privateKey()).isNotNull();
        assertThat(material.orderedChain()).isNotEmpty();
    }

    @Test
    void importFromPkcs12_returnsValidMaterial(@TempDir Path tempDir) throws Exception {
        Path sourceDir = tempDir.resolve("source");
        generator.generate(sourceDir, new char[0], "service.local", true);
        PemTlsMaterial generated = importer.importFrom(sourceDir, null, new char[0]);

        // PKCS12 is only supported when the .p12 file resides inside a directory:
        // importFrom(file) routes through extractArchiveToTempDirectory, which only
        // handles .zip/.tar. The directory scan path is what calls loadFromPkcs12.
        char[] p12Password = "test-p12-password".toCharArray();
        Path p12Dir = tempDir.resolve("p12dir");
        Files.createDirectories(p12Dir);
        writePkcs12(p12Dir.resolve("test.p12"), generated, p12Password);

        PemTlsMaterial material = importer.importFrom(p12Dir, null, p12Password);

        assertThat(material.leafCertificate().getSubjectX500Principal())
                .isEqualTo(generated.leafCertificate().getSubjectX500Principal());
        assertThat(material.privateKey()).isNotNull();
    }

    @Test
    void importFromZipArchive_returnsValidMaterial(@TempDir Path tempDir) throws Exception {
        Path sourceDir = tempDir.resolve("source");
        generator.generate(sourceDir, new char[0], "service.local", true);
        Path zipPath = tempDir.resolve("certs.zip");
        createZip(zipPath, sourceDir, "fullchain.pem", "private-key.pem");

        PemTlsMaterial material = importer.importFrom(zipPath, null, new char[0]);

        assertThat(material.leafCertificate()).isNotNull();
        assertThat(material.privateKey()).isNotNull();
    }

    @Test
    void importFromTarArchive_returnsValidMaterial(@TempDir Path tempDir) throws Exception {
        Path sourceDir = tempDir.resolve("source");
        generator.generate(sourceDir, new char[0], "service.local", true);
        Path tarPath = tempDir.resolve("certs.tar");
        createTar(tarPath, sourceDir, "fullchain.pem", "private-key.pem");

        PemTlsMaterial material = importer.importFrom(tarPath, null, new char[0]);

        assertThat(material.leafCertificate()).isNotNull();
        assertThat(material.privateKey()).isNotNull();
    }

    @Test
    void encryptedKey_withCorrectPassword_succeeds(@TempDir Path tempDir) throws Exception {
        char[] password = "correct-password".toCharArray();
        Path sourceDir = tempDir.resolve("source");
        // allowUnencryptedPrivateKey=false forces the generator to encrypt the key
        generator.generate(sourceDir, password, "service.local", false);

        PemTlsMaterial material = importer.importFrom(sourceDir, null, password);

        assertThat(material.leafCertificate()).isNotNull();
        assertThat(material.privateKey()).isNotNull();
    }

    // -------------------------------------------------------------------------
    // security: path traversal rejection
    // -------------------------------------------------------------------------

    /**
     * An archive entry whose name resolves to a path outside the extraction directory
     * (e.g. "../../etc/passwd") must be rejected immediately. Without this check, a
     * malicious archive could overwrite arbitrary files on the host.
     */
    @Test
    void pathTraversalInZip_isRejected(@TempDir Path tempDir) throws Exception {
        Path maliciousZip = tempDir.resolve("malicious.zip");
        try (ZipArchiveOutputStream zos = new ZipArchiveOutputStream(Files.newOutputStream(maliciousZip))) {
            ZipArchiveEntry entry = new ZipArchiveEntry("../../etc/malicious.txt");
            zos.putArchiveEntry(entry);
            zos.write("malicious content".getBytes());
            zos.closeArchiveEntry();
        }

        assertThatThrownBy(() -> importer.importFrom(maliciousZip, null, new char[0]))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("escapes destination directory");
    }

    @Test
    void pathTraversalInTar_isRejected(@TempDir Path tempDir) throws Exception {
        Path maliciousTar = tempDir.resolve("malicious.tar");
        byte[] content = "malicious content".getBytes();
        try (TarArchiveOutputStream tos = new TarArchiveOutputStream(Files.newOutputStream(maliciousTar))) {
            TarArchiveEntry entry = new TarArchiveEntry("../../etc/malicious.txt");
            entry.setSize(content.length);
            tos.putArchiveEntry(entry);
            tos.write(content);
            tos.closeArchiveEntry();
        }

        assertThatThrownBy(() -> importer.importFrom(maliciousTar, null, new char[0]))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("escapes destination directory");
    }

    // -------------------------------------------------------------------------
    // failure cases
    // -------------------------------------------------------------------------

    @Test
    void missingPrivateKey_throwsDescriptiveException(@TempDir Path tempDir) throws Exception {
        Path sourceDir = tempDir.resolve("source");
        generator.generate(sourceDir, new char[0], "service.local", true);
        Files.deleteIfExists(sourceDir.resolve("private-key.pem"));

        assertThatThrownBy(() -> importer.importFrom(sourceDir, null, new char[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No valid certificate and private key material found");
    }

    @Test
    void encryptedKey_withWrongPassword_failsWithNoMaterialFound(@TempDir Path tempDir) throws Exception {
        char[] correctPassword = "correct-password".toCharArray();
        char[] wrongPassword = "wrong-password".toCharArray();
        Path sourceDir = tempDir.resolve("source");
        generator.generate(sourceDir, correctPassword, "service.local", false);

        // Wrong password → key load silently skipped → no key candidates → no match
        assertThatThrownBy(() -> importer.importFrom(sourceDir, null, wrongPassword))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No valid certificate and private key material found");
    }

    @Test
    void nullSourcePath_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> importer.importFrom(null, null, new char[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not exist");
    }

    @Test
    void nonExistentSourcePath_throwsIllegalArgumentException(@TempDir Path tempDir) {
        Path nonExistent = tempDir.resolve("does-not-exist");

        assertThatThrownBy(() -> importer.importFrom(nonExistent, null, new char[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not exist");
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private void writePkcs12(Path target, PemTlsMaterial material, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("leaf", material.privateKey(), password,
                new Certificate[]{material.leafCertificate()});
        try (OutputStream out = Files.newOutputStream(target)) {
            ks.store(out, password);
        }
    }

    private void createZip(Path target, Path sourceDir, String... fileNames) throws IOException {
        try (ZipArchiveOutputStream zos = new ZipArchiveOutputStream(Files.newOutputStream(target))) {
            for (String fileName : fileNames) {
                byte[] content = Files.readAllBytes(sourceDir.resolve(fileName));
                ZipArchiveEntry entry = new ZipArchiveEntry(fileName);
                entry.setSize(content.length);
                zos.putArchiveEntry(entry);
                zos.write(content);
                zos.closeArchiveEntry();
            }
        }
    }

    private void createTar(Path target, Path sourceDir, String... fileNames) throws IOException {
        try (TarArchiveOutputStream tos = new TarArchiveOutputStream(Files.newOutputStream(target))) {
            for (String fileName : fileNames) {
                byte[] content = Files.readAllBytes(sourceDir.resolve(fileName));
                TarArchiveEntry entry = new TarArchiveEntry(fileName);
                entry.setSize(content.length);
                tos.putArchiveEntry(entry);
                tos.write(content);
                tos.closeArchiveEntry();
            }
        }
    }
}
