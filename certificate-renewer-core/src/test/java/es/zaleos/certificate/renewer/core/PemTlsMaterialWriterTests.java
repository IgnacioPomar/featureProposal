package es.zaleos.certificate.renewer.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

class PemTlsMaterialWriterTests {

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
    private final PemTlsMaterialImporter importer = new PemTlsMaterialImporter();
    private final PemTlsMaterialWriter writer = new PemTlsMaterialWriter();

    // -------------------------------------------------------------------------
    // happy path
    // -------------------------------------------------------------------------

    @Test
    void writesActivePemFiles(@TempDir Path tempDir) throws Exception {
        PemTlsMaterial material = generateAndImport(tempDir, "source", "service.local");
        Path targetDir = tempDir.resolve("target");

        writer.writeAtomically(material, toPaths(targetDir), new char[0], true);

        assertThat(targetDir.resolve("fullchain.pem")).isRegularFile();
        assertThat(targetDir.resolve("private-key.pem")).isRegularFile();        
   }

    // -------------------------------------------------------------------------
    // filesystem permissions (POSIX only)
    // -------------------------------------------------------------------------

    @Test
    @EnabledOnOs({OS.LINUX, OS.MAC})
    void privateKeyHasRestrictivePermissionsOnPosix(@TempDir Path tempDir) throws Exception {
        PemTlsMaterial material = generateAndImport(tempDir, "source", "service.local");
        Path targetDir = tempDir.resolve("target");

        writer.writeAtomically(material, toPaths(targetDir), new char[0], true);

        Set<PosixFilePermission> keyPerms = Files.getPosixFilePermissions(targetDir.resolve("private-key.pem"));
        assertThat(keyPerms).containsExactlyInAnyOrderElementsOf(
                PosixFilePermissions.fromString("rw-------"));
    }

    @Test
    @EnabledOnOs({OS.LINUX, OS.MAC})
    void targetDirectoryHasRestrictivePermissionsOnPosix(@TempDir Path tempDir) throws Exception {
        PemTlsMaterial material = generateAndImport(tempDir, "source", "service.local");
        Path targetDir = tempDir.resolve("target");

        writer.writeAtomically(material, toPaths(targetDir), new char[0], true);

        Set<PosixFilePermission> dirPerms = Files.getPosixFilePermissions(targetDir);
        assertThat(dirPerms).containsExactlyInAnyOrderElementsOf(
                PosixFilePermissions.fromString("rwx------"));
    }

    // -------------------------------------------------------------------------
    // backup for rollback
    // -------------------------------------------------------------------------

    /**
     * After a second write the previous material must survive as .bak files so
     * that the rollback endpoint can restore it. This verifies that the writer
     * does not delete backups on the success path.
     */
    @Test
    void secondWritePreservesBackupOfPreviousMaterial(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("target");
        PemTlsTargetPaths paths = toPaths(targetDir);

        PemTlsMaterial materialA = generateAndImport(tempDir, "source-a", "service-a.local");
        writer.writeAtomically(materialA, paths, new char[0], true);

        String originalFullchain = Files.readString(targetDir.resolve("fullchain.pem"));

        PemTlsMaterial materialB = generateAndImport(tempDir, "source-b", "service-b.local");
        writer.writeAtomically(materialB, paths, new char[0], true);

        Path backupPath = targetDir.resolve("fullchain.pem.bak");
        assertThat(backupPath).isRegularFile();
        assertThat(Files.readString(backupPath)).isEqualTo(originalFullchain);
    }

    @Test
    void leavesCompanionPemFilesUntouchedWhenTheyAreConfigured(@TempDir Path tempDir) throws Exception {
        PemTlsMaterial material = generateAndImport(tempDir, "source", "service.local");
        Path targetDir = tempDir.resolve("target");
        Files.createDirectories(targetDir);
        Files.writeString(targetDir.resolve("certificate.pem"), "legacy-leaf");
        Files.writeString(targetDir.resolve("chain.pem"), "legacy-chain");

        writer.writeAtomically(material, toPaths(targetDir), new char[0], true);

        assertThat(Files.readString(targetDir.resolve("certificate.pem"))).isEqualTo("legacy-leaf");
        assertThat(Files.readString(targetDir.resolve("chain.pem"))).isEqualTo("legacy-chain");
        assertThat(targetDir.resolve("certificate.pem.bak")).doesNotExist();
        assertThat(targetDir.resolve("chain.pem.bak")).doesNotExist();
    }

    @Test
    void writesEncryptedPrivateKeyWhenPasswordIsProvided(@TempDir Path tempDir) throws Exception {
        PemTlsMaterial material = generateAndImport(tempDir, "source", "service.local");
        Path targetDir = tempDir.resolve("target");
        char[] outputPassword = "output-password".toCharArray();

        writer.writeAtomically(material, toPaths(targetDir), outputPassword, false);

        String privateKeyPem = Files.readString(targetDir.resolve("private-key.pem"));
        assertThat(privateKeyPem).contains("BEGIN ENCRYPTED PRIVATE KEY");

        PemTlsMaterial reloaded = importer.importFrom(targetDir, null, outputPassword);
        assertThat(reloaded.leafCertificate().getSubjectX500Principal())
                .isEqualTo(material.leafCertificate().getSubjectX500Principal());
    }

    // -------------------------------------------------------------------------
    // failure cases
    // -------------------------------------------------------------------------

    @Test
    void writingUnencryptedKeyWithoutExplicitAllowFlagThrows(@TempDir Path tempDir) throws Exception {
        PemTlsMaterial material = generateAndImport(tempDir, "source", "service.local");
        Path targetDir = tempDir.resolve("target");

        // No password supplied and allowUnencryptedPrivateKey=false → must refuse
        assertThatThrownBy(() -> writer.writeAtomically(material, toPaths(targetDir), new char[0], false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unencrypted");
    }

    @Test
    void emptyTargetPaths_throwsIllegalArgumentException(@TempDir Path tempDir) throws Exception {
        PemTlsMaterial material = generateAndImport(tempDir, "source", "service.local");
        PemTlsTargetPaths emptyPaths = new PemTlsTargetPaths(null, null, null, null);

        assertThatThrownBy(() -> writer.writeAtomically(material, emptyPaths, new char[0], true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private PemTlsMaterial generateAndImport(Path baseDir, String subDir, String cn) throws Exception {
        Path sourceDir = baseDir.resolve(subDir);
        generator.generate(sourceDir, new char[0], cn, true);
        return importer.importFrom(sourceDir, null, new char[0]);
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
