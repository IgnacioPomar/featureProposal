package es.zaleos.certificate.renewer.core;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;

/**
 * Writes the active TLS PEM pair and swaps it safely into place.
 */
public class PemTlsMaterialWriter {

    public PemActivationResult writeAtomically(
            PemTlsMaterial material,
            PemTlsTargetPaths targetPaths,
            char[] privateKeyPassword,
            boolean allowUnencryptedPrivateKey
    ) throws Exception {
        if (targetPaths == null || targetPaths.activePaths().isEmpty()) {
            throw new IllegalArgumentException("At least one active PEM target path must be configured.");
        }
        if (!allowUnencryptedPrivateKey && (privateKeyPassword == null || privateKeyPassword.length == 0)) {
            throw new IllegalArgumentException(
                    "Writing an unencrypted private-key.pem is disabled and no output key password was provided.");
        }

        Path stagingDirectory = Files.createTempDirectory("zaleos-certificate-stage-");
        Map<Path, Path> stagedFiles = new LinkedHashMap<>();
        Map<Path, Path> backupFiles = new LinkedHashMap<>();

        try {
            stagePemFiles(material, targetPaths, privateKeyPassword, stagedFiles, stagingDirectory);
            createParentDirectories(targetPaths.activePaths());
            backupExistingFiles(targetPaths.activePaths(), backupFiles);
            moveStagedFiles(stagedFiles);

            applySecurePermissions(targetPaths);

            return new PemActivationResult(
                    material.sourcePath(),
                    targetPaths.fullChainPath(),
                    targetPaths.privateKeyPath(),
                    material.expirationDate()
            );
        } catch (Exception exception) {
            restoreBackups(backupFiles, stagedFiles.keySet());
            throw exception;
        } finally {
            // Staging directory is always cleaned up. Backup (.bak) files are intentionally
            // retained on success so the rollback endpoint can restore the previous material.
            // On failure, restoreBackups() has already moved them back to their original paths.
            deleteDirectoryQuietly(stagingDirectory);
        }
    }

    private void stagePemFiles(
            PemTlsMaterial material,
            PemTlsTargetPaths targetPaths,
            char[] privateKeyPassword,
            Map<Path, Path> stagedFiles,
            Path stagingDirectory
    ) throws Exception {
        if (targetPaths.fullChainPath() != null) {
            stagedFiles.put(targetPaths.fullChainPath(),
                    writeCertificateFile(stagingDirectory.resolve("fullchain.pem"), material.orderedChain()));
        }
        if (targetPaths.privateKeyPath() != null) {
            stagedFiles.put(targetPaths.privateKeyPath(),
                    writePrivateKeyFile(stagingDirectory.resolve("private-key.pem"), material.privateKey(), privateKeyPassword));
        }
    }

    private Path writeCertificateFile(Path target, List<X509Certificate> certificates) throws Exception {
        if (target.getParent() != null) {
            Files.createDirectories(target.getParent());
        }
        try (Writer writer = Files.newBufferedWriter(target, StandardCharsets.US_ASCII);
             JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            for (X509Certificate certificate : certificates) {
                pemWriter.writeObject(certificate);
            }
        }
        return target;
    }

    private Path writePrivateKeyFile(Path target, PrivateKey privateKey, char[] password) throws Exception {
        if (target.getParent() != null) {
            Files.createDirectories(target.getParent());
        }
        try (Writer writer = Files.newBufferedWriter(target, StandardCharsets.US_ASCII);
             JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            if (password != null && password.length > 0) {
                OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                        .setRandom(new SecureRandom())
                        .setPassword(password)
                        .build();
                pemWriter.writeObject(new JcaPKCS8Generator(privateKey, encryptor));
            } else {
                pemWriter.writeObject(privateKey);
            }
        }
        return target;
    }

    private void createParentDirectories(Set<Path> targetPaths) throws IOException {
        for (Path path : targetPaths) {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
        }
    }

    private void backupExistingFiles(Set<Path> targetPaths, Map<Path, Path> backupFiles) throws IOException {
        for (Path targetPath : targetPaths) {
            if (!Files.exists(targetPath)) {
                continue;
            }
            Path backupPath = Path.of(targetPath.toString() + ".bak");
            Files.deleteIfExists(backupPath);
            Files.move(targetPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
            backupFiles.put(targetPath, backupPath);
        }
    }

    private void moveStagedFiles(Map<Path, Path> stagedFiles) throws IOException {
        for (Map.Entry<Path, Path> entry : stagedFiles.entrySet()) {
            moveWithAtomicFallback(entry.getValue(), entry.getKey());
        }
    }

    private void restoreBackups(Map<Path, Path> backupFiles, java.util.Set<Path> targetPaths) {
        for (Path targetPath : targetPaths) {
            try {
                Files.deleteIfExists(targetPath);
            } catch (IOException ignored) {
            }
        }

        for (Map.Entry<Path, Path> backupEntry : backupFiles.entrySet()) {
            try {
                moveWithAtomicFallback(backupEntry.getValue(), backupEntry.getKey());
            } catch (IOException ignored) {
            }
        }
    }

    private void moveWithAtomicFallback(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void applySecurePermissions(PemTlsTargetPaths targetPaths) {
        try {
            Path keyPath = targetPaths.privateKeyPath();
            if (keyPath != null && Files.exists(keyPath)) {
                Set<PosixFilePermission> keyPerms = PosixFilePermissions.fromString("rw-------");
                Files.setPosixFilePermissions(keyPath, keyPerms);
            }
            Path dir = keyPath != null ? keyPath.getParent() : null;
            if (dir != null && Files.exists(dir)) {
                Set<PosixFilePermission> dirPerms = PosixFilePermissions.fromString("rwx------");
                Files.setPosixFilePermissions(dir, dirPerms);
            }
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystem (e.g. Windows dev environment) — skip silently
        } catch (IOException ignored) {
            // Best-effort — do not fail the write because of permission enforcement
        }
    }

    private void deleteDirectoryQuietly(Path directory) {
        try (var walk = Files.walk(directory)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }
}
