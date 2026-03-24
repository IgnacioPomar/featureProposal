package es.zaleos.certificate.renewer.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Stream;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

/**
 * Imports TLS material from folders or archives and normalizes it to a PEM bundle model.
 */
public class PemTlsMaterialImporter {

    private static final Logger LOGGER = Logger.getLogger(PemTlsMaterialImporter.class.getName());
    private static final List<String> CERT_EXTENSIONS = List.of(
            ".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".p12", ".pfx");
    private static final List<String> KEY_EXTENSIONS = List.of(".key", ".pem", ".pk8");
    private static final String BC = "BC";

    public PemTlsMaterialImporter() {
        BouncyCastleRegistrar.ensureRegistered();
    }

    public PemTlsMaterial importFrom(Path sourcePath, Path externalPrivateKeyPath, char[] sourcePassword) throws Exception {
        if (sourcePath == null || !Files.exists(sourcePath)) {
            throw new IllegalArgumentException("Source path does not exist: " + sourcePath);
        }

        if (Files.isRegularFile(sourcePath) && isPkcs12File(sourcePath)) {
            return loadFromPkcs12(sourcePath, sourcePassword)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "No valid certificate and private key material found in: " + sourcePath));
        }

        Path workingDirectory = sourcePath;
        Path tempDirectory = null;
        try {
            if (Files.isRegularFile(sourcePath)) {
                tempDirectory = extractArchiveToTempDirectory(sourcePath);
                workingDirectory = tempDirectory;
            }
            if (!Files.isDirectory(workingDirectory)) {
                throw new IllegalArgumentException("Source path must be a directory or supported archive: " + sourcePath);
            }

            return findBestImportMaterial(workingDirectory, externalPrivateKeyPath, sourcePassword)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "No valid certificate and private key material found in: " + sourcePath));
        } finally {
            if (tempDirectory != null) {
                deleteDirectoryQuietly(tempDirectory);
            }
        }
    }

    private Optional<PemTlsMaterial> findBestImportMaterial(
            Path certificatesDirectory,
            Path externalPrivateKeyPath,
            char[] externalMaterialPassword
    ) throws Exception {
        List<PemTlsMaterial> candidates = new ArrayList<>();
        List<PrivateKeyCandidate> privateKeys = loadPrivateKeyCandidates(
                certificatesDirectory, externalPrivateKeyPath, externalMaterialPassword);

        try (Stream<Path> files = Files.list(certificatesDirectory)) {
            List<Path> certificateFiles = files
                    .filter(Files::isRegularFile)
                    .filter(this::isCertificateFile)
                    .toList();

            for (Path certificateFile : certificateFiles) {
                try {
                    String lowerName = certificateFile.getFileName().toString().toLowerCase(Locale.ROOT);
                    if (lowerName.endsWith(".p12") || lowerName.endsWith(".pfx")) {
                        Optional<PemTlsMaterial> pfxMaterial = loadFromPkcs12(certificateFile, externalMaterialPassword);
                        pfxMaterial.ifPresent(candidates::add);
                        continue;
                    }

                    List<X509Certificate> certificates = loadCertificates(certificateFile);
                    Optional<X509Certificate> leaf = selectLeafCertificate(certificates);
                    if (leaf.isEmpty()) {
                        continue;
                    }

                    Optional<PrivateKeyCandidate> matchingKey = privateKeys.stream()
                            .filter(candidate -> privateKeyMatchesCertificate(candidate.privateKey(), leaf.get()))
                            .findFirst();
                    if (matchingKey.isEmpty()) {
                        continue;
                    }

                    candidates.add(new PemTlsMaterial(
                            certificateFile,
                            leaf.get(),
                            matchingKey.get().privateKey(),
                            buildOrderedChain(leaf.get(), certificates)
                    ));
                } catch (Exception e) {
                    LOGGER.fine(() -> "Skipping candidate file " + certificateFile.getFileName() + ": " + e.getMessage());
                }
            }
        }

        return candidates.stream()
                .max(Comparator.comparing(material -> material.leafCertificate().getNotAfter()));
    }

    private Optional<PemTlsMaterial> loadFromPkcs12(Path pkcs12Path, char[] password) throws Exception {
        java.security.KeyStore sourceStore = java.security.KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(pkcs12Path)) {
            sourceStore.load(input, password);
        }

        PemTlsMaterial best = null;
        var aliases = sourceStore.aliases();
        while (aliases.hasMoreElements()) {
            String sourceAlias = aliases.nextElement();
            if (!sourceStore.isKeyEntry(sourceAlias)) {
                continue;
            }
            java.security.KeyStore.Entry entry = sourceStore.getEntry(
                    sourceAlias,
                    new java.security.KeyStore.PasswordProtection(password != null ? password : new char[0])
            );
            if (!(entry instanceof java.security.KeyStore.PrivateKeyEntry privateKeyEntry)) {
                continue;
            }
            X509Certificate leaf = (X509Certificate) privateKeyEntry.getCertificate();
            if (!privateKeyMatchesCertificate(privateKeyEntry.getPrivateKey(), leaf)) {
                continue;
            }

            List<X509Certificate> orderedChain = new ArrayList<>();
            for (Certificate certificate : privateKeyEntry.getCertificateChain()) {
                if (certificate instanceof X509Certificate x509) {
                    orderedChain.add(x509);
                }
            }
            PemTlsMaterial material = new PemTlsMaterial(
                    pkcs12Path,
                    leaf,
                    privateKeyEntry.getPrivateKey(),
                    orderedChain
            );
            if (best == null || leaf.getNotAfter().after(best.leafCertificate().getNotAfter())) {
                best = material;
            }
        }

        return Optional.ofNullable(best);
    }

    private List<PrivateKeyCandidate> loadPrivateKeyCandidates(
            Path certificatesDirectory,
            Path externalPrivateKeyPath,
            char[] externalMaterialPassword
    ) throws Exception {
        List<PrivateKeyCandidate> keys = new ArrayList<>();
        Set<Path> uniquePaths = new HashSet<>();

        if (externalPrivateKeyPath != null && Files.isRegularFile(externalPrivateKeyPath)) {
            try {
                keys.add(new PrivateKeyCandidate(loadPrivateKey(externalPrivateKeyPath, externalMaterialPassword)));
                uniquePaths.add(externalPrivateKeyPath.toAbsolutePath().normalize());
            } catch (Exception e) {
                LOGGER.warning("Failed to load explicitly specified private key at " + externalPrivateKeyPath + ": " + e.getMessage());
            }
        }

        try (Stream<Path> files = Files.list(certificatesDirectory)) {
            for (Path path : files.filter(Files::isRegularFile).filter(this::isPrivateKeyFile).toList()) {
                Path normalized = path.toAbsolutePath().normalize();
                if (uniquePaths.contains(normalized)) {
                    continue;
                }
                try {
                    keys.add(new PrivateKeyCandidate(loadPrivateKey(path, externalMaterialPassword)));
                    uniquePaths.add(normalized);
                } catch (Exception e) {
                    LOGGER.fine(() -> "Skipping key file " + path.getFileName() + ": " + e.getMessage());
                }
            }
        }
        return keys;
    }

    private List<X509Certificate> loadCertificates(Path certificatePath) throws Exception {
        List<X509Certificate> fromPem = loadCertificatesFromPem(certificatePath);
        if (!fromPem.isEmpty()) {
            return fromPem;
        }

        try (InputStream inputStream = Files.newInputStream(certificatePath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certs = new ArrayList<>();
            for (Certificate certificate : factory.generateCertificates(inputStream)) {
                if (certificate instanceof X509Certificate x509) {
                    certs.add(x509);
                }
            }
            return certs;
        }
    }

    private List<X509Certificate> loadCertificatesFromPem(Path path) throws Exception {
        List<X509Certificate> certificates = new ArrayList<>();
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BC);
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8);
             PEMParser parser = new PEMParser(reader)) {
            Object object;
            while ((object = parser.readObject()) != null) {
                if (object instanceof X509CertificateHolder holder) {
                    certificates.add(converter.getCertificate(holder));
                }
            }
        } catch (Exception exception) {
            return List.of();
        }
        return certificates;
    }

    private Optional<X509Certificate> selectLeafCertificate(List<X509Certificate> certificates) {
        if (certificates.isEmpty()) {
            return Optional.empty();
        }
        List<X509Certificate> leaves = certificates.stream()
                .filter(certificate -> certificate.getBasicConstraints() < 0)
                .toList();
        List<X509Certificate> source = leaves.isEmpty() ? certificates : leaves;
        return source.stream().max(Comparator.comparing(X509Certificate::getNotAfter));
    }

    private PrivateKey loadPrivateKey(Path keyPath, char[] password) throws Exception {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC);
        try (Reader reader = Files.newBufferedReader(keyPath, StandardCharsets.UTF_8);
             PEMParser parser = new PEMParser(reader)) {
            Object object;
            while ((object = parser.readObject()) != null) {
                if (object instanceof PEMEncryptedKeyPair encryptedKeyPair) {
                    validatePrivateKeyPassword(password, keyPath);
                    PEMDecryptorProvider decryptor = new JcePEMDecryptorProviderBuilder().build(password);
                    return converter.getKeyPair(encryptedKeyPair.decryptKeyPair(decryptor)).getPrivate();
                }
                if (object instanceof PEMKeyPair keyPair) {
                    return converter.getKeyPair(keyPair).getPrivate();
                }
                if (object instanceof PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo) {
                    validatePrivateKeyPassword(password, keyPath);
                    // BC provider required: the writer uses JceOpenSSLPKCS8EncryptorBuilder
                    // (PKCS#8 AES-256-CBC), which the JVM default provider cannot decrypt.
                    InputDecryptorProvider provider =
                            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider(BC).build(password);
                    PrivateKeyInfo keyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(provider);
                    return converter.getPrivateKey(keyInfo);
                }
                if (object instanceof PrivateKeyInfo keyInfo) {
                    return converter.getPrivateKey(keyInfo);
                }
            }
        }

        byte[] bytes = Files.readAllBytes(keyPath);
        PrivateKeyInfo keyInfo = PrivateKeyInfo.getInstance(bytes);
        return converter.getPrivateKey(keyInfo);
    }

    private void validatePrivateKeyPassword(char[] password, Path keyPath) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Encrypted private key requires a password: " + keyPath);
        }
    }

    private boolean privateKeyMatchesCertificate(PrivateKey privateKey, X509Certificate certificate) {
        try {
            String signatureAlgorithm = switch (privateKey.getAlgorithm().toUpperCase(Locale.ROOT)) {
                case "RSA" -> "SHA256withRSA";
                case "EC", "ECDSA" -> "SHA256withECDSA";
                case "DSA" -> "SHA256withDSA";
                case "ED25519" -> "Ed25519";
                case "ED448" -> "Ed448";
                default -> null;
            };
            if (signatureAlgorithm == null) {
                return false;
            }

            byte[] challenge = "tls-key-check".getBytes(StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance(signatureAlgorithm);
            signer.initSign(privateKey);
            signer.update(challenge);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance(signatureAlgorithm);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);
            return verifier.verify(signature);
        } catch (Exception exception) {
            return false;
        }
    }

    private List<X509Certificate> buildOrderedChain(X509Certificate leaf, List<X509Certificate> allCertificates) {
        List<X509Certificate> ordered = new ArrayList<>();
        Map<String, X509Certificate> bySubject = new HashMap<>();
        for (X509Certificate certificate : allCertificates) {
            bySubject.put(certificate.getSubjectX500Principal().getName(), certificate);
        }

        Set<String> visitedSubjects = new HashSet<>();
        X509Certificate current = leaf;
        while (current != null) {
            String subject = current.getSubjectX500Principal().getName();
            if (!visitedSubjects.add(subject)) {
                break;
            }
            ordered.add(current);
            String issuer = current.getIssuerX500Principal().getName();
            if (issuer.equals(subject)) {
                break;
            }
            current = bySubject.get(issuer);
        }

        for (X509Certificate certificate : allCertificates) {
            if (!visitedSubjects.contains(certificate.getSubjectX500Principal().getName())) {
                ordered.add(certificate);
            }
        }
        return List.copyOf(ordered);
    }

    private Path extractArchiveToTempDirectory(Path archivePath) throws IOException {
        String lowerName = archivePath.getFileName().toString().toLowerCase(Locale.ROOT);
        Path tempDirectory = Files.createTempDirectory("zaleos-certificate-source-");
        if (lowerName.endsWith(".zip")) {
            extractZipArchive(archivePath, tempDirectory);
            return tempDirectory;
        }
        if (lowerName.endsWith(".tar.gz")) {
            extractTarGzArchive(archivePath, tempDirectory);
            return tempDirectory;
        }
        if (lowerName.endsWith(".tar")) {
            extractTarArchive(archivePath, tempDirectory);
            return tempDirectory;
        }
        throw new IllegalArgumentException("Unsupported source archive: " + archivePath);
    }

    private void extractZipArchive(Path archivePath, Path destinationDirectory) throws IOException {
        try (InputStream input = Files.newInputStream(archivePath);
             ZipArchiveInputStream zip = new ZipArchiveInputStream(input)) {
            ZipArchiveEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                writeArchiveEntry(destinationDirectory, entry.getName(), zip);
            }
        }
    }

    private void extractTarArchive(Path archivePath, Path destinationDirectory) throws IOException {
        try (InputStream input = Files.newInputStream(archivePath);
             TarArchiveInputStream tar = new TarArchiveInputStream(input)) {
            TarArchiveEntry entry;
            while ((entry = tar.getNextTarEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                writeArchiveEntry(destinationDirectory, entry.getName(), tar);
            }
        }
    }

    private void extractTarGzArchive(Path archivePath, Path destinationDirectory) throws IOException {
        try (InputStream input = Files.newInputStream(archivePath);
             GzipCompressorInputStream gzip = new GzipCompressorInputStream(input);
             TarArchiveInputStream tar = new TarArchiveInputStream(gzip)) {
            TarArchiveEntry entry;
            while ((entry = tar.getNextTarEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                writeArchiveEntry(destinationDirectory, entry.getName(), tar);
            }
        }
    }

    private void writeArchiveEntry(Path destinationDirectory, String entryName, InputStream inputStream) throws IOException {
        Path target = destinationDirectory.resolve(entryName).normalize();
        if (!target.startsWith(destinationDirectory)) {
            throw new IOException("Archive entry escapes destination directory: " + entryName);
        }
        if (target.getParent() != null) {
            Files.createDirectories(target.getParent());
        }
        Files.copy(inputStream, target);
    }

    private void deleteDirectoryQuietly(Path directory) {
        try (Stream<Path> walk = Files.walk(directory)) {
            walk.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }

    private boolean isCertificateFile(Path path) {
        return hasAnyExtension(path, CERT_EXTENSIONS);
    }

    private boolean isPrivateKeyFile(Path path) {
        return hasAnyExtension(path, KEY_EXTENSIONS);
    }

    private boolean isPkcs12File(Path path) {
        String fileName = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return fileName.endsWith(".p12") || fileName.endsWith(".pfx");
    }

    private boolean hasAnyExtension(Path path, List<String> allowedExtensions) {
        String fileName = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return allowedExtensions.stream().anyMatch(fileName::endsWith);
    }

    private record PrivateKeyCandidate(PrivateKey privateKey) {
    }
}
