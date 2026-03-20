package com.example.ssl.cli;

import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
 * Imports the newest HTTPS certificate available in a directory into a Java keystore.
 */
public class CertificateImport {

    private static final List<String> CERT_EXTENSIONS = List.of(
            ".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".p12", ".pfx");
    private static final List<String> KEY_EXTENSIONS = List.of(".key", ".pem", ".pk8");
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public CertificateImport() {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Imports the candidate certificate with latest expiration date.
     *
     * @param certificatesDirectory source directory with cert/key files
     * @param keystorePath destination keystore path
     * @param keystorePassword destination keystore password
     * @param keystoreKeyPassword destination entry key password, defaults to keystore password
     * @param alias destination alias
     * @param externalPrivateKeyPath optional explicit private key path for PEM/CRT imports
     * @param externalMaterialPassword password for encrypted private key or source PFX/P12
     * @return import summary
     * @throws Exception if no valid import material exists or import fails
     */
    public ImportResult execute(
            Path certificatesDirectory,
            Path keystorePath,
            char[] keystorePassword,
            char[] keystoreKeyPassword,
            String alias,
            Path externalPrivateKeyPath,
            char[] externalMaterialPassword
    ) throws Exception {
        validateInputs(certificatesDirectory, keystorePath, keystorePassword, alias);

        ImportMaterial material = findBestImportMaterial(
                certificatesDirectory, externalPrivateKeyPath, externalMaterialPassword)
                .orElseThrow(() -> new IllegalArgumentException(
                        "No se encontró material de certificado+clave válido en: " + certificatesDirectory));

        KeyStore keyStore = loadOrCreateKeystore(keystorePath, keystorePassword);
        char[] effectiveKeyPassword = (keystoreKeyPassword == null || keystoreKeyPassword.length == 0)
                ? keystorePassword
                : keystoreKeyPassword;

        keyStore.setKeyEntry(alias, material.privateKey(), effectiveKeyPassword, material.chain());
        if (keystorePath.getParent() != null) {
            Files.createDirectories(keystorePath.getParent());
        }
        try (var output = Files.newOutputStream(keystorePath)) {
            keyStore.store(output, keystorePassword);
        }

        return new ImportResult(alias, material.certificatePath(), material.leaf().getNotAfter().toInstant());
    }

    private void validateInputs(
            Path certificatesDirectory,
            Path keystorePath,
            char[] keystorePassword,
            String alias
    ) {
        if (certificatesDirectory == null || !Files.isDirectory(certificatesDirectory)) {
            throw new IllegalArgumentException("Ruta de certificados no válida: " + certificatesDirectory);
        }
        if (keystorePath == null) {
            throw new IllegalArgumentException("La ruta del keystore es obligatoria.");
        }
        if (keystorePassword == null || keystorePassword.length == 0) {
            throw new IllegalArgumentException("La contraseña del keystore es obligatoria.");
        }
        if (alias == null || alias.isBlank()) {
            throw new IllegalArgumentException("El alias del certificado es obligatorio.");
        }
    }

    private Optional<ImportMaterial> findBestImportMaterial(
            Path certificatesDirectory,
            Path externalPrivateKeyPath,
            char[] externalMaterialPassword
    ) throws Exception {
        List<ImportMaterial> candidates = new ArrayList<>();
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
                        Optional<ImportMaterial> pfxMaterial = loadFromPkcs12(certificateFile, externalMaterialPassword);
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

                    Certificate[] chain = buildOrderedChain(leaf.get(), certificates);
                    candidates.add(new ImportMaterial(
                            certificateFile,
                            leaf.get(),
                            matchingKey.get().privateKey(),
                            chain
                    ));
                } catch (Exception ignored) {
                    // Skip invalid material and continue scanning.
                }
            }
        }

        return candidates.stream()
                .max(Comparator.comparing(candidate -> candidate.leaf().getNotAfter()));
    }

    private Optional<ImportMaterial> loadFromPkcs12(Path pkcs12Path, char[] password) throws Exception {
        KeyStore sourceStore = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(pkcs12Path)) {
            sourceStore.load(input, password);
        }

        ImportMaterial best = null;
        var aliases = sourceStore.aliases();
        while (aliases.hasMoreElements()) {
            String sourceAlias = aliases.nextElement();
            if (!sourceStore.isKeyEntry(sourceAlias)) {
                continue;
            }
            KeyStore.Entry entry = sourceStore.getEntry(
                    sourceAlias,
                    new KeyStore.PasswordProtection(password != null ? password : new char[0])
            );
            if (!(entry instanceof KeyStore.PrivateKeyEntry privateKeyEntry)) {
                continue;
            }
            X509Certificate leaf = (X509Certificate) privateKeyEntry.getCertificate();
            Certificate[] chain = privateKeyEntry.getCertificateChain();
            if (!privateKeyMatchesCertificate(privateKeyEntry.getPrivateKey(), leaf)) {
                continue;
            }
            ImportMaterial material = new ImportMaterial(pkcs12Path, leaf, privateKeyEntry.getPrivateKey(), chain);
            if (best == null || leaf.getNotAfter().after(best.leaf().getNotAfter())) {
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
                keys.add(new PrivateKeyCandidate(
                        loadPrivateKey(externalPrivateKeyPath, externalMaterialPassword)));
                uniquePaths.add(externalPrivateKeyPath.toAbsolutePath().normalize());
            } catch (Exception ignored) {
                // External key path provided but unreadable as private key.
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
                } catch (Exception ignored) {
                    // Some .pem/.key files can contain only certificates or unknown material.
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
                    InputDecryptorProvider provider = new JcePKCSPBEInputDecryptorProviderBuilder().build(password);
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
            throw new IllegalArgumentException("La clave privada en " + keyPath + " requiere contraseña.");
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

            byte[] challenge = "ssl-key-check".getBytes(StandardCharsets.UTF_8);
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

    private Certificate[] buildOrderedChain(X509Certificate leaf, List<X509Certificate> allCertificates) {
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
        return ordered.toArray(new Certificate[0]);
    }

    private KeyStore loadOrCreateKeystore(Path keystorePath, char[] keystorePassword) throws Exception {
        String keystoreType = inferKeystoreType(keystorePath);
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        if (Files.exists(keystorePath)) {
            try (InputStream input = Files.newInputStream(keystorePath)) {
                keyStore.load(input, keystorePassword);
            }
        } else {
            keyStore.load(null, keystorePassword);
        }
        return keyStore;
    }

    private String inferKeystoreType(Path keystorePath) {
        String fileName = keystorePath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (fileName.endsWith(".p12") || fileName.endsWith(".pfx")) {
            return "PKCS12";
        }
        return "JKS";
    }

    private boolean isCertificateFile(Path path) {
        return hasAnyExtension(path, CERT_EXTENSIONS);
    }

    private boolean isPrivateKeyFile(Path path) {
        return hasAnyExtension(path, KEY_EXTENSIONS);
    }

    private boolean hasAnyExtension(Path path, List<String> allowedExtensions) {
        String fileName = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return allowedExtensions.stream().anyMatch(fileName::endsWith);
    }

    private record PrivateKeyCandidate(PrivateKey privateKey) {
    }

    private record ImportMaterial(Path certificatePath, X509Certificate leaf, PrivateKey privateKey, Certificate[] chain) {
    }

    public record ImportResult(String alias, Path certificatePath, Instant expirationDate) {
    }
}
