package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import es.zaleos.certificate.renewer.core.BouncyCastleRegistrar;
import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import es.zaleos.certificate.renewer.core.PemTlsMaterialValidator;
import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

/**
 * Creates installation TLS material automatically when the configured PEM files are missing.
 */
public class ZaleosCertificateBootstrapInitializer implements InitializingBean {

    private static final String BC = "BC";
    private static final Log LOGGER = LogFactory.getLog(ZaleosCertificateBootstrapInitializer.class);

    private final Environment environment;
    private final ZaleosCertificateProperties properties;
    private final ZaleosCertificateTargetResolver targetResolver;
    private final InstallationTlsMaterialGenerator generator;

    public ZaleosCertificateBootstrapInitializer(
            Environment environment,
            ZaleosCertificateProperties properties,
            ZaleosCertificateTargetResolver targetResolver,
            InstallationTlsMaterialGenerator generator
    ) {
        this.environment = environment;
        this.properties = properties;
        this.targetResolver = targetResolver;
        this.generator = generator;
        BouncyCastleRegistrar.ensureRegistered();
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (!properties.isEnabled() || !properties.getBootstrap().isEnabled()) {
            return;
        }

        bootstrapDefaultWebServerIfNeeded();
        bootstrapExplicitTargetsIfNeeded();
    }

    private void bootstrapDefaultWebServerIfNeeded() throws Exception {
        PemTlsTargetPaths targetPaths = targetResolver.resolveDefaultWebServerTarget();
        if (isUsable(targetPaths) && properties.getBootstrap().isOnlyIfMissing()) {
            return;
        }
        if (!isUsable(targetPaths)) {
            String commonName = defaultCommonName("web-server");
            Path outputDirectory = outputDirectoryOf(targetPaths);
            LOGGER.warn("No usable web-server TLS material found. Generating installation PEM material at "
                    + outputDirectory.toAbsolutePath());
            generator.generate(targetPaths, outputDirectory, outputPassword(), commonName, allowUnencryptedPrivateKey());
        }
    }

    private void bootstrapExplicitTargetsIfNeeded() throws Exception {
        for (var entry : properties.getTargets().entrySet()) {
            String targetName = entry.getKey();
            ZaleosCertificateProperties.Target target = entry.getValue();
            if (!target.isBootstrapEnabled() || "web-server".equals(targetName)) {
                continue;
            }

            PemTlsTargetPaths targetPaths = targetResolver.resolve(targetName);
            if (isUsable(targetPaths) && properties.getBootstrap().isOnlyIfMissing()) {
                continue;
            }
            if (!isUsable(targetPaths)) {
                Path outputDirectory = outputDirectoryOf(targetPaths);
                LOGGER.warn("No usable TLS material found for target '" + targetName
                        + "'. Generating installation PEM material at " + outputDirectory.toAbsolutePath());
                generator.generate(
                        targetPaths,
                        outputDirectory,
                        outputPassword(),
                        defaultCommonName(targetName),
                        allowUnencryptedPrivateKey()
                );
            }
        }
    }

    private boolean allowUnencryptedPrivateKey() {
        return properties.getOutput().isWriteUnencryptedPrivateKey();
    }

    private char[] outputPassword() {
        return Optional.ofNullable(properties.getOutput().getPrivateKeyPassword())
                .filter(StringUtils::hasText)
                .or(() -> Optional.ofNullable(environment.getProperty(
                        "spring.ssl.bundle.pem.server.keystore.private-key-password"))
                        .filter(StringUtils::hasText))
                .map(String::toCharArray)
                .orElse(new char[0]);
    }

    private String defaultCommonName(String targetName) {
        String configured = properties.getBootstrap().getDefaultCommonName();
        if (StringUtils.hasText(configured) && !"installation.local".equals(configured)) {
            return configured;
        }
        String applicationName = environment.getProperty("spring.application.name", "application");
        return applicationName + "-" + targetName + PemTlsMaterialValidator.PLACEHOLDER_CN_SUFFIX;
    }

    private Path outputDirectoryOf(PemTlsTargetPaths targetPaths) {
        Path preferred = firstNonNull(
                targetPaths.certificatePath(),
                targetPaths.chainPath(),
                targetPaths.fullChainPath(),
                targetPaths.privateKeyPath()
        );
        if (preferred == null || preferred.getParent() == null) {
            return Path.of("./target/zaleos/bootstrap");
        }
        return preferred.getParent();
    }

    private Path firstNonNull(Path... candidates) {
        for (Path candidate : candidates) {
            if (candidate != null) {
                return candidate;
            }
        }
        return null;
    }

    private boolean isUsable(PemTlsTargetPaths targetPaths) {
        return hasUsableCertificate(targetPaths) && hasUsablePrivateKey(targetPaths);
    }

    private boolean hasUsableCertificate(PemTlsTargetPaths targetPaths) {
        Path certificatePath = Optional.ofNullable(targetPaths.fullChainPath()).orElse(targetPaths.certificatePath());
        if (certificatePath == null || !Files.isReadable(certificatePath)) {
            return false;
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            try (var input = Files.newInputStream(certificatePath)) {
                List<? extends Certificate> certificates = new ArrayList<>(factory.generateCertificates(input));
                return !certificates.isEmpty();
            }
        } catch (Exception exception) {
            return false;
        }
    }

    private boolean hasUsablePrivateKey(PemTlsTargetPaths targetPaths) {
        Path privateKeyPath = targetPaths.privateKeyPath();
        if (privateKeyPath == null || !Files.isReadable(privateKeyPath)) {
            return false;
        }
        try {
            loadPrivateKey(privateKeyPath, outputPassword());
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    private void loadPrivateKey(Path privateKeyPath, char[] password) throws Exception {
        try (Reader reader = Files.newBufferedReader(privateKeyPath, StandardCharsets.US_ASCII);
             PEMParser parser = new PEMParser(reader)) {
            Object parsed = parser.readObject();
            if (parsed instanceof PEMKeyPair keyPair) {
                new JcaPEMKeyConverter().setProvider(BC).getKeyPair(keyPair).getPrivate();
                return;
            }
            if (parsed instanceof PrivateKeyInfo privateKeyInfo) {
                new JcaPEMKeyConverter().setProvider(BC).getPrivateKey(privateKeyInfo);
                return;
            }
            if (parsed instanceof PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo) {
                if (password == null || password.length == 0) {
                    throw new IOException("Encrypted private key requires a password");
                }
                PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(
                        new JcePKCSPBEInputDecryptorProviderBuilder().build(password));
                new JcaPEMKeyConverter().setProvider(BC).getPrivateKey(privateKeyInfo);
                return;
            }
            throw new IOException("Unsupported PEM private key format");
        }
    }
}
