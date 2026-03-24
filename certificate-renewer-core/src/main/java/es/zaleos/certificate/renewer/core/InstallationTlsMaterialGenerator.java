package es.zaleos.certificate.renewer.core;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Generates self-signed PEM TLS material to bootstrap an installation.
 */
public class InstallationTlsMaterialGenerator {

    private static final String BC = "BC";
    private static final String DEMO_ORGANIZATION = "Zaleos";
    private static final String DEMO_ORGANIZATIONAL_UNIT = "Demo Installation TLS";

    private final Clock clock;

    public InstallationTlsMaterialGenerator() {
        this(Clock.systemUTC());
    }

    InstallationTlsMaterialGenerator(Clock clock) {
        this.clock = clock;
        BouncyCastleRegistrar.ensureRegistered();
    }

    public Path generate(
            Path outputDirectory,
            char[] privateKeyPassword,
            String commonName,
            boolean allowUnencryptedPrivateKey
    ) throws Exception {
        return generate(
                new PemTlsTargetPaths(
                        null,
                        null,
                        outputDirectory.resolve("fullchain.pem"),
                        outputDirectory.resolve("private-key.pem")
                ),
                outputDirectory,
                privateKeyPassword,
                commonName,
                allowUnencryptedPrivateKey
        );
    }

    public Path generate(
            PemTlsTargetPaths targetPaths,
            Path sourcePath,
            char[] privateKeyPassword,
            String commonName,
            boolean allowUnencryptedPrivateKey
    ) throws Exception {
        if (sourcePath.getParent() != null) {
            Files.createDirectories(sourcePath.getParent());
        }
        Files.createDirectories(sourcePath);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Name subject = new X500Name(
                "CN=" + commonName + ", OU=" + DEMO_ORGANIZATIONAL_UNIT + ", O=" + DEMO_ORGANIZATION);
        Instant now = clock.instant();
        Date notBefore = Date.from(now.minusSeconds(60));
        Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certBuilder.addExtension(Extension.subjectAlternativeName, false, installationSubjectAlternativeNames());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BC)
                .build(keyPair.getPrivate());

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BC)
                .getCertificate(certBuilder.build(signer));

        certificate.checkValidity(new Date());
        certificate.verify(keyPair.getPublic());

        PemTlsMaterial material = new PemTlsMaterial(
                sourcePath,
                certificate,
                keyPair.getPrivate(),
                List.of(certificate)
        );

        new PemTlsMaterialWriter().writeAtomically(
                material,
                targetPaths,
                privateKeyPassword,
                allowUnencryptedPrivateKey
        );
        return sourcePath;
    }

    private GeneralNames installationSubjectAlternativeNames() {
        return new GeneralNames(new GeneralName[] {
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                new GeneralName(GeneralName.iPAddress, "::1")
        });
    }
}
