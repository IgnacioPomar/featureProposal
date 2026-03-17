package com.example.ssl.cli;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Generates an installation self-signed certificate and stores it in a PKCS12 keystore.
 */
public class InstallationCertificateGenerator {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public InstallationCertificateGenerator() {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public Path generate(Path keystorePath, char[] password, String alias, String commonName) throws Exception {
        if (keystorePath.getParent() != null) {
            Files.createDirectories(keystorePath.getParent());
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Name subject = new X500Name("CN=" + commonName);
        Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
        Date notAfter = new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000));
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

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BC)
                .build(keyPair.getPrivate());

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BC)
                .getCertificate(certBuilder.build(signer));

        certificate.checkValidity(new Date());
        certificate.verify(keyPair.getPublic());

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password);
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, new X509Certificate[]{certificate});

        try (var output = Files.newOutputStream(keystorePath)) {
            keyStore.store(output, password);
        }

        return keystorePath;
    }
}
