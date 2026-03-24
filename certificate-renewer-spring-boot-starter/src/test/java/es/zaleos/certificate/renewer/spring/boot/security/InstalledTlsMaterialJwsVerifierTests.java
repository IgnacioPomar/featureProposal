package es.zaleos.certificate.renewer.spring.boot.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import es.zaleos.certificate.renewer.core.PemTlsCurrentMaterialLoader;
import es.zaleos.certificate.renewer.core.PemTlsMaterial;
import es.zaleos.certificate.renewer.core.PemTlsMaterialImporter;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.event.TlsMaterialActivatedEvent;
import es.zaleos.certificate.renewer.spring.boot.runtime.TargetPathsResolver;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;

class InstalledTlsMaterialJwsVerifierTests {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
    private final PemTlsMaterialImporter importer = new PemTlsMaterialImporter();

    @Test
    void verifiesCompactJwsUsingInstalledCertificateWhenX5cHeaderIsAbsent(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("web-server");
        generator.generate(targetDir, new char[0], "service.local", true);
        PemTlsMaterial installed = importer.importFrom(targetDir, null, new char[0]);

        InstalledTlsMaterialJwsVerifier verifier = createVerifier(targetDir, null);
        String token = sign(
                installed.privateKey(),
                Map.of("alg", "RS256"),
                Map.of("sub", "alice", "iat", 1L, "exp", 2L)
        );

        Map<String, Object> claims = verifier.verifyAndExtractClaims(token);

        assertThat(claims).containsEntry("sub", "alice");
    }

    @Test
    void rejectsCompactJwsWhenSignatureDoesNotMatchInstalledCertificate(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("web-server");
        Path differentDir = tempDir.resolve("different");
        generator.generate(targetDir, new char[0], "service.local", true);
        generator.generate(differentDir, new char[0], "different.local", true);
        PemTlsMaterial different = importer.importFrom(differentDir, null, new char[0]);

        InstalledTlsMaterialJwsVerifier verifier = createVerifier(targetDir, null);
        String token = sign(
                different.privateKey(),
                Map.of("alg", "RS256"),
                Map.of("sub", "mallory")
        );

        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOf(JwsVerificationException.class)
                .hasMessageContaining("signature");
    }

    @Test
    void rejectsX5cChainWhenRootDoesNotMatchConfiguredExpectedRootCa(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("web-server");
        Path anchorDir = tempDir.resolve("anchor");
        generator.generate(targetDir, new char[0], "service.local", true);
        generator.generate(anchorDir, new char[0], "pca-anchor.local", true);
        PemTlsMaterial installed = importer.importFrom(targetDir, null, new char[0]);

        InstalledTlsMaterialJwsVerifier verifier =
                createVerifier(targetDir, anchorDir.resolve("fullchain.pem"));
        String token = sign(
                installed.privateKey(),
                Map.of("alg", "RS256", "x5c", List.of(Base64.getEncoder().encodeToString(
                        installed.leafCertificate().getEncoded()))),
                Map.of("sub", "alice")
        );

        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOf(JwsVerificationException.class)
                .hasMessageContaining("expected-root-ca");
    }

    @Test
    void reloadsInstalledPublicKeyAfterTlsMaterialActivatedEvent(@TempDir Path tempDir) throws Exception {
        Path targetDir = tempDir.resolve("web-server");
        generator.generate(targetDir, new char[0], "service-a.local", true);
        PemTlsMaterial original = importer.importFrom(targetDir, null, new char[0]);

        InstalledTlsMaterialJwsVerifier verifier = createVerifier(targetDir, null);
        String originalToken = sign(original.privateKey(), Map.of("alg", "RS256"), Map.of("sub", "before-reload"));
        assertThat(verifier.verifyAndExtractClaims(originalToken)).containsEntry("sub", "before-reload");

        generator.generate(targetDir, new char[0], "service-b.local", true);
        PemTlsMaterial rotated = importer.importFrom(targetDir, null, new char[0]);
        verifier.onTlsMaterialActivated(new TlsMaterialActivatedEvent(this, "web-server", null));

        String rotatedToken = sign(rotated.privateKey(), Map.of("alg", "RS256"), Map.of("sub", "after-reload"));
        assertThat(verifier.verifyAndExtractClaims(rotatedToken)).containsEntry("sub", "after-reload");
        assertThatThrownBy(() -> verifier.verify(originalToken))
                .isInstanceOf(JwsVerificationException.class)
                .hasMessageContaining("signature");
    }

    private InstalledTlsMaterialJwsVerifier createVerifier(Path targetDir, Path expectedRootCaPath) {
        CertificateRenewerProperties properties = new CertificateRenewerProperties();
        properties.getTargets().computeIfAbsent("web-server", ignored -> new CertificateRenewerProperties.Target())
                .setOutputDir(targetDir.toString());
        if (expectedRootCaPath != null) {
            properties.getPolicy().setExpectedRootCa("file:" + expectedRootCaPath);
        }

        TargetPathsResolver targetResolver =
                new TargetPathsResolver(new MockEnvironment(), properties);

        return new InstalledTlsMaterialJwsVerifier(
                targetResolver,
                properties,
                new PemTlsCurrentMaterialLoader()
        );
    }

    private String sign(PrivateKey privateKey, Map<String, Object> header, Map<String, Object> claims) throws Exception {
        String headerPart = base64UrlEncode(OBJECT_MAPPER.writeValueAsBytes(header));
        String payloadPart = base64UrlEncode(OBJECT_MAPPER.writeValueAsBytes(claims));
        String signingInput = headerPart + "." + payloadPart;

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));

        return signingInput + "." + base64UrlEncode(signature.sign());
    }

    private String base64UrlEncode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
