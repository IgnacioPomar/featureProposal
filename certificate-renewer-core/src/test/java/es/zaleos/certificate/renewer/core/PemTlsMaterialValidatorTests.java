package es.zaleos.certificate.renewer.core;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PemTlsMaterialValidatorTests {

    private final InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
    private final PemTlsCurrentMaterialLoader loader = new PemTlsCurrentMaterialLoader();
    private final PemTlsMaterialValidator validator = new PemTlsMaterialValidator();

    // -------------------------------------------------------------------------
    // same-public-key
    // -------------------------------------------------------------------------

    @Test
    void failsWhenSamePublicKeyIsRequiredAndCandidateUsesDifferentKey(@TempDir Path tempDir) throws Exception {
        Path currentDir = tempDir.resolve("current");
        Path candidateDir = tempDir.resolve("candidate");

        generator.generate(currentDir, new char[0], "service-a.local", true);
        generator.generate(candidateDir, new char[0], "service-b.local", true);

        PemTlsMaterial current = loader.load(toPaths(currentDir)).orElseThrow();
        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                false, false, false, false, true, null, null, null);

        assertThatThrownBy(() -> validator.validate(candidate, current, policy))
                .isInstanceOf(PemTlsValidationException.class)
                .hasMessageContaining("same-public-key");
    }

    // -------------------------------------------------------------------------
    // bootstrap placeholder bypass
    // -------------------------------------------------------------------------

    @Test
    void allowsFirstRealImportWhenCurrentMaterialIsBootstrapPlaceholder(@TempDir Path tempDir) throws Exception {
        Path currentDir = tempDir.resolve("current");
        Path candidateDir = tempDir.resolve("candidate");

        generator.generate(currentDir, new char[0], "demo-web-server.installation.local", true);
        generator.generate(candidateDir, new char[0], "service.example.com", true);

        PemTlsMaterial current = loader.load(toPaths(currentDir)).orElseThrow();
        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                true, true, true, true, true, "RSA", 2048, null);

        assertThatCode(() -> validator.validate(candidate, current, policy))
                .doesNotThrowAnyException();
    }

    // -------------------------------------------------------------------------
    // same-root-ca
    // -------------------------------------------------------------------------

    @Test
    void failsWhenSameRootCaIsRequiredAndCandidateHasDifferentRoot(@TempDir Path tempDir) throws Exception {
        Path currentDir = tempDir.resolve("current");
        Path candidateDir = tempDir.resolve("candidate");

        generator.generate(currentDir, new char[0], "service-a.local", true);
        generator.generate(candidateDir, new char[0], "service-b.local", true);

        PemTlsMaterial current = loader.load(toPaths(currentDir)).orElseThrow();
        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                true, false, false, false, false, null, null, null);

        assertThatThrownBy(() -> validator.validate(candidate, current, policy))
                .isInstanceOf(PemTlsValidationException.class)
                .hasMessageContaining("same-root-ca");
    }

    @Test
    void passesWhenSameRootCaIsRequiredAndMaterialIsReimported(@TempDir Path tempDir) throws Exception {
        Path dir = tempDir.resolve("certs");
        generator.generate(dir, new char[0], "service.local", true);

        PemTlsMaterial current = loader.load(toPaths(dir)).orElseThrow();
        PemTlsMaterial candidate = loader.load(toPaths(dir)).orElseThrow();
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                true, false, false, false, false, null, null, null);

        assertThatCode(() -> validator.validate(candidate, current, policy))
                .doesNotThrowAnyException();
    }

    // -------------------------------------------------------------------------
    // same-subject
    // -------------------------------------------------------------------------

    @Test
    void failsWhenSameSubjectIsRequiredAndCandidateHasDifferentCn(@TempDir Path tempDir) throws Exception {
        Path currentDir = tempDir.resolve("current");
        Path candidateDir = tempDir.resolve("candidate");

        generator.generate(currentDir, new char[0], "service-a.local", true);
        generator.generate(candidateDir, new char[0], "service-b.local", true);

        PemTlsMaterial current = loader.load(toPaths(currentDir)).orElseThrow();
        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                false, false, true, false, false, null, null, null);

        assertThatThrownBy(() -> validator.validate(candidate, current, policy))
                .isInstanceOf(PemTlsValidationException.class)
                .hasMessageContaining("same-subject");
    }

    // -------------------------------------------------------------------------
    // minimum-key-algorithm
    // -------------------------------------------------------------------------

    @Test
    void failsWhenCandidateAlgorithmDoesNotMeetPolicy(@TempDir Path tempDir) throws Exception {
        Path candidateDir = tempDir.resolve("candidate");
        generator.generate(candidateDir, new char[0], "service.local", true);

        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        // Generator always produces RSA; requiring EC must fail
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                false, false, false, false, false, "EC", null, null);

        assertThatThrownBy(() -> validator.validate(candidate, null, policy))
                .isInstanceOf(PemTlsValidationException.class)
                .hasMessageContaining("minimum-key-algorithm");
    }

    // -------------------------------------------------------------------------
    // minimum-key-size
    // -------------------------------------------------------------------------

    @Test
    void failsWhenKeySizeIsBelowMinimum(@TempDir Path tempDir) throws Exception {
        Path candidateDir = tempDir.resolve("candidate");
        generator.generate(candidateDir, new char[0], "service.local", true);

        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        // Generator produces RSA-2048; requiring 4096 must fail
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                false, false, false, false, false, null, 4096, null);

        assertThatThrownBy(() -> validator.validate(candidate, null, policy))
                .isInstanceOf(PemTlsValidationException.class)
                .hasMessageContaining("minimum-key-size");
    }

    @Test
    void passesWhenKeySizeExactlyMeetsMinimum(@TempDir Path tempDir) throws Exception {
        Path candidateDir = tempDir.resolve("candidate");
        generator.generate(candidateDir, new char[0], "service.local", true);

        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        // Generator produces RSA-2048; requiring exactly 2048 must pass
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                false, false, false, false, false, null, 2048, null);

        assertThatCode(() -> validator.validate(candidate, null, policy))
                .doesNotThrowAnyException();
    }

    // -------------------------------------------------------------------------
    // expected-root-ca
    // -------------------------------------------------------------------------

    @Test
    void passesWhenExpectedRootCaMatchesChainRoot(@TempDir Path tempDir) throws Exception {
        Path dir = tempDir.resolve("certs");
        generator.generate(dir, new char[0], "service.local", true);

        PemTlsMaterial material = loader.load(toPaths(dir)).orElseThrow();
        // Self-signed: the cert is its own root
        X509Certificate root = material.orderedChain().get(material.orderedChain().size() - 1);
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                false, false, false, false, false, null, null, root);

        assertThatCode(() -> validator.validate(material, null, policy))
                .doesNotThrowAnyException();
    }

    @Test
    void failsWhenExpectedRootCaDoesNotMatchChainRoot(@TempDir Path tempDir) throws Exception {
        Path anchorDir = tempDir.resolve("anchor");
        Path candidateDir = tempDir.resolve("candidate");

        generator.generate(anchorDir, new char[0], "pca-anchor.local", true);
        generator.generate(candidateDir, new char[0], "service.local", true);

        PemTlsMaterial anchor = loader.load(toPaths(anchorDir)).orElseThrow();
        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        X509Certificate anchorRoot = anchor.orderedChain().get(anchor.orderedChain().size() - 1);
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                false, false, false, false, false, null, null, anchorRoot);

        assertThatThrownBy(() -> validator.validate(candidate, null, policy))
                .isInstanceOf(PemTlsValidationException.class)
                .hasMessageContaining("expected-root-ca");
    }

    /**
     * Security invariant: when the current certificate is a bootstrap placeholder,
     * same-* checks are skipped to allow the first real import — but expectedRootCa
     * must still be enforced. An operator who has configured a PCA trust anchor
     * must not be able to import a certificate rooted in an untrusted CA just
     * because the application is in bootstrap state.
     */
    @Test
    void expectedRootCaIsStillEnforcedWhenCurrentIsInstallationPlaceholder(@TempDir Path tempDir) throws Exception {
        Path placeholderDir = tempDir.resolve("placeholder");
        Path candidateDir = tempDir.resolve("candidate");
        Path anchorDir = tempDir.resolve("anchor");

        generator.generate(placeholderDir, new char[0], "app-web-server.installation.local", true);
        generator.generate(candidateDir, new char[0], "service.example.com", true);
        generator.generate(anchorDir, new char[0], "pca-anchor.local", true);

        PemTlsMaterial placeholder = loader.load(toPaths(placeholderDir)).orElseThrow();
        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        PemTlsMaterial anchor = loader.load(toPaths(anchorDir)).orElseThrow();
        X509Certificate anchorRoot = anchor.orderedChain().get(anchor.orderedChain().size() - 1);

        // All same-* are enabled (they will be skipped due to placeholder), but
        // expectedRootCa must still block the import because candidate's root ≠ anchorRoot.
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                true, true, true, true, true, "RSA", 2048, anchorRoot);

        assertThatThrownBy(() -> validator.validate(candidate, placeholder, policy))
                .isInstanceOf(PemTlsValidationException.class)
                .hasMessageContaining("expected-root-ca");
    }

    // -------------------------------------------------------------------------
    // null / absent inputs
    // -------------------------------------------------------------------------

    @Test
    void throwsWhenSamePolicyRequiresCurrentMaterialButNoneIsPresent(@TempDir Path tempDir) throws Exception {
        Path candidateDir = tempDir.resolve("candidate");
        generator.generate(candidateDir, new char[0], "service.local", true);

        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();
        PemTlsValidationPolicy policy = new PemTlsValidationPolicy(
                true, false, false, false, false, null, null, null);

        assertThatThrownBy(() -> validator.validate(candidate, null, policy))
                .isInstanceOf(PemTlsValidationException.class)
                .hasMessageContaining("Validation policy requires current TLS material");
    }

    @Test
    void nullPolicySkipsAllValidation(@TempDir Path tempDir) throws Exception {
        Path candidateDir = tempDir.resolve("candidate");
        generator.generate(candidateDir, new char[0], "service.local", true);

        PemTlsMaterial candidate = loader.load(toPaths(candidateDir)).orElseThrow();

        assertThatCode(() -> validator.validate(candidate, null, null))
                .doesNotThrowAnyException();
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private PemTlsTargetPaths toPaths(Path dir) {
        return new PemTlsTargetPaths(
                dir.resolve("certificate.pem"),
                dir.resolve("chain.pem"),
                dir.resolve("fullchain.pem"),
                dir.resolve("private-key.pem")
        );
    }
}
