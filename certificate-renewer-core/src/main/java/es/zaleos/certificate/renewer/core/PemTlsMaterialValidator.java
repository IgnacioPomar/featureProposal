package es.zaleos.certificate.renewer.core;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Compares candidate TLS material against the current target material.
 */
public class PemTlsMaterialValidator {

    /**
     * CN suffix used to identify self-signed bootstrap placeholder certificates.
     * The validator skips {@code same-*} policy checks when the current material carries this suffix.
     */
    public static final String PLACEHOLDER_CN_SUFFIX = ".installation.local";

    public void validate(
            PemTlsMaterial candidate,
            PemTlsMaterial current,
            PemTlsValidationPolicy policy
    ) {
        if (policy == null) {
            return;
        }

        boolean installationPlaceholder = current != null && isInstallationPlaceholder(current);
        if (requiresCurrentMaterial(policy) && current == null) {
            throw new PemTlsValidationException(
                    "Validation policy requires current TLS material, but no current material was found.");
        }

        if (policy.sameRootCa() && !installationPlaceholder) {
            assertEquals("same-root-ca", certificateFingerprint(rootCertificate(current)), certificateFingerprint(rootCertificate(candidate)));
        }
        if (policy.sameChain() && !installationPlaceholder) {
            assertEquals("same-chain", chainFingerprints(chainOnly(current)), chainFingerprints(chainOnly(candidate)));
        }
        if (policy.sameSubject() && !installationPlaceholder) {
            assertEquals("same-subject",
                    current.leafCertificate().getSubjectX500Principal().getName(),
                    candidate.leafCertificate().getSubjectX500Principal().getName());
        }
        if (policy.sameSan() && !installationPlaceholder) {
            assertEquals("same-san", normalizeSans(current.leafCertificate()), normalizeSans(candidate.leafCertificate()));
        }
        if (policy.samePublicKey() && !installationPlaceholder) {
            assertEquals("same-public-key",
                    Base64.getEncoder().encodeToString(current.leafCertificate().getPublicKey().getEncoded()),
                    Base64.getEncoder().encodeToString(candidate.leafCertificate().getPublicKey().getEncoded()));
        }
        if (policy.minimumKeyAlgorithm() != null && !policy.minimumKeyAlgorithm().isBlank()) {
            String actualAlgorithm = candidate.leafCertificate().getPublicKey().getAlgorithm();
            if (!policy.minimumKeyAlgorithm().equalsIgnoreCase(actualAlgorithm)) {
                throw new PemTlsValidationException("Validation failed for minimum-key-algorithm: expected "
                        + policy.minimumKeyAlgorithm() + " but got " + actualAlgorithm);
            }
        }
        if (policy.minimumKeySize() != null) {
            int actualKeySize = keySize(candidate.leafCertificate());
            if (actualKeySize < policy.minimumKeySize()) {
                throw new PemTlsValidationException("Validation failed for minimum-key-size: expected >= "
                        + policy.minimumKeySize() + " but got " + actualKeySize);
            }
        }
        if (policy.expectedRootCa() != null) {
            assertEquals("expected-root-ca",
                    certificateFingerprint(policy.expectedRootCa()),
                    certificateFingerprint(rootCertificate(candidate)));
        }
    }

    private boolean requiresCurrentMaterial(PemTlsValidationPolicy policy) {
        return policy.sameRootCa()
                || policy.sameChain()
                || policy.sameSubject()
                || policy.sameSan()
                || policy.samePublicKey();
    }

    private boolean isInstallationPlaceholder(PemTlsMaterial material) {
        X509Certificate leaf = material.leafCertificate();
        String subject = leaf.getSubjectX500Principal().getName();
        String issuer = leaf.getIssuerX500Principal().getName();
        return subject.equals(issuer) && subject.contains(PLACEHOLDER_CN_SUFFIX);
    }

    private X509Certificate rootCertificate(PemTlsMaterial material) {
        List<X509Certificate> orderedChain = material.orderedChain();
        return orderedChain.get(orderedChain.size() - 1);
    }

    private List<X509Certificate> chainOnly(PemTlsMaterial material) {
        List<X509Certificate> orderedChain = material.orderedChain();
        if (orderedChain.size() <= 1) {
            return List.of();
        }
        return orderedChain.subList(1, orderedChain.size());
    }

    private List<String> chainFingerprints(List<X509Certificate> certificates) {
        return certificates.stream()
                .map(this::certificateFingerprint)
                .toList();
    }

    private String certificateFingerprint(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (Exception exception) {
            throw new PemTlsValidationException("Unable to encode certificate for comparison: " + exception.getMessage());
        }
    }

    private Set<String> normalizeSans(X509Certificate certificate) {
        try {
            Collection<List<?>> sanValues = certificate.getSubjectAlternativeNames();
            if (sanValues == null) {
                return Set.of();
            }
            Set<String> normalized = new LinkedHashSet<>();
            for (List<?> san : sanValues) {
                if (san.size() < 2) {
                    continue;
                }
                Object type = san.get(0);
                Object value = san.get(1);
                normalized.add(type + ":" + Objects.toString(value, ""));
            }
            return normalized;
        } catch (Exception exception) {
            throw new PemTlsValidationException("Unable to inspect subject alternative names: " + exception.getMessage());
        }
    }

    private int keySize(X509Certificate certificate) {
        var publicKey = certificate.getPublicKey();
        if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            return rsaPublicKey.getModulus().bitLength();
        }
        if (publicKey instanceof ECPublicKey ecPublicKey) {
            return ecPublicKey.getParams().getCurve().getField().getFieldSize();
        }
        if (publicKey instanceof DSAPublicKey dsaPublicKey) {
            BigInteger p = dsaPublicKey.getParams().getP();
            return p == null ? 0 : p.bitLength();
        }
        String algorithm = publicKey.getAlgorithm();
        if ("Ed25519".equalsIgnoreCase(algorithm)) {
            return 255;
        }
        if ("Ed448".equalsIgnoreCase(algorithm)) {
            return 448;
        }
        return 0;
    }

    private void assertEquals(String policyName, Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) {
            throw new PemTlsValidationException("Validation failed for " + policyName);
        }
    }
}
