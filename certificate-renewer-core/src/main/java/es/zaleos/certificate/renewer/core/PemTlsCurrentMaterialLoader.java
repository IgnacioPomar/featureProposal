package es.zaleos.certificate.renewer.core;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Loads current target certificate material to compare it with a new candidate.
 */
public class PemTlsCurrentMaterialLoader {

    public Optional<PemTlsMaterial> load(PemTlsTargetPaths targetPaths) throws Exception {
        if (targetPaths == null) {
            return Optional.empty();
        }

        Path certificatePath = preferredCertificatePath(targetPaths);
        if (certificatePath == null || !Files.isReadable(certificatePath)) {
            return Optional.empty();
        }

        List<X509Certificate> certificates = loadCertificates(certificatePath);
        if (certificates.isEmpty()) {
            return Optional.empty();
        }

        X509Certificate leaf = selectLeaf(certificates).orElse(certificates.get(0));
        List<X509Certificate> orderedChain = orderChain(leaf, certificates);
        return Optional.of(new PemTlsMaterial(certificatePath, leaf, null, orderedChain));
    }

    private Path preferredCertificatePath(PemTlsTargetPaths targetPaths) {
        if (targetPaths.fullChainPath() != null) {
            return targetPaths.fullChainPath();
        }
        return targetPaths.certificatePath();
    }

    private List<X509Certificate> loadCertificates(Path path) throws Exception {
        try (InputStream input = Files.newInputStream(path)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certificates = new ArrayList<>();
            for (Certificate certificate : factory.generateCertificates(input)) {
                if (certificate instanceof X509Certificate x509) {
                    certificates.add(x509);
                }
            }
            return certificates;
        }
    }

    private Optional<X509Certificate> selectLeaf(List<X509Certificate> certificates) {
        return certificates.stream()
                .filter(certificate -> certificate.getBasicConstraints() < 0)
                .max(Comparator.comparing(X509Certificate::getNotAfter));
    }

    private List<X509Certificate> orderChain(X509Certificate leaf, List<X509Certificate> certificates) {
        List<X509Certificate> ordered = new ArrayList<>();
        ordered.add(leaf);

        X509Certificate current = leaf;
        while (true) {
            X509Certificate issuer = null;
            for (X509Certificate candidate : certificates) {
                if (candidate.equals(current)) {
                    continue;
                }
                if (candidate.getSubjectX500Principal().equals(current.getIssuerX500Principal())) {
                    issuer = candidate;
                    break;
                }
            }
            if (issuer == null) {
                break;
            }
            ordered.add(issuer);
            if (issuer.getSubjectX500Principal().equals(issuer.getIssuerX500Principal())) {
                break;
            }
            current = issuer;
        }
        return ordered;
    }
}
