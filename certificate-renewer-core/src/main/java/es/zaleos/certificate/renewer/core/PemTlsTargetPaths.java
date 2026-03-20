package es.zaleos.certificate.renewer.core;

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Destination file set for PEM TLS material.
 */
public record PemTlsTargetPaths(
        Path certificatePath,
        Path chainPath,
        Path fullChainPath,
        Path privateKeyPath
) {

    public Set<Path> allConfiguredPaths() {
        Set<Path> paths = new LinkedHashSet<>();
        addIfPresent(paths, certificatePath);
        addIfPresent(paths, chainPath);
        addIfPresent(paths, fullChainPath);
        addIfPresent(paths, privateKeyPath);
        return paths;
    }

    private void addIfPresent(Set<Path> paths, Path path) {
        if (path != null) {
            paths.add(path);
        }
    }
}
