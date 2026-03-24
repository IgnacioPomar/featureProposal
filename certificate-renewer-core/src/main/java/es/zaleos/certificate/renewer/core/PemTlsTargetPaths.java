package es.zaleos.certificate.renewer.core;

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Destination path set for TLS material.
 *
 * <p>The active runtime contract uses {@code fullchain.pem} and {@code private-key.pem}. Leaf
 * and chain-only paths remain optional companion locations for callers that still want to model
 * them explicitly.
 */
public record PemTlsTargetPaths(
        Path certificatePath,
        Path chainPath,
        Path fullChainPath,
        Path privateKeyPath
) {

    public Set<Path> activePaths() {
        Set<Path> paths = new LinkedHashSet<>();
        addIfPresent(paths, fullChainPath);
        addIfPresent(paths, privateKeyPath);
        return paths;
    }

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
