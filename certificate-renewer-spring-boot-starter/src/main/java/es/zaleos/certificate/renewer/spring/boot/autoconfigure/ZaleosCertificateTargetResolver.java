package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import java.nio.file.Path;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

/**
 * Resolves PEM target paths from explicit target configuration or Spring SSL defaults.
 */
public class ZaleosCertificateTargetResolver {

    private final Environment environment;
    private final ZaleosCertificateProperties properties;

    public ZaleosCertificateTargetResolver(Environment environment, ZaleosCertificateProperties properties) {
        this.environment = environment;
        this.properties = properties;
    }

    public PemTlsTargetPaths resolve(String targetName) {
        if (StringUtils.hasText(targetName) && properties.getTargets().containsKey(targetName)) {
            return fromTarget(properties.getTargets().get(targetName));
        }
        return resolveDefaultWebServerTarget();
    }

    public PemTlsTargetPaths resolveDefaultWebServerTarget() {
        String bundleName = environment.getProperty("server.ssl.bundle");
        if (StringUtils.hasText(bundleName)) {
            String prefix = "spring.ssl.bundle.pem." + bundleName + ".keystore.";
            String certificate = environment.getProperty(prefix + "certificate");
            String privateKey = environment.getProperty(prefix + "private-key");
            if (StringUtils.hasText(certificate) && StringUtils.hasText(privateKey)) {
                return new PemTlsTargetPaths(
                        toPath(certificate),
                        null,
                        toPath(certificate),
                        toPath(privateKey)
                );
            }
        }

        String keyStore = environment.getProperty("server.ssl.key-store");
        if (StringUtils.hasText(keyStore) && keyStore.startsWith("file:")) {
            Path baseDirectory = toPath(keyStore).getParent();
            if (baseDirectory != null) {
                return new PemTlsTargetPaths(
                        baseDirectory.resolve("certificate.pem"),
                        baseDirectory.resolve("chain.pem"),
                        baseDirectory.resolve("fullchain.pem"),
                        baseDirectory.resolve("private-key.pem")
                );
            }
        }

        ZaleosCertificateProperties.Target webServer = properties.getTargets().get("web-server");
        if (webServer != null) {
            return fromTarget(webServer);
        }

        Path fallback = Path.of("./target/zaleos/web-server");
        return new PemTlsTargetPaths(
                fallback.resolve("certificate.pem"),
                fallback.resolve("chain.pem"),
                fallback.resolve("fullchain.pem"),
                fallback.resolve("private-key.pem")
        );
    }

    private PemTlsTargetPaths fromTarget(ZaleosCertificateProperties.Target target) {
        if (StringUtils.hasText(target.getOutputDir())) {
            Path outputDir = Path.of(target.getOutputDir());
            return new PemTlsTargetPaths(
                    outputDir.resolve("certificate.pem"),
                    outputDir.resolve("chain.pem"),
                    outputDir.resolve("fullchain.pem"),
                    outputDir.resolve("private-key.pem")
            );
        }
        return new PemTlsTargetPaths(
                nullablePath(target.getCertificatePath()),
                nullablePath(target.getChainPath()),
                nullablePath(target.getFullChainPath()),
                nullablePath(target.getPrivateKeyPath())
        );
    }

    private Path nullablePath(String value) {
        return StringUtils.hasText(value) ? toPath(value) : null;
    }

    private Path toPath(String value) {
        if (value.startsWith("file:")) {
            return Path.of(value.substring("file:".length()));
        }
        return Path.of(value);
    }
}
