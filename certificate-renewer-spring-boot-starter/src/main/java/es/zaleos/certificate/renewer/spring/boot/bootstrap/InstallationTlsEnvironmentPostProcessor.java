package es.zaleos.certificate.renewer.spring.boot.bootstrap;

import es.zaleos.certificate.renewer.core.BouncyCastleRegistrar;
import es.zaleos.certificate.renewer.core.InstallationTlsMaterialGenerator;
import es.zaleos.certificate.renewer.core.PemTlsMaterialValidator;
import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.util.StringUtils;

/**
 * Ensures default HTTPS PEM material exists before Spring Boot registers SSL file watchers.
 */
public final class InstallationTlsEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    private static final Log LOGGER = LogFactory.getLog(InstallationTlsEnvironmentPostProcessor.class);

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if (!environment.getProperty("zaleos.certificate.enabled", Boolean.class, true)) {
            return;
        }
        if (!environment.getProperty("zaleos.certificate.bootstrap.enabled", Boolean.class, true)) {
            return;
        }

        PemTlsTargetPaths targetPaths = resolveDefaultWebServerTarget(environment);
        if (targetPaths.fullChainPath() == null || targetPaths.privateKeyPath() == null) {
            return;
        }
        if (isUsable(targetPaths) && environment.getProperty(
                "zaleos.certificate.bootstrap.only-if-missing", Boolean.class, true)) {
            return;
        }

        try {
            BouncyCastleRegistrar.ensureRegistered();
            InstallationTlsMaterialGenerator generator = new InstallationTlsMaterialGenerator();
            Path outputDirectory = Optional.ofNullable(targetPaths.fullChainPath().getParent())
                    .orElseGet(() -> Optional.ofNullable(targetPaths.privateKeyPath().getParent())
                            .orElse(Path.of("./target/zaleos/web-server")));
            String applicationName = environment.getProperty("spring.application.name", "application");
            String configuredCn = environment.getProperty(
                    "zaleos.certificate.bootstrap.default-common-name", "installation.local");
            String commonName = StringUtils.hasText(configuredCn) && !"installation.local".equals(configuredCn)
                    ? configuredCn
                    : applicationName + "-web-server" + PemTlsMaterialValidator.PLACEHOLDER_CN_SUFFIX;
            char[] password = Optional.ofNullable(environment.getProperty("zaleos.certificate.output.private-key-password"))
                    .filter(StringUtils::hasText)
                    .or(() -> Optional.ofNullable(environment.getProperty(
                            "spring.ssl.bundle.pem.server.keystore.private-key-password")).filter(StringUtils::hasText))
                    .map(String::toCharArray)
                    .orElse(new char[0]);
            boolean allowUnencryptedPrivateKey = environment.getProperty(
                    "zaleos.certificate.output.write-unencrypted-private-key", Boolean.class, password.length == 0);

            LOGGER.warn("No usable web-server TLS material found during environment bootstrap. Generating installation "
                    + "PEM material at " + outputDirectory.toAbsolutePath());
            generator.generate(targetPaths, outputDirectory, password, commonName, allowUnencryptedPrivateKey);
        } catch (Exception exception) {
            throw new IllegalStateException("Failed to bootstrap HTTPS PEM material before SSL initialization", exception);
        }
    }

    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER + 1;
    }

    private PemTlsTargetPaths resolveDefaultWebServerTarget(ConfigurableEnvironment environment) {
        String bundleName = environment.getProperty("server.ssl.bundle");
        if (StringUtils.hasText(bundleName)) {
            String prefix = "spring.ssl.bundle.pem." + bundleName + ".keystore.";
            String certificate = environment.getProperty(prefix + "certificate");
            String privateKey = environment.getProperty(prefix + "private-key");
            if (StringUtils.hasText(certificate) && StringUtils.hasText(privateKey)) {
                return new PemTlsTargetPaths(toPath(certificate), null, toPath(certificate), toPath(privateKey));
            }
        }

        String outputDir = environment.getProperty("zaleos.certificate.targets.web-server.output-dir");
        Path fallback = StringUtils.hasText(outputDir) ? Path.of(outputDir) : Path.of("./target/zaleos/web-server");
        return new PemTlsTargetPaths(
                fallback.resolve("certificate.pem"),
                fallback.resolve("chain.pem"),
                fallback.resolve("fullchain.pem"),
                fallback.resolve("private-key.pem")
        );
    }

    private Path toPath(String value) {
        return value.startsWith("file:") ? Path.of(value.substring("file:".length())) : Path.of(value);
    }

    private boolean isUsable(PemTlsTargetPaths targetPaths) {
        return isReadableFile(targetPaths.fullChainPath()) && isReadableFile(targetPaths.privateKeyPath());
    }

    private boolean isReadableFile(Path path) {
        if (path == null || !Files.isReadable(path) || !Files.isRegularFile(path)) {
            return false;
        }
        try {
            return Files.size(path) > 0;
        } catch (IOException exception) {
            return false;
        }
    }
}
