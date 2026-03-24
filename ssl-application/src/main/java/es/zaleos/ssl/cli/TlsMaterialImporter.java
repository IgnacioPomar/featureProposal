package es.zaleos.ssl.cli;

import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.runtime.TlsMaterialService;
import java.nio.file.Path;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Imports and activates TLS material using the Zaleos PEM-based starter.
 */
@Component
public class TlsMaterialImporter {

    private static final Logger LOGGER = LogManager.getLogger(TlsMaterialImporter.class);
    private static final String PROP_SOURCE_DIR = "tls.import.source-dir";
    private static final String PROP_EXTERNAL_KEY_PATH = "tls.import.external-key-path";
    private static final String PROP_EXTERNAL_MATERIAL_PASSWORD = "tls.import.source-password";

    private final Environment environment;
    private final TlsMaterialService operationService;
    private final CertificateRenewerProperties properties;

    public TlsMaterialImporter(
            Environment environment,
            TlsMaterialService operationService,
            CertificateRenewerProperties properties
    ) {
        this.environment = environment;
        this.operationService = operationService;
        this.properties = properties;
    }

    /**
     * Executes the TLS material import flow using command-line args and environment properties.
     */
    public void execute() {
        try {
            Path sourceDirectory = requirePath(
                    PROP_SOURCE_DIR,
                    "tls.import.directory",
                    "tls-source-dir",
                    "import-tls-directory",
                    "directory",
                    "TLS_SOURCE_DIR",
                    "APP_TLS_SOURCE_DIR",
                    "SSL_RENEW_SOURCE_DIR",
                    "renew.directory",
                    "renew-directory",
                    "RENEW_DIRECTORY",
                    "APP_CERT_RENEW_DIRECTORY"
            );

            Path externalKeyPath = optionalPath(PROP_EXTERNAL_KEY_PATH).orElse(null);
            char[] externalMaterialPassword = requireString(
                    PROP_EXTERNAL_MATERIAL_PASSWORD,
                    "tls.import.password",
                    "tls-source-password",
                    "import-tls-password",
                    "password",
                    "TLS_SOURCE_PASSWORD",
                    "APP_TLS_SOURCE_PASSWORD",
                    "SSL_RENEW_EXTERNAL_MATERIAL_PASSWORD",
                    "renew.password",
                    "renew-password",
                    "RENEW_PASSWORD",
                    "APP_CERT_RENEW_PASSWORD"
            ).toCharArray();

            PemActivationResult result = importAndActivate(sourceDirectory, externalKeyPath, externalMaterialPassword);

            LOGGER.info("TLS material import completed. Source={}, Expires={}",
                    result.sourcePath(), result.expirationDate());
            System.out.println("[TLS] TLS material imported successfully. Source="
                    + result.sourcePath() + ", expiration=" + result.expirationDate());
        } catch (Exception exception) {
            LOGGER.error("TLS material import failed: {}", exception.getMessage());
            throw new IllegalStateException("TLS material import failed: " + exception.getMessage(), exception);
        }
    }

    public PemActivationResult importAndActivate(
            Path sourceDirectory,
            Path externalKeyPath,
            char[] externalMaterialPassword
    ) throws Exception {
        return operationService.importAndActivate(
                "web-server",
                sourceDirectory,
                externalKeyPath,
                externalMaterialPassword,
                false
        );
    }

    private Optional<String> optionalString(String... keys) {
        for (String key : keys) {
            String value = resolveValue(key);
            if (value != null && !value.isBlank()) {
                return Optional.of(value);
            }
        }
        return Optional.empty();
    }

    private String requireString(String... keys) {
        return optionalString(keys)
                .orElseThrow(() -> new IllegalArgumentException("Missing required configuration. One of: "
                        + String.join(", ", keys)));
    }

    private Optional<Path> optionalPath(String... keys) {
        return optionalString(keys).map(Path::of);
    }

    private Path requirePath(String... keys) {
        return optionalPath(keys)
                .orElseThrow(() -> new IllegalArgumentException("Missing required configuration. One of: "
                        + String.join(", ", keys)));
    }

    private String resolveValue(String key) {
        String systemValue = System.getProperty(key);
        if (systemValue != null && !systemValue.isBlank()) {
            return systemValue;
        }

        String envValue = System.getenv(toEnvStyle(key));
        if (envValue != null && !envValue.isBlank()) {
            return envValue;
        }

        return environment.getProperty(key);
    }

    private String toEnvStyle(String key) {
        return key.replace('.', '_').replace('-', '_').toUpperCase();
    }
}
