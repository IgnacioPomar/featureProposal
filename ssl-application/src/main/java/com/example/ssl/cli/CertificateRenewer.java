package com.example.ssl.cli;

import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Imports renewed certificates into a temporary keystore and swaps it with production.
 */
@Component
public class CertificateRenewer {

    private static final Logger LOGGER = LogManager.getLogger(CertificateRenewer.class);
    private static final String PROP_SOURCE_DIR = "ssl.renew.source-dir";
    private static final String PROP_TARGET_KEYSTORE = "ssl.renew.target-keystore";
    private static final String PROP_TARGET_PASSWORD = "ssl.renew.target-password";
    private static final String PROP_TARGET_KEY_PASSWORD = "ssl.renew.target-key-password";
    private static final String PROP_TARGET_ALIAS = "ssl.renew.target-alias";
    private static final String PROP_EXTERNAL_KEY_PATH = "ssl.renew.external-key-path";
    private static final String PROP_EXTERNAL_MATERIAL_PASSWORD = "ssl.renew.external-material-password";
    private static final String DEFAULT_ALIAS = "ssl-app";

    private final Environment environment;

    public CertificateRenewer(Environment environment) {
        this.environment = environment;
    }

    /**
     * Executes the renewal flow using command-line args and environment properties.
     */
    public void execute() {
        try {
            Path sourceDirectory = requirePath(
                    PROP_SOURCE_DIR,
                    "renew.directory",
                    "renew-directory",
                    "directory",
                    "RENEW_DIRECTORY",
                    "APP_CERT_RENEW_DIRECTORY",
                    "SSL_RENEW_SOURCE_DIR"
            );

            Path targetKeystore = optionalPath(PROP_TARGET_KEYSTORE)
                    .or(() -> optionalPath("app.certificate-page.target-keystore"))
                    .orElse(Path.of("./target/classes/ssl/keystore.p12"));

            char[] targetKeystorePassword = requireString(
                    PROP_TARGET_PASSWORD,
                    "server.ssl.key-store-password",
                    "SSL_KEYSTORE_PASSWORD"
            ).toCharArray();

            char[] targetKeyPassword = optionalString(
                    PROP_TARGET_KEY_PASSWORD,
                    "server.ssl.key-password",
                    "SSL_KEY_PASSWORD"
            ).map(String::toCharArray).orElse(targetKeystorePassword);

            String alias = optionalString(PROP_TARGET_ALIAS, "app.certificate-page.alias", "server.ssl.key-alias")
                    .orElse(DEFAULT_ALIAS);

            Path externalKeyPath = optionalPath(PROP_EXTERNAL_KEY_PATH).orElse(null);

            char[] externalMaterialPassword = requireString(
                    PROP_EXTERNAL_MATERIAL_PASSWORD,
                    "renew.password",
                    "renew-password",
                    "password",
                    "RENEW_PASSWORD",
                    "APP_CERT_RENEW_PASSWORD",
                    "SSL_RENEW_EXTERNAL_MATERIAL_PASSWORD"
            ).toCharArray();

            CertificateImport.ImportResult result = renew(
                    sourceDirectory,
                    targetKeystore,
                    targetKeystorePassword,
                    targetKeyPassword,
                    alias,
                    externalKeyPath,
                    externalMaterialPassword
            );

            LOGGER.info("Certificate renewal completed. Source={}, Expires={}",
                    result.certificatePath(), result.expirationDate());
            System.out.println("[CERTIFICATE] Renewal finished successfully. Imported from "
                    + result.certificatePath() + ", expiration=" + result.expirationDate());
        } catch (Exception exception) {
            LOGGER.error("Certificate renewal failed: {}", exception.getMessage());
            throw new IllegalStateException("Certificate renewal failed: " + exception.getMessage(), exception);
        }
    }

    /**
     * Executes renewal with explicit inputs for programmatic usage.
     */
    public CertificateImport.ImportResult renew(
            Path sourceDirectory,
            Path targetKeystore,
            char[] targetKeystorePassword,
            char[] targetKeyPassword,
            String alias,
            Path externalKeyPath,
            char[] externalMaterialPassword
    ) throws Exception {
        Path tempKeystore = buildTempKeystorePath(targetKeystore);
        Path previousKeystore = buildPreviousKeystorePath(targetKeystore);

        CertificateImport certificateImport = new CertificateImport();
        CertificateImport.ImportResult result = certificateImport.execute(
                sourceDirectory,
                tempKeystore,
                targetKeystorePassword,
                targetKeyPassword,
                alias,
                externalKeyPath,
                externalMaterialPassword
        );

        replaceKeystore(targetKeystore, tempKeystore, previousKeystore);
        Files.deleteIfExists(previousKeystore);
        return result;
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

    private Path buildTempKeystorePath(Path targetKeystore) {
        return targetKeystore.resolveSibling(targetKeystore.getFileName() + ".tmp");
    }

    private Path buildPreviousKeystorePath(Path targetKeystore) {
        return targetKeystore.resolveSibling(targetKeystore.getFileName() + ".previous");
    }

    private void replaceKeystore(Path targetKeystore, Path tempKeystore, Path previousKeystore) throws Exception {
        if (targetKeystore.getParent() != null) {
            Files.createDirectories(targetKeystore.getParent());
        }

        Files.deleteIfExists(previousKeystore);
        boolean backupCreated = false;
        if (Files.exists(targetKeystore)) {
            Files.move(targetKeystore, previousKeystore, StandardCopyOption.REPLACE_EXISTING);
            backupCreated = true;
        }

        try {
            Files.move(tempKeystore, targetKeystore,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(tempKeystore, targetKeystore, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception moveException) {
            if (backupCreated && Files.exists(previousKeystore) && !Files.exists(targetKeystore)) {
                Files.move(previousKeystore, targetKeystore, StandardCopyOption.REPLACE_EXISTING);
            }
            throw moveException;
        } finally {
            Files.deleteIfExists(tempKeystore);
        }
    }
}
