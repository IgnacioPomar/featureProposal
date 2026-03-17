package com.example.ssl.cli;

import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    /**
     * Executes the renewal flow without propagating failures.
     */
    public void execute() {
        try {
            Path sourceDirectory = requirePathProperty(PROP_SOURCE_DIR);
            Path targetKeystore = requirePathProperty(PROP_TARGET_KEYSTORE);
            char[] targetKeystorePassword = requireStringProperty(PROP_TARGET_PASSWORD).toCharArray();
            char[] targetKeyPassword = optionalStringProperty(PROP_TARGET_KEY_PASSWORD)
                    .map(String::toCharArray)
                    .orElse(targetKeystorePassword);
            String alias = optionalStringProperty(PROP_TARGET_ALIAS).orElse(DEFAULT_ALIAS);
            Path externalKeyPath = optionalStringProperty(PROP_EXTERNAL_KEY_PATH).map(Path::of).orElse(null);
            char[] externalMaterialPassword = optionalStringProperty(PROP_EXTERNAL_MATERIAL_PASSWORD)
                    .map(String::toCharArray)
                    .orElse(new char[0]);

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

            LOGGER.info("Certificate renewal completed. Source={}, Expires={}",
                    result.certificatePath(), result.expirationDate());
            System.out.println("[CERTIFICATE] Renewal finished successfully. Imported from "
                    + result.certificatePath() + ", expiration=" + result.expirationDate());
        } catch (Exception exception) {
            LOGGER.error("Certificate renewal failed: {}", exception.getMessage());
            System.err.println("[CERTIFICATE] Renewal failed: " + exception.getMessage());
        }
    }

    private Path requirePathProperty(String key) {
        String value = System.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required property: " + key);
        }
        return Path.of(value);
    }

    private String requireStringProperty(String key) {
        String value = System.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required property: " + key);
        }
        return value;
    }

    private Optional<String> optionalStringProperty(String key) {
        String value = System.getProperty(key);
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(value);
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
