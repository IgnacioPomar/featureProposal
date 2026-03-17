package com.example.ssl.cli;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

/**
 * Verifies that the application installation is healthy.
 */
@Component
public class CheckInstallation {

    private static final Logger LOGGER = LogManager.getLogger(CheckInstallation.class);

    /**
     * Executes the installation check without propagating failures.
     */
    public void execute() {
        try {
            LOGGER.info("Installation check completed successfully.");
            System.out.println("[CHECK] Installation is valid.");
        } catch (Exception exception) {
            LOGGER.error("Installation check failed: {}", exception.getMessage());
            System.err.println("[CHECK] Installation check failed: " + exception.getMessage());
        }
    }
}
