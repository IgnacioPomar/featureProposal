package es.zaleos.ssl.cli;

import java.util.List;

/**
 * Shared installation requirements used by CLI installation tasks.
 */
public final class InstallationRequirements {

    private InstallationRequirements() {
    }

    public static final List<String> REQUIRED_VARIABLES = List.of(
            "APP_TLS_PRIVATE_KEY_PASSWORD",
            "APP_DATASOURCE_URL",
            "APP_DATASOURCE_USERNAME",
            "APP_DATASOURCE_PASSWORD"
    );
}
