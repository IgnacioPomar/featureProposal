package com.example.ssl.cli;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Scanner;
import liquibase.Contexts;
import liquibase.LabelExpression;
import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;

/**
 * Performs setup actions before Spring starts.
 */
public class SetupConfigurator {

    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_BOLD = "\u001B[1m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_CYAN = "\u001B[36m";

    /**
     * Executes setup tasks and handles failures locally.
     */
    public void execute() {
        try (Scanner scanner = new Scanner(System.in)) {
            printTitle();
            handleExternalConfigurationWarnings(scanner);

            String sslPassword = askSslPassword(scanner);
            DbConfig dbConfig = askAndValidateDatabaseConfig(scanner);
            CertificateConfig certificateConfig = generateInstallationCertificate(sslPassword);
            runLiquibaseFromSetup(scanner, dbConfig);

            System.out.println();
            System.out.println(ANSI_BOLD + "Suggested application.properties values" + ANSI_RESET);
            System.out.println("server.ssl.key-store-password=" + maskIfNeeded(sslPassword));
            System.out.println("spring.datasource.url=" + dbConfig.jdbcUrl());
            System.out.println("spring.datasource.username=" + dbConfig.username());
            System.out.println("spring.datasource.password=" + maskIfNeeded(dbConfig.password()));
            System.out.println("app.certificate-page.target-keystore=" + certificateConfig.keystorePath().toAbsolutePath());
            System.out.println("# app.certificate-page.alias remains default (ssl-app)");
            System.out.println();

            String outputPath = askWithDefault(scanner, "Save definitive setup file", "./config/application.properties");
            Path savedFile = writeSetupFile(outputPath, sslPassword, dbConfig, certificateConfig);
            printSuccess("Configuration saved to " + savedFile.toAbsolutePath());
            System.out.println("Spring Boot will load it automatically from ./config/application.properties.");
            System.out.println(ANSI_GREEN + "[SETUP] Interactive setup finished." + ANSI_RESET);
        } catch (Exception exception) {
            System.err.println(ANSI_RED + "[SETUP] Setup failed: " + exception.getMessage() + ANSI_RESET);
        }
    }

    private void printTitle() {
        System.out.println(ANSI_BOLD + ANSI_CYAN + "== SSL Application Setup Wizard ==" + ANSI_RESET);
        System.out.println("This wizard asks values step by step and validates what it can.");
        System.out.println("Terminal UI note: no real combobox by default, we use a numbered menu.");
        System.out.println();
    }

    private void handleExternalConfigurationWarnings(Scanner scanner) {
        for (String variable : InstallationRequirements.REQUIRED_VARIABLES) {
            String env = System.getenv(variable);
            String prop = System.getProperty(variable.toLowerCase(Locale.ROOT).replace('_', '.'));
            if ((env != null && !env.isBlank()) || (prop != null && !prop.isBlank())) {
                boolean wantsCorrection = askWarningDecision(scanner,
                        "External configuration detected for " + variable
                                + ". Wizard value may be overridden at runtime.");
                if (wantsCorrection) {
                    throw new IllegalStateException(
                            "Please remove external override for " + variable + " and run --setup again.");
                }
            }
        }
    }

    private String askSslPassword(Scanner scanner) {
        while (true) {
            String sslPassword = askValue(scanner, "SSL keystore password", "SSL_KEYSTORE_PASSWORD", true);
            if (sslPassword.isBlank()) {
                boolean wantsCorrection = askWarningDecision(scanner,
                        "SSL password is empty. TLS startup will likely fail.");
                if (wantsCorrection) {
                    continue;
                }
                return sslPassword;
            }
            if (sslPassword.length() < 8) {
                boolean wantsCorrection = askWarningDecision(scanner,
                        "SSL password is short (<8 chars).");
                if (wantsCorrection) {
                    continue;
                }
            }
            printSuccess("SSL password captured.");
            return sslPassword;
        }
    }

    private DbConfig askAndValidateDatabaseConfig(Scanner scanner) {
        while (true) {
            DatabaseType databaseType = askDatabaseType(scanner);
            DbConfig dbConfig = askDatabaseConfig(scanner, databaseType);

            if (databaseType == DatabaseType.H2) {
                boolean wantsCorrection = askWarningDecision(scanner,
                        "H2 is convenient but considered volatile for production.");
                if (wantsCorrection) {
                    continue;
                }
            }

            printInfo("Checking DB connection...");
            DbCheckResult dbCheck = checkDbConnection(dbConfig);
            if (dbCheck.ok()) {
                printSuccess("Database connection is valid.");
                return dbConfig;
            }
            if (dbCheck.driverMissing()) {
                boolean wantsCorrection = askWarningDecision(scanner,
                        "Cannot validate DB connection: JDBC driver not available in this build. "
                                + dbCheck.message());
                if (wantsCorrection) {
                    continue;
                }
                return dbConfig;
            }

            boolean wantsCorrection = askErrorDecision(scanner,
                    "Database connection failed: " + dbCheck.message());
            if (wantsCorrection) {
                continue;
            }
            throw new IllegalStateException("Installation aborted by user.");
        }
    }

    private CertificateConfig generateInstallationCertificate(String sslPassword) {
        ApplicationYamlDefaults defaults = new ApplicationYamlDefaults();
        String defaultKeystorePath = defaults.defaultValue("APP_CERT_TARGET_KEYSTORE")
                .orElse("./target/classes/ssl/keystore.p12");
        String defaultAlias = defaults.defaultValue("APP_CERT_ALIAS").orElse("ssl-app");
        String certCn = "installation.local";
        Path keystorePath = Path.of(defaultKeystorePath).toAbsolutePath().normalize();

        printWarning("A temporary installation certificate will be generated automatically.");
        printInfo("Target keystore: " + keystorePath + " (alias: " + defaultAlias + ")");

        try {
            InstallationCertificateGenerator generator = new InstallationCertificateGenerator();
            generator.generate(keystorePath, sslPassword.toCharArray(), defaultAlias, certCn);
            printSuccess("Installation certificate generated at " + keystorePath);
            return new CertificateConfig(keystorePath, defaultAlias);
        } catch (Exception exception) {
            throw new IllegalStateException("Cannot generate installation certificate: " + exception.getMessage(), exception);
        }
    }

    private String askValue(Scanner scanner, String label, String envName, boolean secret) {
        String envValue = System.getenv(envName);
        if (envValue != null && !envValue.isBlank()) {
            printWarning(label + " already configured externally.");
        }

        Console console = System.console();
        System.out.print(label + ": ");

        if (secret && console != null) {
            char[] chars = console.readPassword();
            return chars == null ? "" : new String(chars).trim();
        }
        return scanner.nextLine().trim();
    }

    private boolean askWarningDecision(Scanner scanner, String warningMessage) {
        printWarning(warningMessage);
        while (true) {
            System.out.print("Warning detected. Choose [c]orrect or [continue]: ");
            String input = scanner.nextLine().trim().toLowerCase(Locale.ROOT);
            if (input.equals("c") || input.equals("correct")) {
                return true;
            }
            if (input.equals("continue") || input.equals("cont") || input.isEmpty()) {
                return false;
            }
            printWarning("Invalid option. Type 'c' or 'continue'.");
        }
    }

    private boolean askErrorDecision(Scanner scanner, String errorMessage) {
        printError(errorMessage);
        while (true) {
            System.out.print("Error detected. Choose [c]orrect or [a]bort installation: ");
            String input = scanner.nextLine().trim().toLowerCase(Locale.ROOT);
            if (input.equals("c") || input.equals("correct")) {
                return true;
            }
            if (input.equals("a") || input.equals("abort")) {
                return false;
            }
            printWarning("Invalid option. Type 'c' or 'a'.");
        }
    }

    private DatabaseType askDatabaseType(Scanner scanner) {
        System.out.println();
        System.out.println("Select database type:");
        System.out.println("1) H2 (file)");
        System.out.println("2) PostgreSQL");
        System.out.println("3) MySQL");
        System.out.println("4) MariaDB");

        while (true) {
            System.out.print("Option [1-4]: ");
            String raw = scanner.nextLine().trim();
            if ("1".equals(raw)) {
                return DatabaseType.H2;
            }
            if ("2".equals(raw)) {
                return DatabaseType.POSTGRESQL;
            }
            if ("3".equals(raw)) {
                return DatabaseType.MYSQL;
            }
            if ("4".equals(raw)) {
                return DatabaseType.MARIADB;
            }
            printWarning("Invalid option. Please choose 1, 2, 3 or 4.");
        }
    }

    private DbConfig askDatabaseConfig(Scanner scanner, DatabaseType type) {
        return switch (type) {
            case H2 -> askH2Config(scanner);
            case POSTGRESQL -> askPostgresConfig(scanner);
            case MYSQL -> askMysqlConfig(scanner);
            case MARIADB -> askMariaDbConfig(scanner);
        };
    }

    private DbConfig askH2Config(Scanner scanner) {
        System.out.print("H2 file path [./target/db/sslapp]: ");
        String filePath = scanner.nextLine().trim();
        if (filePath.isBlank()) {
            filePath = "./target/db/sslapp";
        }
        String url = "jdbc:h2:file:" + filePath + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1;AUTO_SERVER=TRUE";
        return new DbConfig(url, "sa", "", "org.h2.Driver", "org.hibernate.dialect.H2Dialect");
    }

    private DbConfig askPostgresConfig(Scanner scanner) {
        String host = askWithDefault(scanner, "PostgreSQL host", "localhost");
        String port = askWithDefault(scanner, "PostgreSQL port", "5432");
        String db = askWithDefault(scanner, "PostgreSQL database", "sslapp");
        String user = askWithDefault(scanner, "PostgreSQL username", "postgres");
        String pass = askValue(scanner, "PostgreSQL password", "APP_DATASOURCE_PASSWORD", true);
        String url = "jdbc:postgresql://" + host + ":" + port + "/" + db;
        return new DbConfig(url, user, pass, "org.postgresql.Driver", "org.hibernate.dialect.PostgreSQLDialect");
    }

    private DbConfig askMysqlConfig(Scanner scanner) {
        String host = askWithDefault(scanner, "MySQL host", "localhost");
        String port = askWithDefault(scanner, "MySQL port", "3306");
        String db = askWithDefault(scanner, "MySQL database", "sslapp");
        String user = askWithDefault(scanner, "MySQL username", "root");
        String pass = askValue(scanner, "MySQL password", "APP_DATASOURCE_PASSWORD", true);
        String url = "jdbc:mysql://" + host + ":" + port + "/" + db;
        return new DbConfig(url, user, pass, "com.mysql.cj.jdbc.Driver", "org.hibernate.dialect.MySQLDialect");
    }

    private DbConfig askMariaDbConfig(Scanner scanner) {
        String host = askWithDefault(scanner, "MariaDB host", "mariadb");
        String port = askWithDefault(scanner, "MariaDB port", "3306");
        String db = askWithDefault(scanner, "MariaDB database", "appdb");
        String user = askWithDefault(scanner, "MariaDB username", "appuser");
        String pass = askValue(scanner, "MariaDB password", "APP_DATASOURCE_PASSWORD", true);
        String url = "jdbc:mariadb://" + host + ":" + port + "/" + db;
        return new DbConfig(url, user, pass, "org.mariadb.jdbc.Driver", "org.hibernate.dialect.MariaDBDialect");
    }

    private String askWithDefault(Scanner scanner, String label, String defaultValue) {
        System.out.print(label + " [" + defaultValue + "]: ");
        String value = scanner.nextLine().trim();
        return value.isBlank() ? defaultValue : value;
    }

    private DbCheckResult checkDbConnection(DbConfig config) {
        try (Connection ignored = DriverManager.getConnection(config.jdbcUrl(), config.username(), config.password())) {
            return new DbCheckResult(true, false, "ok");
        } catch (Exception exception) {
            String message = exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage();
            boolean driverMissing = message.toLowerCase(Locale.ROOT).contains("no suitable driver");
            return new DbCheckResult(false, driverMissing, message);
        }
    }

    private void runLiquibaseFromSetup(Scanner scanner, DbConfig dbConfig) {
        while (true) {
            printInfo("Applying database schema with Liquibase from setup...");
            try (Connection connection = DriverManager.getConnection(
                    dbConfig.jdbcUrl(), dbConfig.username(), dbConfig.password())) {
                Database database = DatabaseFactory.getInstance()
                        .findCorrectDatabaseImplementation(new JdbcConnection(connection));
                Liquibase liquibase = new Liquibase(
                        "db/changelog/db.changelog-master.json",
                        new ClassLoaderResourceAccessor(Thread.currentThread().getContextClassLoader()),
                        database
                );
                liquibase.update(new Contexts(), new LabelExpression());
                printSuccess("Liquibase migration completed from setup.");
                return;
            } catch (Exception exception) {
                boolean wantsCorrection = askErrorDecision(
                        scanner,
                        "Liquibase migration failed: " + exception.getMessage()
                );
                if (!wantsCorrection) {
                    throw new IllegalStateException("Installation aborted by user.");
                }
                DbConfig corrected = askAndValidateDatabaseConfig(scanner);
                dbConfig = corrected;
            }
        }
    }

    private Path writeSetupFile(String outputPath, String sslPassword, DbConfig dbConfig, CertificateConfig certificateConfig)
            throws IOException {
        Path path = Path.of(outputPath).toAbsolutePath().normalize();
        if (path.getParent() != null) {
            Files.createDirectories(path.getParent());
        }

        Map<String, String> values = new LinkedHashMap<>();
        values.put("server.ssl.key-store-password", sslPassword);
        values.put("app.certificate-page.target-keystore", certificateConfig.keystorePath().toString());
        values.put("spring.datasource.url", dbConfig.jdbcUrl());
        values.put("spring.datasource.username", dbConfig.username());
        values.put("spring.datasource.password", dbConfig.password());

        StringBuilder content = new StringBuilder();
        content.append("# Generated by --setup").append(System.lineSeparator());
        for (Map.Entry<String, String> entry : values.entrySet()) {
            content.append(entry.getKey())
                    .append("=")
                    .append(escapeEnvValue(entry.getValue()))
                    .append(System.lineSeparator());
        }

        Files.writeString(path, content.toString(), StandardCharsets.UTF_8);
        return path;
    }

    private String escapeEnvValue(String value) {
        if (value == null) {
            return "";
        }
        if (value.isEmpty()) {
            return "\"\"";
        }
        if (value.matches("^[A-Za-z0-9_./:-]+$")) {
            return value;
        }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private String maskIfNeeded(String value) {
        return (value == null || value.isEmpty()) ? "<empty>" : "********";
    }

    private void printWarning(String message) {
        System.out.println(ANSI_YELLOW + ANSI_BOLD + "[WARNING] " + message + ANSI_RESET);
    }

    private void printSuccess(String message) {
        System.out.println(ANSI_GREEN + "[OK] " + message + ANSI_RESET);
    }

    private void printError(String message) {
        System.err.println(ANSI_RED + ANSI_BOLD + "[ERROR] " + message + ANSI_RESET);
    }

    private void printInfo(String message) {
        System.out.println(ANSI_CYAN + message + ANSI_RESET);
    }

    private enum DatabaseType {
        H2,
        POSTGRESQL,
        MYSQL,
        MARIADB
    }

    private record DbConfig(
            String jdbcUrl,
            String username,
            String password,
            String driverClassName,
            String hibernateDialect
    ) {
    }

    private record DbCheckResult(boolean ok, boolean driverMissing, String message) {
    }

    private record CertificateConfig(Path keystorePath, String alias) {
    }
}
