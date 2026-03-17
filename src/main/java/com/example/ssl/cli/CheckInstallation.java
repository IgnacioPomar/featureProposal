package com.example.ssl.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import javax.sql.DataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Verifies that the application installation is healthy.
 */
@Component
public class CheckInstallation {

    private static final Logger LOGGER = LogManager.getLogger(CheckInstallation.class);

    private static final String[] REQUIRED_VARIABLES = {
            "SSL_KEYSTORE_PASSWORD",
            "APP_DATASOURCE_URL",
            "APP_DATASOURCE_USERNAME",
            "APP_DATASOURCE_PASSWORD"
    };

    private static final Map<String, String> REQUIRED_VARIABLE_DEFAULTS = Map.of(
            "SSL_KEYSTORE_PASSWORD", "changeit",
            "APP_DATASOURCE_URL", "jdbc:h2:file:./target/db/sslapp;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;AUTO_SERVER=TRUE",
            "APP_DATASOURCE_USERNAME", "sa",
            "APP_DATASOURCE_PASSWORD", ""
    );

    private static final String DEFAULT_DATASOURCE_URL =
            "jdbc:h2:file:./target/db/sslapp;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;AUTO_SERVER=TRUE";
    private static final String DEFAULT_DATASOURCE_USERNAME = "sa";
    private static final String DEFAULT_DATASOURCE_PASSWORD = "";

    private static final Map<String, Set<String>> REQUIRED_TABLE_COLUMNS = new LinkedHashMap<>();

    static {
        REQUIRED_TABLE_COLUMNS.put("task_item", Set.of("id", "title", "done", "created_at", "updated_at"));
        REQUIRED_TABLE_COLUMNS.put("archive", Set.of("id", "title", "done", "created_at", "updated_at"));
    }

    private final DataSource dataSource;
    private final Environment environment;
    private final ApplicationArguments applicationArguments;

    public CheckInstallation(
            DataSource dataSource,
            Environment environment,
            ApplicationArguments applicationArguments
    ) {
        this.dataSource = dataSource;
        this.environment = environment;
        this.applicationArguments = applicationArguments;
    }

    /**
     * Executes installation checks and writes an HTML report.
     */
    public void execute() {
        List<CheckResult> checks = new ArrayList<>();

        checkRequiredVariables(checks);
        checkDatabaseConfigurationWarnings(checks);

        boolean dbConnectionOk = checkDatabaseConnection(checks);
        if (dbConnectionOk) {
            checkSchema(checks);
        }

        String report = buildHtmlReport(checks);
        Optional<Path> outputFile = resolveOutputFile();

        try {
            if (outputFile.isPresent()) {
                writeReportToFile(outputFile.get(), report);
                System.out.println("[CHECK] HTML report written to " + outputFile.get().toAbsolutePath());
            } else {
                System.out.println(report);
            }
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to write installation report: " + exception.getMessage(), exception);
        }

        long failures = checks.stream().filter(c -> c.severity() == Severity.FAIL).count();
        long warnings = checks.stream().filter(c -> c.severity() == Severity.WARNING).count();

        LOGGER.info("Installation check finished. failures={}, warnings={}", failures, warnings);

        if (failures > 0) {
            throw new IllegalStateException("Installation check failed. See HTML report for details.");
        }
    }

    private void checkRequiredVariables(List<CheckResult> checks) {
        for (String variable : REQUIRED_VARIABLES) {
            String propertyKey = toPropertyKey(variable);
            String envValue = System.getenv(variable);
            String systemPropertyValue = System.getProperty(propertyKey);

            boolean hasExplicitValue = (envValue != null && !envValue.isBlank())
                    || (systemPropertyValue != null && !systemPropertyValue.isBlank());
            boolean explicitlyDefinedButEmpty = (envValue != null && envValue.isBlank())
                    || (systemPropertyValue != null && systemPropertyValue.isBlank());

            if (hasExplicitValue) {
                checks.add(new CheckResult(
                        Severity.PASS,
                        "Required variable",
                        variable,
                        "Configured"
                ));
            } else if (explicitlyDefinedButEmpty) {
                checks.add(new CheckResult(
                        Severity.FAIL,
                        "Required variable",
                        variable,
                        "Defined but empty"
                ));
            } else if (REQUIRED_VARIABLE_DEFAULTS.containsKey(variable)) {
                checks.add(new CheckResult(
                        Severity.WARNING,
                        "Required variable",
                        variable,
                        "Not defined; using default value from application configuration"
                ));
            } else {
                checks.add(new CheckResult(
                        Severity.FAIL,
                        "Required variable",
                        variable,
                        "Missing and no default value"
                ));
            }
        }
    }

    private void checkDatabaseConfigurationWarnings(List<CheckResult> checks) {
        String datasourceUrl = Optional.ofNullable(environment.getProperty("spring.datasource.url")).orElse("");
        String datasourceUsername = Optional.ofNullable(environment.getProperty("spring.datasource.username")).orElse("");
        String datasourcePassword = Optional.ofNullable(environment.getProperty("spring.datasource.password")).orElse("");
        String driverClassName = Optional.ofNullable(environment.getProperty("spring.datasource.driver-class-name")).orElse("");

        boolean isDefaultConfiguration = DEFAULT_DATASOURCE_URL.equals(datasourceUrl)
                && DEFAULT_DATASOURCE_USERNAME.equals(datasourceUsername)
                && DEFAULT_DATASOURCE_PASSWORD.equals(datasourcePassword);

        if (isDefaultConfiguration) {
            checks.add(new CheckResult(
                    Severity.WARNING,
                    "Database configuration",
                    "Datasource settings",
                    "default configuration"
            ));
        } else {
            checks.add(new CheckResult(
                    Severity.PASS,
                    "Database configuration",
                    "Datasource settings",
                    "Custom configuration detected"
            ));
        }

        if (isH2(datasourceUrl, driverClassName)) {
            checks.add(new CheckResult(
                    Severity.WARNING,
                    "Database configuration",
                    "Database engine",
                    "volatile database"
            ));
        }
    }

    private boolean isH2(String datasourceUrl, String driverClassName) {
        String normalizedUrl = datasourceUrl.toLowerCase(Locale.ROOT);
        String normalizedDriver = driverClassName.toLowerCase(Locale.ROOT);
        return normalizedUrl.contains(":h2:") || normalizedDriver.contains("h2");
    }

    private boolean checkDatabaseConnection(List<CheckResult> checks) {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metadata = connection.getMetaData();
            String product = metadata.getDatabaseProductName() + " " + metadata.getDatabaseProductVersion();
            checks.add(new CheckResult(
                    Severity.PASS,
                    "Database connection",
                    "Connection",
                    "Connected successfully to " + product
            ));
            return true;
        } catch (Exception exception) {
            checks.add(new CheckResult(
                    Severity.FAIL,
                    "Database connection",
                    "Connection",
                    exception.getMessage()
            ));
            return false;
        }
    }

    private void checkSchema(List<CheckResult> checks) {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metadata = connection.getMetaData();

            for (Map.Entry<String, Set<String>> tableEntry : REQUIRED_TABLE_COLUMNS.entrySet()) {
                String tableName = tableEntry.getKey();
                Set<String> requiredColumns = tableEntry.getValue();

                if (!tableExists(metadata, tableName)) {
                    checks.add(new CheckResult(
                            Severity.FAIL,
                            "Schema table",
                            tableName,
                            "Table not found"
                    ));
                    continue;
                }

                Set<String> existingColumns = loadTableColumns(metadata, tableName);

                Set<String> missingColumns = new TreeSet<>();
                for (String requiredColumn : requiredColumns) {
                    if (!existingColumns.contains(requiredColumn)) {
                        missingColumns.add(requiredColumn);
                    }
                }

                Set<String> additionalColumns = new TreeSet<>();
                for (String existingColumn : existingColumns) {
                    if (!requiredColumns.contains(existingColumn)) {
                        additionalColumns.add(existingColumn);
                    }
                }

                if (missingColumns.isEmpty()) {
                    checks.add(new CheckResult(
                            Severity.PASS,
                            "Schema table",
                            tableName,
                            "table found and schema matches"
                    ));
                } else {
                    checks.add(new CheckResult(
                            Severity.FAIL,
                            "Schema table",
                            tableName,
                            "table found, incorrect fields. Missing: " + String.join(", ", missingColumns)
                    ));
                }

                if (!additionalColumns.isEmpty()) {
                    checks.add(new CheckResult(
                            Severity.WARNING,
                            "Schema table",
                            tableName,
                            "Found, aditional fields: " + String.join(", ", additionalColumns)
                    ));
                }
            }
        } catch (Exception exception) {
            checks.add(new CheckResult(
                    Severity.FAIL,
                    "Schema check",
                    "Database metadata",
                    exception.getMessage()
            ));
        }
    }

    private boolean tableExists(DatabaseMetaData metadata, String tableName) throws Exception {
        try (ResultSet rs = metadata.getTables(null, null, tableName, new String[]{"TABLE"})) {
            if (rs.next()) {
                return true;
            }
        }

        try (ResultSet rs = metadata.getTables(null, null, tableName.toUpperCase(Locale.ROOT), new String[]{"TABLE"})) {
            if (rs.next()) {
                return true;
            }
        }

        try (ResultSet rs = metadata.getTables(null, null, tableName.toLowerCase(Locale.ROOT), new String[]{"TABLE"})) {
            return rs.next();
        }
    }

    private Set<String> loadTableColumns(DatabaseMetaData metadata, String tableName) throws Exception {
        Set<String> columns = new LinkedHashSet<>();

        collectColumns(metadata, tableName, columns);
        collectColumns(metadata, tableName.toUpperCase(Locale.ROOT), columns);
        collectColumns(metadata, tableName.toLowerCase(Locale.ROOT), columns);

        return columns;
    }

    private void collectColumns(DatabaseMetaData metadata, String tableName, Set<String> columns) throws Exception {
        try (ResultSet rs = metadata.getColumns(null, null, tableName, null)) {
            while (rs.next()) {
                columns.add(rs.getString("COLUMN_NAME").toLowerCase(Locale.ROOT));
            }
        }
    }

    private Optional<Path> resolveOutputFile() {
        List<String> values = applicationArguments.getOptionValues("to-file");
        if (values == null || values.isEmpty()) {
            return Optional.empty();
        }

        String value = values.get(0);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("--to-file requires a valid target path");
        }

        return Optional.of(Path.of(value.trim()));
    }

    private void writeReportToFile(Path outputFile, String report) throws IOException {
        Path parent = outputFile.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(outputFile, report, StandardCharsets.UTF_8);
    }

    private String toPropertyKey(String variableName) {
        return variableName.toLowerCase(Locale.ROOT).replace('_', '.');
    }

    private String buildHtmlReport(List<CheckResult> checks) {
        long pass = checks.stream().filter(c -> c.severity() == Severity.PASS).count();
        long warning = checks.stream().filter(c -> c.severity() == Severity.WARNING).count();
        long fail = checks.stream().filter(c -> c.severity() == Severity.FAIL).count();

        Map<Severity, String> colors = new HashMap<>();
        colors.put(Severity.PASS, "#166534");
        colors.put(Severity.WARNING, "#92400E");
        colors.put(Severity.FAIL, "#991B1B");

        StringBuilder html = new StringBuilder();
        html.append("<!doctype html><html><head><meta charset='UTF-8'><title>Installation Check Report</title>")
                .append("<style>")
                .append("body{font-family:Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;}")
                .append("table{border-collapse:collapse;width:100%;margin-top:14px;}")
                .append("th,td{border:1px solid #ddd;padding:8px;vertical-align:top;text-align:left;}")
                .append("th{background:#f4f4f5;}")
                .append(".pill{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700;color:#fff;}")
                .append("</style></head><body>")
                .append("<h1>Installation Check Report</h1>")
                .append("<p>Generated: ").append(escapeHtml(OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))).append("</p>")
                .append("<p>")
                .append("<span class='pill' style='background:").append(colors.get(Severity.PASS)).append("'>PASS: ").append(pass).append("</span> ")
                .append("<span class='pill' style='background:").append(colors.get(Severity.WARNING)).append("'>WARNING: ").append(warning).append("</span> ")
                .append("<span class='pill' style='background:").append(colors.get(Severity.FAIL)).append("'>FAIL: ").append(fail).append("</span>")
                .append("</p>")
                .append("<table><thead><tr><th>Status</th><th>Category</th><th>Check</th><th>Details</th></tr></thead><tbody>");

        for (CheckResult check : checks) {
            html.append("<tr>")
                    .append("<td><span class='pill' style='background:")
                    .append(colors.get(check.severity()))
                    .append("'>")
                    .append(check.severity())
                    .append("</span></td>")
                    .append("<td>").append(escapeHtml(check.category())).append("</td>")
                    .append("<td>").append(escapeHtml(check.checkName())).append("</td>")
                    .append("<td>").append(escapeHtml(check.details())).append("</td>")
                    .append("</tr>");
        }

        html.append("</tbody></table></body></html>");
        return html.toString();
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private enum Severity {
        PASS,
        WARNING,
        FAIL
    }

    private record CheckResult(
            Severity severity,
            String category,
            String checkName,
            String details
    ) {
    }
}
