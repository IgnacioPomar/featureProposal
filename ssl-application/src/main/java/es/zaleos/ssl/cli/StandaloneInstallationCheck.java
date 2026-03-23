package es.zaleos.ssl.cli;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import liquibase.change.Change;
import liquibase.change.core.CreateTableChange;
import liquibase.changelog.ChangeLogParameters;
import liquibase.changelog.ChangeSet;
import liquibase.changelog.DatabaseChangeLog;
import liquibase.parser.ChangeLogParserFactory;
import liquibase.resource.ClassLoaderResourceAccessor;
import liquibase.resource.ResourceAccessor;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.yaml.snakeyaml.Yaml;

/**
 * Standalone installation checker used by --check-installation.
 */
public class StandaloneInstallationCheck {

    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\$\\{\\s*([^:}]+)\\s*:(.*)}");
    private static final Map<String, List<String>> REQUIRED_PROPERTY_ALIASES = Map.of(
            "APP_TLS_PRIVATE_KEY_PASSWORD", List.of("spring.ssl.bundle.pem.server.keystore.private-key-password"),
            "APP_DATASOURCE_URL", List.of("spring.datasource.url"),
            "APP_DATASOURCE_USERNAME", List.of("spring.datasource.username"),
            "APP_DATASOURCE_PASSWORD", List.of("spring.datasource.password")
    );

    private final ApplicationYamlDefaults applicationYamlDefaults = new ApplicationYamlDefaults();

    public int execute(String[] args) {
        List<CheckResult> checks = new ArrayList<>();
        ParsedArgs parsedArgs = ParsedArgs.parse(args);
        ConfigSnapshot config = ConfigSnapshot.load(parsedArgs);

        try {
            checkRequiredVariables(checks, config);
            checkTlsMaterial(checks, config);
            checkDatabaseConfigurationWarnings(checks, config);

            boolean dbConnectionOk = checkDatabaseConnection(checks, config);
            if (dbConnectionOk) {
                checkSchema(checks, config);
            }
        } catch (Exception exception) {
            checks.add(new CheckResult(
                    Severity.FAIL,
                    "Check execution",
                    "Unexpected error",
                    rootCauseMessage(exception)
            ));
        }

        String report = buildHtmlReport(checks);
        try {
            if (parsedArgs.outputFile().isPresent()) {
                writeReportToFile(parsedArgs.outputFile().get(), report);
                System.out.println("[CHECK] HTML report written to " + parsedArgs.outputFile().get().toAbsolutePath());
            } else {
                System.out.println(report);
            }
        } catch (IOException exception) {
            System.err.println("[CHECK] Unable to write report file: " + exception.getMessage());
            System.out.println(report);
        }

        boolean failed = checks.stream().anyMatch(c -> c.severity() == Severity.FAIL);
        return failed ? 1 : 0;
    }

    private void checkRequiredVariables(List<CheckResult> checks, ConfigSnapshot config) {
        for (String variable : InstallationRequirements.REQUIRED_VARIABLES) {
            List<String> aliases = REQUIRED_PROPERTY_ALIASES.getOrDefault(variable, List.of());
            String springKey = toSpringCheckName(variable, aliases);
            ConfigSnapshot.ResolvedProperty resolved = config.resolveFirst(variable, aliases);

            if (resolved.found() && resolved.explicit() && resolved.value() != null && !resolved.value().isBlank()) {
                checks.add(new CheckResult(
                        Severity.PASS,
                        "Required variable",
                        springKey,
                        withSource("Configured", resolved.source())
                ));
            } else if (resolved.found() && resolved.explicit() && (resolved.value() == null || resolved.value().isBlank())) {
                checks.add(new CheckResult(
                        Severity.FAIL,
                        "Required variable",
                        springKey,
                        withSource("Defined but empty", resolved.source())
                ));
            } else if (applicationYamlDefaults.hasDefault(variable)) {
                checks.add(new CheckResult(
                        Severity.WARNING,
                        "Required variable",
                        springKey,
                        withSource("Not explicitly defined; using default value from application configuration", resolved.source())
                ));
            } else {
                checks.add(new CheckResult(
                        Severity.FAIL,
                        "Required variable",
                        springKey,
                        "Missing and no default value"
                ));
            }
        }
    }

    private String toSpringCheckName(String variable, List<String> aliases) {
        if (!aliases.isEmpty()) {
            return aliases.get(0);
        }
        return variable.toLowerCase(Locale.ROOT).replace('_', '.');
    }

    private String withSource(String base, String source) {
        if (source == null || source.isBlank()) {
            return base;
        }
        return base + " (" + source + ")";
    }

    private void checkDatabaseConfigurationWarnings(List<CheckResult> checks, ConfigSnapshot config) {
        String datasourceUrl = config.effective("spring.datasource.url");
        String datasourceUsername = config.effective("spring.datasource.username");
        String datasourcePassword = config.effective("spring.datasource.password");
        String driverClassName = config.effective("spring.datasource.driver-class-name");

        String defaultUrl = applicationYamlDefaults.defaultValue("APP_DATASOURCE_URL").orElse(null);
        String defaultUsername = applicationYamlDefaults.defaultValue("APP_DATASOURCE_USERNAME").orElse(null);
        String defaultPassword = applicationYamlDefaults.defaultValue("APP_DATASOURCE_PASSWORD").orElse(null);

        if (defaultUrl != null
                && defaultUsername != null
                && defaultPassword != null
                && defaultUrl.equals(datasourceUrl)
                && defaultUsername.equals(datasourceUsername)
                && defaultPassword.equals(datasourcePassword)) {
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

    private void checkTlsMaterial(List<CheckResult> checks, ConfigSnapshot config) {
        ConfigSnapshot.ResolvedProperty certificate = config.resolveFirst(
                "spring.ssl.bundle.pem.server.keystore.certificate", List.of());
        ConfigSnapshot.ResolvedProperty privateKey = config.resolveFirst(
                "spring.ssl.bundle.pem.server.keystore.private-key", List.of());
        ConfigSnapshot.ResolvedProperty privateKeyPassword = config.resolveFirst(
                "APP_TLS_PRIVATE_KEY_PASSWORD",
                List.of("spring.ssl.bundle.pem.server.keystore.private-key-password")
        );

        if (!certificate.found() || certificate.value() == null || certificate.value().isBlank()) {
            checks.add(new CheckResult(Severity.FAIL, "TLS material", "spring.ssl.bundle.pem.server.keystore.certificate",
                    "Missing certificate path"));
        } else {
            Path certificatePath = toPath(certificate.value());
            if (Files.isReadable(certificatePath)) {
                checks.add(new CheckResult(
                        Severity.PASS,
                        "TLS material",
                        "spring.ssl.bundle.pem.server.keystore.certificate",
                        withSource("Readable PEM certificate file: " + certificatePath, certificate.source())
                ));
            } else {
                checks.add(new CheckResult(
                        Severity.FAIL,
                        "TLS material",
                        "spring.ssl.bundle.pem.server.keystore.certificate",
                        withSource("Certificate file not found or unreadable: " + certificatePath, certificate.source())
                ));
            }
        }

        if (!privateKey.found() || privateKey.value() == null || privateKey.value().isBlank()) {
            checks.add(new CheckResult(Severity.FAIL, "TLS material", "spring.ssl.bundle.pem.server.keystore.private-key",
                    "Missing private key path"));
            return;
        }

        Path privateKeyPath = toPath(privateKey.value());
        if (!Files.isReadable(privateKeyPath)) {
            checks.add(new CheckResult(
                    Severity.FAIL,
                    "TLS material",
                    "spring.ssl.bundle.pem.server.keystore.private-key",
                    withSource("Private key file not found or unreadable: " + privateKeyPath, privateKey.source())
            ));
            return;
        }

        try {
            loadPrivateKey(privateKeyPath, privateKeyPassword.value());
            checks.add(new CheckResult(
                    Severity.PASS,
                    "TLS material",
                    "spring.ssl.bundle.pem.server.keystore.private-key",
                    withSource("Readable PEM private key file: " + privateKeyPath, privateKey.source())
            ));
        } catch (Exception exception) {
            checks.add(new CheckResult(
                    Severity.FAIL,
                    "TLS material",
                    "spring.ssl.bundle.pem.server.keystore.private-key",
                    withSource("Invalid private key material: " + rootCauseMessage(exception), privateKey.source())
            ));
        }
    }

    private boolean checkDatabaseConnection(List<CheckResult> checks, ConfigSnapshot config) {
        String url = config.effective("spring.datasource.url");
        String username = Optional.ofNullable(config.effective("spring.datasource.username")).orElse("");
        String password = Optional.ofNullable(config.effective("spring.datasource.password")).orElse("");
        String driverClassName = Optional.ofNullable(config.effective("spring.datasource.driver-class-name")).orElse("");

        if (url == null || url.isBlank()) {
            checks.add(new CheckResult(
                    Severity.FAIL,
                    "Database connection",
                    "Connection",
                    "spring.datasource.url is empty or missing"
            ));
            return false;
        }

        try {
            if (!driverClassName.isBlank()) {
                Class.forName(driverClassName);
            }
            try (Connection connection = DriverManager.getConnection(url, username, password)) {
                DatabaseMetaData metadata = connection.getMetaData();
                String product = metadata.getDatabaseProductName() + " " + metadata.getDatabaseProductVersion();
                checks.add(new CheckResult(
                        Severity.PASS,
                        "Database connection",
                        "Connection",
                        "Connected successfully to " + product
                ));
                return true;
            }
        } catch (Exception exception) {
            checks.add(new CheckResult(
                    Severity.FAIL,
                    "Database connection",
                    "Connection",
                    rootCauseMessage(exception)
            ));
            return false;
        }
    }

    private void checkSchema(List<CheckResult> checks, ConfigSnapshot config) {
        Map<String, Set<String>> expectedSchema;
        try {
            expectedSchema = loadExpectedSchemaFromLiquibase(config);
        } catch (Exception exception) {
            checks.add(new CheckResult(
                    Severity.FAIL,
                    "Schema check",
                    "Liquibase changelog",
                    "Unable to parse Liquibase changelog: " + rootCauseMessage(exception)
            ));
            return;
        }

        String url = config.effective("spring.datasource.url");
        String username = Optional.ofNullable(config.effective("spring.datasource.username")).orElse("");
        String password = Optional.ofNullable(config.effective("spring.datasource.password")).orElse("");

        try (Connection connection = DriverManager.getConnection(url, username, password)) {
            DatabaseMetaData metadata = connection.getMetaData();

            for (Map.Entry<String, Set<String>> tableEntry : expectedSchema.entrySet()) {
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
                    rootCauseMessage(exception)
            ));
        }
    }

    private Map<String, Set<String>> loadExpectedSchemaFromLiquibase(ConfigSnapshot config) throws Exception {
        String configuredChangeLog = Optional.ofNullable(config.effective("spring.liquibase.change-log"))
                .orElse("classpath:db/changelog/db.changelog-master.json");
        String changeLogPath = configuredChangeLog.startsWith("classpath:")
                ? configuredChangeLog.substring("classpath:".length())
                : configuredChangeLog;

        ResourceAccessor accessor = new ClassLoaderResourceAccessor(Thread.currentThread().getContextClassLoader());
        DatabaseChangeLog databaseChangeLog = ChangeLogParserFactory.getInstance()
                .getParser(changeLogPath, accessor)
                .parse(changeLogPath, new ChangeLogParameters(), accessor);

        Map<String, Set<String>> expected = new LinkedHashMap<>();
        for (ChangeSet changeSet : databaseChangeLog.getChangeSets()) {
            for (Change change : changeSet.getChanges()) {
                if (change instanceof CreateTableChange createTableChange) {
                    String tableName = createTableChange.getTableName();
                    if (tableName == null || tableName.isBlank()) {
                        continue;
                    }

                    Set<String> columns = expected.computeIfAbsent(
                            tableName.toLowerCase(Locale.ROOT),
                            ignored -> new LinkedHashSet<>()
                    );
                    createTableChange.getColumns().forEach(columnConfig -> {
                        if (columnConfig.getName() != null && !columnConfig.getName().isBlank()) {
                            columns.add(columnConfig.getName().toLowerCase(Locale.ROOT));
                        }
                    });
                }
            }
        }
        return expected;
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

    private boolean isH2(String datasourceUrl, String driverClassName) {
        String normalizedUrl = Optional.ofNullable(datasourceUrl).orElse("").toLowerCase(Locale.ROOT);
        String normalizedDriver = Optional.ofNullable(driverClassName).orElse("").toLowerCase(Locale.ROOT);
        return normalizedUrl.contains(":h2:") || normalizedDriver.contains("h2");
    }

    private void writeReportToFile(Path outputFile, String report) throws IOException {
        Path parent = outputFile.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(outputFile, report, StandardCharsets.UTF_8);
    }

    private String rootCauseMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current.getMessage() == null ? current.getClass().getSimpleName() : current.getMessage();
    }

    private Path toPath(String value) {
        if (value.startsWith("file:")) {
            return Path.of(value.substring("file:".length()));
        }
        return Path.of(value);
    }

    private PrivateKey loadPrivateKey(Path path, String password) throws Exception {
        try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8);
             PEMParser parser = new PEMParser(reader)) {
            Object object;
            while ((object = parser.readObject()) != null) {
                if (object instanceof PEMKeyPair keyPair) {
                    return new JcaPEMKeyConverter().getKeyPair(keyPair).getPrivate();
                }
                if (object instanceof PKCS8EncryptedPrivateKeyInfo encrypted) {
                    if (password == null || password.isBlank()) {
                        throw new IllegalArgumentException("Encrypted PEM private key requires password");
                    }
                    var provider = new JcePKCSPBEInputDecryptorProviderBuilder().build(password.toCharArray());
                    return new JcaPEMKeyConverter().getPrivateKey(encrypted.decryptPrivateKeyInfo(provider));
                }
                if (object instanceof PrivateKeyInfo keyInfo) {
                    return new JcaPEMKeyConverter().getPrivateKey(keyInfo);
                }
            }
        }
        throw new IllegalArgumentException("No supported private key found in PEM file");
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

    private record ParsedArgs(Map<String, String> values, Optional<Path> outputFile) {
        static ParsedArgs parse(String[] args) {
            Map<String, String> values = new LinkedHashMap<>();
            Optional<Path> outputFile = Optional.empty();

            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if (arg == null || !arg.startsWith("--")) {
                    continue;
                }

                String body = arg.substring(2);
                int eq = body.indexOf('=');
                if (eq > 0) {
                    String key = body.substring(0, eq);
                    String value = body.substring(eq + 1);
                    values.put(key, value);
                    if ("to-file".equals(key) && !value.isBlank()) {
                        outputFile = Optional.of(Path.of(value.trim()));
                    }
                } else {
                    String key = body;
                    if ("to-file".equals(key) && i + 1 < args.length) {
                        String value = args[i + 1];
                        if (value != null && !value.startsWith("--") && !value.isBlank()) {
                            outputFile = Optional.of(Path.of(value.trim()));
                            values.put(key, value.trim());
                            i++;
                            continue;
                        }
                    }
                    values.putIfAbsent(key, "true");
                }
            }

            return new ParsedArgs(values, outputFile);
        }
    }

    private static final class ConfigSnapshot {
        private final Map<String, String> mergedFileProperties;
        private final Map<String, String> mergedFileSources;
        private final Map<String, String> args;
        private final Map<String, String> env;

        private ConfigSnapshot(
                Map<String, String> mergedFileProperties,
                Map<String, String> mergedFileSources,
                Map<String, String> args,
                Map<String, String> env
        ) {
            this.mergedFileProperties = mergedFileProperties;
            this.mergedFileSources = mergedFileSources;
            this.args = args;
            this.env = env;
        }

        static ConfigSnapshot load(ParsedArgs parsedArgs) {
            Map<String, String> merged = new LinkedHashMap<>();
            Map<String, String> sources = new LinkedHashMap<>();
            loadClasspathProperties(merged, sources, "application.properties");
            loadClasspathYaml(merged, sources, "application.yml");
            loadClasspathYaml(merged, sources, "application.yaml");
            loadFileProperties(merged, sources, Path.of("./application.properties"), "./application.properties");
            loadFileYaml(merged, sources, Path.of("./application.yml"), "./application.yml");
            loadFileYaml(merged, sources, Path.of("./application.yaml"), "./application.yaml");
            loadFileProperties(merged, sources, Path.of("./config/application.properties"), "./config/application.properties");
            loadFileYaml(merged, sources, Path.of("./config/application.yml"), "./config/application.yml");
            loadFileYaml(merged, sources, Path.of("./config/application.yaml"), "./config/application.yaml");
            return new ConfigSnapshot(merged, sources, parsedArgs.values(), System.getenv());
        }

        String effective(String key) {
            ResolvedProperty resolved = resolveKey(key);
            if (!resolved.found()) {
                return null;
            }
            return resolved.value();
        }

        ResolvedProperty resolveFirst(String variable, List<String> aliases) {
            for (String key : allLookupKeys(variable, aliases)) {
                ResolvedProperty resolved = resolveKey(key);
                if (resolved.found()) {
                    return resolved;
                }
            }
            return ResolvedProperty.notFound();
        }

        private ResolvedProperty resolveKey(String key) {
            String arg = args.get(key);
            if (arg != null) {
                return resolveValue(arg, "arg:--" + key, true, 0);
            }

            String envKey = toEnvStyle(key);
            if (env.containsKey(envKey)) {
                return resolveValue(env.get(envKey), "env:" + envKey, true, 0);
            }

            String system = System.getProperty(key);
            if (system != null) {
                return resolveValue(system, "system-property:" + key, true, 0);
            }

            if (mergedFileProperties.containsKey(key)) {
                String raw = mergedFileProperties.get(key);
                String source = mergedFileSources.getOrDefault(key, "unknown-source");
                boolean explicit = raw == null || !raw.trim().startsWith("${");
                return resolveValue(raw, source, explicit, 0);
            }
            return ResolvedProperty.notFound();
        }

        private ResolvedProperty resolveValue(String raw, String source, boolean explicit, int depth) {
            if (raw == null || depth > 10) {
                return new ResolvedProperty(raw, source, explicit, true);
            }
            String value = raw.trim();
            Matcher matcher = PLACEHOLDER_PATTERN.matcher(value);
            if (!matcher.matches()) {
                return new ResolvedProperty(value, source, explicit, true);
            }

            String variable = matcher.group(1).trim();
            String defaultPart = matcher.group(2) == null ? "" : matcher.group(2).trim();

            ResolvedProperty placeholderResolved = lookupByExactName(variable);
            if (placeholderResolved.found()) {
                return resolveValue(placeholderResolved.value(), placeholderResolved.source(), true, depth + 1);
            }
            return resolveValue(defaultPart, source, false, depth + 1);
        }

        private ResolvedProperty lookupByExactName(String name) {
            String arg = args.get(name);
            if (arg != null) {
                return new ResolvedProperty(arg, "arg:--" + name, true, true);
            }

            if (env.containsKey(name)) {
                return new ResolvedProperty(env.get(name), "env:" + name, true, true);
            }

            String sys = System.getProperty(name);
            if (sys != null) {
                return new ResolvedProperty(sys, "system-property:" + name, true, true);
            }

            if (mergedFileProperties.containsKey(name)) {
                return new ResolvedProperty(
                        mergedFileProperties.get(name),
                        mergedFileSources.getOrDefault(name, "unknown-source"),
                        true,
                        true
                );
            }
            return ResolvedProperty.notFound();
        }

        private List<String> allLookupKeys(String variable, List<String> aliases) {
            List<String> keys = new ArrayList<>();
            keys.add(variable);
            keys.add(toPropertyKey(variable));
            keys.addAll(aliases);
            return keys;
        }

        private static String toPropertyKey(String variableName) {
            return variableName.toLowerCase(Locale.ROOT).replace('_', '.');
        }

        private static String toEnvStyle(String key) {
            return key.replace('.', '_').replace('-', '_').toUpperCase(Locale.ROOT);
        }

        private static void loadClasspathProperties(
                Map<String, String> target,
                Map<String, String> sources,
                String classpathResource
        ) {
            try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(classpathResource)) {
                if (in == null) {
                    return;
                }
                java.util.Properties properties = new java.util.Properties();
                properties.load(in);
                for (String name : properties.stringPropertyNames()) {
                    target.put(name, properties.getProperty(name));
                    sources.put(name, "classpath:" + classpathResource);
                }
            } catch (Exception ignored) {
            }
        }

        private static void loadClasspathYaml(
                Map<String, String> target,
                Map<String, String> sources,
                String classpathResource
        ) {
            try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(classpathResource)) {
                if (in == null) {
                    return;
                }
                flattenYaml(target, sources, in, "classpath:" + classpathResource);
            } catch (Exception ignored) {
            }
        }

        private static void loadFileProperties(
                Map<String, String> target,
                Map<String, String> sources,
                Path file,
                String sourceLabel
        ) {
            if (!Files.exists(file)) {
                return;
            }
            try (InputStream in = Files.newInputStream(file)) {
                java.util.Properties properties = new java.util.Properties();
                properties.load(in);
                for (String name : properties.stringPropertyNames()) {
                    target.put(name, properties.getProperty(name));
                    sources.put(name, sourceLabel);
                }
            } catch (Exception ignored) {
            }
        }

        private static void loadFileYaml(
                Map<String, String> target,
                Map<String, String> sources,
                Path file,
                String sourceLabel
        ) {
            if (!Files.exists(file)) {
                return;
            }
            try (InputStream in = Files.newInputStream(file)) {
                flattenYaml(target, sources, in, sourceLabel);
            } catch (Exception ignored) {
            }
        }

        @SuppressWarnings("unchecked")
        private static void flattenYaml(Map<String, String> target, Map<String, String> sources, InputStream in, String sourceLabel) {
            Object loaded = new Yaml().load(in);
            if (!(loaded instanceof Map<?, ?> root)) {
                return;
            }
            flattenMap(target, sources, "", (Map<String, Object>) root, sourceLabel);
        }

        @SuppressWarnings("unchecked")
        private static void flattenMap(
                Map<String, String> target,
                Map<String, String> sources,
                String prefix,
                Map<String, Object> map,
                String sourceLabel
        ) {
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
                Object value = entry.getValue();
                if (value instanceof Map<?, ?> nested) {
                    flattenMap(target, sources, key, (Map<String, Object>) nested, sourceLabel);
                } else if (value != null) {
                    target.put(key, String.valueOf(value));
                    sources.put(key, sourceLabel);
                } else {
                    target.put(key, "");
                    sources.put(key, sourceLabel);
                }
            }
        }

        private record ResolvedProperty(String value, String source, boolean explicit, boolean found) {
            static ResolvedProperty notFound() {
                return new ResolvedProperty(null, null, false, false);
            }
        }
    }
}
