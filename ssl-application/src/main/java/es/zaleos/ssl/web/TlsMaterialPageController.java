package es.zaleos.ssl.web;

import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.runtime.TargetPathsResolver;
import es.zaleos.certificate.renewer.spring.boot.runtime.TlsMaterialService;
import es.zaleos.ssl.cli.TlsMaterialImporter;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequestMapping("${app.tls-page.path:/certificate-renewal}")
public class TlsMaterialPageController {

    private static final String DEFAULT_TARGET = "web-server";
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    private final TlsMaterialImporter tlsMaterialImporter;
    private final TlsMaterialService tlsMaterialService;
    private final MaintenanceJwsRequestService maintenanceRequestService;
    private final TargetPathsResolver targetResolver;
    private final CertificateRenewerProperties certificateProperties;

    @Value("${app.tls-page.target-name:web-server}")
    private String defaultTargetName;

    public TlsMaterialPageController(
            TlsMaterialImporter tlsMaterialImporter,
            TlsMaterialService tlsMaterialService,
            MaintenanceJwsRequestService maintenanceRequestService,
            TargetPathsResolver targetResolver,
            CertificateRenewerProperties certificateProperties
    ) {
        this.tlsMaterialImporter = tlsMaterialImporter;
        this.tlsMaterialService = tlsMaterialService;
        this.maintenanceRequestService = maintenanceRequestService;
        this.targetResolver = targetResolver;
        this.certificateProperties = certificateProperties;
    }

    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> page(
            HttpServletRequest request,
            @RequestParam(value = "target", required = false) String requestedTarget
    ) {
        return renderForTarget(request, requestedTarget, null);
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> submit(
            HttpServletRequest request,
            @RequestParam(value = "target", required = false) String requestedTarget,
            @RequestParam(value = "authMode", required = false, defaultValue = "no-auth") String requestedAuthMode,
            @RequestParam(value = "useWrongCertificate", required = false, defaultValue = "false") boolean useWrongCertificate,
            @RequestParam("operation") String operation,
            @RequestParam(value = "directory", required = false) String directory,
            @RequestParam(value = "password", required = false, defaultValue = "") String password,
            @RequestParam(value = "fullchain", required = false) MultipartFile fullchain,
            @RequestParam(value = "privateKey", required = false) MultipartFile privateKey
    ) {
        String targetName;
        try {
            targetName = resolveTargetName(requestedTarget);
        } catch (IllegalArgumentException exception) {
            return invalidTargetResponse(request, requestedTarget, exception.getMessage());
        }

        AuthMode authMode = AuthMode.from(requestedAuthMode);
        PemTlsTargetPaths targetPaths = targetResolver.resolve(targetName);
        boolean backupAvailable = backupAvailable(targetPaths);
        CertificateDetails before = loadCertificate(resolveCertificatePath(targetPaths)).orElse(null);

        OperationView view;
        try {
            view = switch (operation) {
                case "import-folder" -> handleFolderImport(
                        request,
                        targetName,
                        authMode,
                        useWrongCertificate,
                        directory,
                        password,
                        before
                );
                case "import-upload" -> handleUploadImport(
                        request,
                        targetName,
                        authMode,
                        useWrongCertificate,
                        password,
                        fullchain,
                        privateKey,
                        before
                );
                case "rollback" -> handleRollback(targetName, before, backupAvailable);
                default -> throw new IllegalArgumentException("Unknown operation: " + operation);
            };
        } catch (Exception exception) {
            CertificateDetails after = loadCertificate(resolveCertificatePath(targetPaths)).orElse(before);
            view = new OperationView(
                    "Error during operation: " + exception.getMessage(),
                    true,
                    targetName,
                    authMode,
                    useWrongCertificate,
                    before,
                    after,
                    backupAvailable,
                    null,
                    operationLabel(operation),
                    authMode == AuthMode.NO_AUTH && useWrongCertificate
                            ? "The wrong certificate option only applies to JWS/JWT authentication."
                            : null,
                    directory == null ? "" : directory,
                    password
            );
        }

        return renderForTarget(request, targetName, view);
    }

    private OperationView handleFolderImport(
            HttpServletRequest request,
            String targetName,
            AuthMode authMode,
            boolean useWrongCertificate,
            String directory,
            String password,
            CertificateDetails before
    ) throws Exception {
        if (!StringUtils.hasText(directory)) {
            throw new IllegalArgumentException("Directory is required for folder import.");
        }

        Path sourcePath = Path.of(directory.trim());
        MaintenanceJwsRequestService.InvocationResult remoteResult = null;
        boolean remoteError = false;
        if (authMode == AuthMode.NO_AUTH) {
            tlsMaterialImporter.importAndActivate(targetName, sourcePath, null, password.toCharArray(), true);
        } else {
            remoteResult = maintenanceRequestService.importFromFolder(
                    baseUrl(request),
                    targetName,
                    sourcePath.toString(),
                    password,
                    authMode.toRemoteMode(),
                    useWrongCertificate
            );
            remoteError = remoteResult.statusCode() >= 400;
        }

        CertificateDetails after = loadCertificate(resolveCertificatePath(targetResolver.resolve(targetName))).orElse(null);
        return new OperationView(
                remoteError
                        ? "Remote folder import failed with HTTP " + remoteResult.statusCode() + "."
                        : successMessage(targetName, authMode, "Folder import completed."),
                remoteError,
                targetName,
                authMode,
                useWrongCertificate,
                before,
                after,
                backupAvailable(targetResolver.resolve(targetName)),
                remoteResult,
                "Import from directory",
                authMode == AuthMode.NO_AUTH && useWrongCertificate
                        ? "The wrong certificate option is ignored when no-auth is selected."
                        : null,
                sourcePath.toString(),
                password
        );
    }

    private OperationView handleUploadImport(
            HttpServletRequest request,
            String targetName,
            AuthMode authMode,
            boolean useWrongCertificate,
            String password,
            MultipartFile fullchain,
            MultipartFile privateKey,
            CertificateDetails before
    ) throws Exception {
        if (fullchain == null || fullchain.isEmpty()) {
            throw new IllegalArgumentException("fullchain file is required for upload import.");
        }
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("privateKey file is required for upload import.");
        }

        MaintenanceJwsRequestService.InvocationResult remoteResult = null;
        boolean remoteError = false;
        if (authMode == AuthMode.NO_AUTH) {
            Path tempDir = null;
            try {
                tempDir = Files.createTempDirectory("tls-page-upload-");
                fullchain.transferTo(tempDir.resolve("fullchain.pem"));
                privateKey.transferTo(tempDir.resolve("private-key.pem"));
                tlsMaterialImporter.importAndActivate(targetName, tempDir, null, password.toCharArray(), true);
            } finally {
                deleteQuietly(tempDir);
            }
        } else {
            remoteResult = maintenanceRequestService.importUpload(
                    baseUrl(request),
                    targetName,
                    fullchain,
                    privateKey,
                    password,
                    authMode.toRemoteMode(),
                    useWrongCertificate
            );
            remoteError = remoteResult.statusCode() >= 400;
        }

        CertificateDetails after = loadCertificate(resolveCertificatePath(targetResolver.resolve(targetName))).orElse(null);
        return new OperationView(
                remoteError
                        ? "Remote upload import failed with HTTP " + remoteResult.statusCode() + "."
                        : successMessage(targetName, authMode, "Upload import completed."),
                remoteError,
                targetName,
                authMode,
                useWrongCertificate,
                before,
                after,
                backupAvailable(targetResolver.resolve(targetName)),
                remoteResult,
                "Import uploaded PEM",
                authMode == AuthMode.NO_AUTH && useWrongCertificate
                        ? "The wrong certificate option is ignored when no-auth is selected."
                        : null,
                "",
                password
        );
    }

    private OperationView handleRollback(
            String targetName,
            CertificateDetails before,
            boolean backupAvailable
    ) throws Exception {
        if (!backupAvailable) {
            throw new IllegalStateException("No backup files are available for the selected target.");
        }

        tlsMaterialService.rollback(targetName, isWebServerTarget(targetName));
        CertificateDetails after = loadCertificate(resolveCertificatePath(targetResolver.resolve(targetName))).orElse(null);
        return new OperationView(
                "Rollback completed.",
                false,
                targetName,
                AuthMode.NO_AUTH,
                false,
                before,
                after,
                backupAvailable(targetResolver.resolve(targetName)),
                null,
                "Rollback",
                null,
                "",
                ""
        );
    }

    private ResponseEntity<String> renderForTarget(
            HttpServletRequest request,
            String requestedTarget,
            OperationView view
    ) {
        String targetName;
        try {
            targetName = resolveTargetName(requestedTarget);
        } catch (IllegalArgumentException exception) {
            return invalidTargetResponse(request, requestedTarget, exception.getMessage());
        }

        PemTlsTargetPaths targetPaths = targetResolver.resolve(targetName);
        CertificateDetails current = loadCertificate(resolveCertificatePath(targetPaths)).orElse(null);
        boolean backupAvailable = backupAvailable(targetPaths);
        String html = renderPage(
                targetName,
                current,
                backupAvailable,
                view
        );
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    private ResponseEntity<String> invalidTargetResponse(
            HttpServletRequest request,
            String requestedTarget,
            String message
    ) {
        String fallbackTarget = availableTargets().get(0);
        OperationView view = new OperationView(
                "Error during operation: " + message,
                true,
                fallbackTarget,
                AuthMode.NO_AUTH,
                false,
                null,
                null,
                backupAvailable(targetResolver.resolve(fallbackTarget)),
                null,
                "Target selection",
                null,
                "",
                ""
        );
        return renderForTarget(request, fallbackTarget, view);
    }

    private String resolveTargetName(String requestedTarget) {
        String candidate = StringUtils.hasText(requestedTarget) ? requestedTarget.trim() : defaultTargetName;
        if (!StringUtils.hasText(candidate)) {
            return DEFAULT_TARGET;
        }
        if (DEFAULT_TARGET.equals(candidate) || candidate.equals(defaultTargetName)) {
            return candidate;
        }
        if (certificateProperties.getTargets().containsKey(candidate)) {
            return candidate;
        }
        throw new IllegalArgumentException("Unknown certificate target: " + candidate);
    }

    private List<String> availableTargets() {
        LinkedHashSet<String> targetNames = new LinkedHashSet<>();
        targetNames.add(defaultTargetName);
        targetNames.add(DEFAULT_TARGET);
        targetNames.addAll(certificateProperties.getTargets().keySet());
        return targetNames.stream().filter(StringUtils::hasText).toList();
    }

    private boolean isWebServerTarget(String targetName) {
        return DEFAULT_TARGET.equals(targetName);
    }

    private boolean backupAvailable(PemTlsTargetPaths targetPaths) {
        for (Path activePath : targetPaths.activePaths()) {
            if (Files.exists(Path.of(activePath + ".bak"))) {
                return true;
            }
        }
        return false;
    }

    private String baseUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
    }

    private String successMessage(String targetName, AuthMode authMode, String prefix) {
        if (authMode == AuthMode.NO_AUTH) {
            return prefix + " This path uses the same Spring-managed import flow as the CLI command.";
        }
        if (isWebServerTarget(targetName)) {
            return prefix + " The request went through the authenticated maintenance API and asked the HTTPS server to reload immediately.";
        }
        return prefix + " The request went through the authenticated maintenance API for the selected named target.";
    }

    private String operationLabel(String operation) {
        return switch (operation) {
            case "import-folder" -> "Import from directory";
            case "import-upload" -> "Import uploaded PEM";
            case "rollback" -> "Rollback";
            default -> operation;
        };
    }

    private Path resolveCertificatePath(PemTlsTargetPaths targetPaths) {
        if (targetPaths.fullChainPath() != null) {
            return targetPaths.fullChainPath();
        }
        return targetPaths.certificatePath();
    }

    private Optional<CertificateDetails> loadCertificate(Path certificatePath) {
        try {
            if (certificatePath == null || !Files.exists(certificatePath)) {
                return Optional.empty();
            }

            try (InputStream input = Files.newInputStream(certificatePath)) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                for (Certificate certificate : factory.generateCertificates(input)) {
                    if (certificate instanceof X509Certificate x509) {
                        return Optional.of(new CertificateDetails(
                                x509.getSubjectX500Principal().getName(),
                                x509.getIssuerX500Principal().getName(),
                                x509.getSerialNumber().toString(16),
                                DATE_FORMAT.format(x509.getNotBefore().toInstant().atOffset(ZoneOffset.UTC)),
                                DATE_FORMAT.format(x509.getNotAfter().toInstant().atOffset(ZoneOffset.UTC)),
                                fingerprintSha256(x509)
                        ));
                    }
                }
            }
            return Optional.empty();
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    private String fingerprintSha256(X509Certificate certificate) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = digest.digest(certificate.getEncoded());
        List<String> hex = new ArrayList<>();
        for (byte b : bytes) {
            hex.add(String.format("%02X", b));
        }
        return String.join(":", hex);
    }

    private String renderPage(
            String targetName,
            CertificateDetails current,
            boolean backupAvailable,
            OperationView view
    ) {
        String selectedAuthMode = view != null ? view.authMode().parameterValue() : AuthMode.NO_AUTH.parameterValue();
        boolean useWrongCertificate = view != null && view.useWrongCertificate();
        StringBuilder html = new StringBuilder();
        html.append("<!doctype html><html><head><meta charset='UTF-8'><title>Certificate Renewal Demo</title>")
                .append("<style>")
                .append("body{font-family:Arial,sans-serif;max-width:1120px;margin:24px auto;padding:0 18px;background:#f7f8fb;color:#1f2937}")
                .append("a{color:#0f4c81;text-decoration:none}a:hover{text-decoration:underline}")
                .append("h1{margin-bottom:8px}h2{margin:18px 0 12px}h3{margin:16px 0 8px}")
                .append(".top-links{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 18px}")
                .append(".card{background:#fff;border:1px solid #d8dee9;border-radius:10px;padding:20px 22px;box-shadow:0 1px 3px rgba(15,23,42,.06)}")
                .append(".muted{color:#526071}")
                .append(".ok-banner{background:#eefbf1;border:1px solid #b7e4c7;border-radius:8px;padding:12px 14px;margin:0 0 14px}")
                .append(".err-banner{background:#fff1f2;border:1px solid #fecdd3;border-radius:8px;padding:12px 14px;margin:0 0 14px}")
                .append("table{border-collapse:collapse;width:100%}")
                .append(".data-table th,.data-table td,.form-table td{border:1px solid #d8dee9;padding:10px;vertical-align:top;text-align:left}")
                .append(".data-table th,.form-table .label{width:28%;background:#f8fafc;font-weight:600;color:#334155}")
                .append("input[type='text'],input[type='password'],input[type='file'],select{width:100%;max-width:100%;padding:9px 10px;border:1px solid #cbd5e1;border-radius:6px;box-sizing:border-box;background:#fff}")
                .append("input[type='checkbox']{transform:scale(1.15)}")
                .append("button{padding:10px 14px;border:none;border-radius:6px;background:#0f4c81;color:#fff;cursor:pointer;margin-right:10px;margin-top:8px}")
                .append("button:hover{background:#0c3d67}")
                .append("button.secondary{background:#475569}")
                .append("button.secondary:hover{background:#334155}")
                .append("button.warn{background:#9a3412}")
                .append("button.warn:hover{background:#7c2d12}")
                .append("code,pre{background:#f1f5f9;border-radius:6px}")
                .append("code{padding:2px 4px}")
                .append("pre{padding:12px;overflow:auto;white-space:pre-wrap}")
                .append("hr{border:none;border-top:1px solid #d8dee9;margin:18px 0}")
                .append("</style></head><body>")
                .append("<div class='top-links'><a href='/'>Index</a></div>")
                .append("<h1>Certificate Renewal Demo</h1>")
                .append("<p class='muted'>Use this page to test successful and failing certificate operations through the local flow and the authenticated maintenance API.</p>")
                .append("<div class='card'>");

        if (view != null && view.message() != null) {
            html.append("<div class='").append(view.error() ? "err-banner" : "ok-banner").append("'><strong>")
                    .append(escapeHtml(view.message())).append("</strong></div>");
        }
        if (view != null && view.note() != null) {
            html.append("<p class='muted'>").append(escapeHtml(view.note())).append("</p>");
        }

        html.append("<h2>Current target state</h2>")
                .append("<table class='data-table'>")
                .append("<tr><th>Destination target</th><td><code>").append(escapeHtml(targetName)).append("</code></td></tr>")
                .append("<tr><th>Available targets</th><td><code>").append(escapeHtml(String.join(", ", availableTargets()))).append("</code></td></tr>")
                .append("<tr><th>Backup available</th><td>").append(backupAvailable ? "Yes" : "No").append("</td></tr>")
                .append("<tr><th>Current certificate path</th><td><code>")
                .append(escapeHtml(String.valueOf(resolveCertificatePath(targetResolver.resolve(targetName))))).append("</code></td></tr>")
                .append("<tr><th>Current private key path</th><td><code>")
                .append(escapeHtml(String.valueOf(targetResolver.resolve(targetName).privateKeyPath()))).append("</code></td></tr>")
                .append("</table>")
                .append("<h2>Configured validation policy</h2>")
                .append(renderPolicyTable(targetName))
                .append("<p class='muted'>Bootstrap placeholder certificates ending in <code>.installation.local</code> always allow the first replacement: the validator skips the <code>same-*</code> checks for that first import. If <code>expected-root-ca</code> is configured, that trust-anchor check still applies.</p>")
                .append("<h2>Scenario guide for generated test certificates</h2>")
                .append(renderScenarioGuide())
                .append("<h2>Recommended scenarios per target</h2>")
                .append(renderTargetLegend())
                .append("<h3>Current certificate</h3>")
                .append(renderCertificateTable(current))
                .append("<hr>")
                .append("<h2>Run certificate operation</h2>")
                .append("<form method='post' action='' enctype='multipart/form-data'>")
                .append("<table class='form-table'>")
                .append("<tr><td class='label'>Authentication</td><td>")
                .append(renderAuthModeSelect(selectedAuthMode))
                .append("<div class='muted'>Use <code>no-auth</code> for the direct local import path, or <code>JWS/JWT</code> for the remote maintenance API.</div>")
                .append("</td></tr>")
                .append("<tr><td class='label'>Use incorrect certificate</td><td>")
                .append("<label><input type='checkbox' name='useWrongCertificate' value='true'")
                .append(useWrongCertificate ? " checked" : "")
                .append("> Sign JWS/JWT requests with the source certificate material instead of the current web-server certificate.</label>")
                .append("</td></tr>")
                .append("<tr><td class='label'>Destination target</td><td>").append(renderTargetSelect(targetName)).append("</td></tr>")
                .append("</table>")
                .append("<hr>")
                .append("<table class='form-table'>")
                .append("<tr><td class='label'>Directory</td><td><input name='directory' value='")
                .append(escapeHtml(view != null ? view.directory() : ""))
                .append("'><div class='muted'>Used by the directory import action. Example: <code>/workspace/testdata/certs/180d-pem</code></div></td></tr>")
                .append("<tr><td class='label'>Full chain</td><td><input type='file' name='fullchain' accept='.pem,.crt,.cer'></td></tr>")
                .append("<tr><td class='label'>Private key</td><td><input type='file' name='privateKey' accept='.pem,.key'></td></tr>")
                .append("<tr><td class='label'>Password</td><td><input type='password' name='password' value='")
                .append(escapeHtml(view != null ? view.password() : ""))
                .append("'><div class='muted'>Only needed when the source material is encrypted.</div></td></tr>")
                .append("<tr><td class='label'>Actions</td><td>")
                .append("<button type='submit' name='operation' value='import-folder'>Import from directory</button>")
                .append("<button class='secondary' type='submit' name='operation' value='import-upload'>Import uploaded PEM</button>");

        if (backupAvailable) {
            html.append("<button class='warn' type='submit' name='operation' value='rollback'>Rollback current backup</button>");
        }

        html.append("</td></tr>")
                .append("</table>")
                .append("</form>");

        if (view != null) {
            html.append("<hr>")
                    .append("<h2>Operation result</h2>")
                    .append("<table class='data-table'>")
                    .append("<tr><th>Operation</th><td>").append(escapeHtml(view.operationLabel())).append("</td></tr>")
                    .append("<tr><th>Authentication</th><td><code>").append(escapeHtml(view.authMode().parameterValue())).append("</code></td></tr>")
                    .append("<tr><th>Wrong certificate</th><td>").append(view.useWrongCertificate() ? "Yes" : "No").append("</td></tr>")
                    .append("<tr><th>Detected change</th><td>")
                    .append(certificatesChanged(view.before(), view.after()) ? "Yes" : "No")
                    .append("</td></tr>")
                    .append("</table>")
                    .append("<h3>Before</h3>")
                    .append(renderCertificateTable(view.before()))
                    .append("<h3>After</h3>")
                    .append(renderCertificateTable(view.after()));

            if (view.remoteResult() != null) {
                html.append("<h3>Remote maintenance response</h3>")
                        .append("<table class='data-table'>")
                        .append("<tr><th>Endpoint URL</th><td><code>").append(escapeHtml(view.remoteResult().endpointUrl())).append("</code></td></tr>")
                        .append("<tr><th>HTTP status</th><td><code>").append(view.remoteResult().statusCode()).append("</code></td></tr>")
                        .append("<tr><th>Token type</th><td><code>").append(escapeHtml(view.remoteResult().authMode().name())).append("</code></td></tr>")
                        .append("<tr><th>Claims</th><td><pre>").append(escapeHtml(view.remoteResult().claims().toString())).append("</pre></td></tr>")
                        .append("</table>")
                        .append("<h3>Response body</h3>")
                        .append("<pre>").append(escapeHtml(view.remoteResult().responseBody())).append("</pre>");
            }
        }

        html.append("</div></body></html>");
        return html.toString();
    }

    private boolean certificatesChanged(CertificateDetails before, CertificateDetails after) {
        if (before == null || after == null) {
            return !Objects.equals(before, after);
        }
        return !Objects.equals(before.sha256(), after.sha256());
    }

    private String renderAuthModeSelect(String selectedValue) {
        StringBuilder html = new StringBuilder("<select name='authMode'>");
        for (AuthMode mode : AuthMode.values()) {
            html.append("<option value='").append(mode.parameterValue()).append("'");
            if (mode.parameterValue().equals(selectedValue)) {
                html.append(" selected");
            }
            html.append(">").append(escapeHtml(mode.parameterValue())).append("</option>");
        }
        html.append("</select>");
        return html.toString();
    }

    private String renderTargetSelect(String selectedTarget) {
        StringBuilder html = new StringBuilder("<select name='target'>");
        for (String target : availableTargets()) {
            html.append("<option value='").append(escapeHtml(target)).append("'");
            if (target.equals(selectedTarget)) {
                html.append(" selected");
            }
            html.append(">").append(escapeHtml(target)).append("</option>");
        }
        html.append("</select>");
        return html.toString();
    }

    private String renderCertificateTable(CertificateDetails details) {
        if (details == null) {
            return "<p>Not available (certificate path missing or invalid).</p>";
        }
        return "<table class='data-table'>"
                + "<tr><th>Subject</th><td>" + escapeHtml(details.subject()) + "</td></tr>"
                + "<tr><th>Issuer</th><td>" + escapeHtml(details.issuer()) + "</td></tr>"
                + "<tr><th>Serial</th><td>" + escapeHtml(details.serial()) + "</td></tr>"
                + "<tr><th>Not Before (UTC)</th><td>" + escapeHtml(details.notBefore()) + "</td></tr>"
                + "<tr><th>Not After (UTC)</th><td>" + escapeHtml(details.notAfter()) + "</td></tr>"
                + "<tr><th>SHA-256</th><td>" + escapeHtml(details.sha256()) + "</td></tr>"
                + "</table>";
    }

    private String renderPolicyTable(String targetName) {
        EffectivePolicyInfo policy = effectivePolicy(targetName);
        return "<table class='data-table'>"
                + "<tr><th>Target</th><td><code>" + escapeHtml(targetName) + "</code></td></tr>"
                + "<tr><th>same-root-ca</th><td>" + booleanText(policy.sameRootCa()) + "</td></tr>"
                + "<tr><th>same-chain</th><td>" + booleanText(policy.sameChain()) + "</td></tr>"
                + "<tr><th>same-subject</th><td>" + booleanText(policy.sameSubject()) + "</td></tr>"
                + "<tr><th>same-san</th><td>" + booleanText(policy.sameSan()) + "</td></tr>"
                + "<tr><th>same-public-key</th><td>" + booleanText(policy.samePublicKey()) + "</td></tr>"
                + "<tr><th>minimum-key-algorithm</th><td><code>" + escapeHtml(policy.minimumKeyAlgorithm()) + "</code></td></tr>"
                + "<tr><th>minimum-key-size</th><td><code>" + escapeHtml(String.valueOf(policy.minimumKeySize())) + "</code></td></tr>"
                + "<tr><th>expected-root-ca</th><td><code>" + escapeHtml(policy.expectedRootCaDescription()) + "</code></td></tr>"
                + "<tr><th>Per-target note</th><td>" + escapeHtml(policy.note()) + "</td></tr>"
                + "</table>";
    }

    private EffectivePolicyInfo effectivePolicy(String targetName) {
        CertificateRenewerProperties.Policy defaults = certificateProperties.getPolicy();
        CertificateRenewerProperties.Target target = certificateProperties.getTargets().get(targetName);
        CertificateRenewerProperties.TargetPolicy overrides = target == null ? null : target.getPolicy();

        boolean sameRootCa = overrides != null && overrides.getSameRootCa() != null
                ? overrides.getSameRootCa()
                : defaults.isSameRootCa();
        boolean sameChain = overrides != null && overrides.getSameChain() != null
                ? overrides.getSameChain()
                : defaults.isSameChain();
        boolean sameSubject = overrides != null && overrides.getSameSubject() != null
                ? overrides.getSameSubject()
                : defaults.isSameSubject();
        boolean sameSan = overrides != null && overrides.getSameSan() != null
                ? overrides.getSameSan()
                : defaults.isSameSan();
        boolean samePublicKey = overrides != null && overrides.getSamePublicKey() != null
                ? overrides.getSamePublicKey()
                : defaults.isSamePublicKey();
        String minimumKeyAlgorithm = overrides != null && StringUtils.hasText(overrides.getMinimumKeyAlgorithm())
                ? overrides.getMinimumKeyAlgorithm()
                : defaults.getMinimumKeyAlgorithm();
        Integer minimumKeySize = overrides != null && overrides.getMinimumKeySize() != null
                ? overrides.getMinimumKeySize()
                : defaults.getMinimumKeySize();
        String expectedRootCa = overrides != null && StringUtils.hasText(overrides.getExpectedRootCa())
                ? overrides.getExpectedRootCa()
                : defaults.getExpectedRootCa();

        String note = samePublicKey
                ? "This target keeps the default strict policy."
                : "This target relaxes same-public-key to allow key rotation.";

        return new EffectivePolicyInfo(
                sameRootCa,
                sameChain,
                sameSubject,
                sameSan,
                samePublicKey,
                minimumKeyAlgorithm,
                minimumKeySize,
                StringUtils.hasText(expectedRootCa) ? expectedRootCa : "(not configured in this demo)",
                note
        );
    }

    private String renderScenarioGuide() {
        return "<table class='data-table'>"
                + "<tr><th>Valid sequence</th><td><code>180d-pem</code> first, then <code>360d-pem</code>. They were generated to keep the same root CA, chain, subject, SAN and public key, so they match the default strict policy.</td></tr>"
                + "<tr><th>Root / anchor failures</th><td><code>bad-different-root-ca-pem</code> changes the issuing root, so it is the one to use for <code>same-root-ca</code> and, if configured, <code>expected-root-ca</code>.</td></tr>"
                + "<tr><th>Other same-* failures</th><td><code>bad-different-chain-pem</code>, <code>bad-different-subject-pem</code>, <code>bad-different-san-pem</code> and <code>bad-different-public-key-pem</code> each change exactly one strict-validation aspect.</td></tr>"
                + "<tr><th>Algorithm / size failures</th><td><code>bad-minimum-key-size-pem</code> uses RSA 1024 and <code>bad-minimum-key-algorithm-pem</code> uses EC. These are useful when the target is still on the bootstrap placeholder or when the <code>same-*</code> checks have been relaxed.</td></tr>"
                + "<tr><th>Bootstrap warning</th><td>The auto-generated installation certificate is a bootstrap placeholder. It is expected to accept the first replacement even when the final target policy is strict.</td></tr>"
                + "</table>";
    }

    private String renderTargetLegend() {
        return "<table class='data-table'>"
                + "<tr><th><code>web-server</code></th><td>Use <code>180d-pem</code> for the first replacement and then <code>360d-pem</code> for the valid renewal. For negative checks, the strict policy makes <code>bad-different-root-ca-pem</code>, <code>bad-different-chain-pem</code>, <code>bad-different-subject-pem</code>, <code>bad-different-san-pem</code> and <code>bad-different-public-key-pem</code> the most representative scenarios.</td></tr>"
                + "<tr><th><code>jwt-signer</code></th><td>This target relaxes <code>same-public-key</code>, so it is a good place to test key rotation with <code>bad-different-public-key-pem</code>. It also accepts the valid path <code>180d-pem</code> then <code>360d-pem</code>. While it is still on the bootstrap placeholder, it is also useful for <code>bad-minimum-key-size-pem</code> and <code>bad-minimum-key-algorithm-pem</code>.</td></tr>"
                + "<tr><th><code>jwt-verifier</code></th><td>Use the same recommendations as <code>jwt-signer</code>: valid renewal with <code>180d-pem</code> then <code>360d-pem</code>, key-rotation checks with <code>bad-different-public-key-pem</code>, and bootstrap-only tests with <code>bad-minimum-key-size-pem</code> or <code>bad-minimum-key-algorithm-pem</code>.</td></tr>"
                + "</table>";
    }

    private String booleanText(boolean value) {
        return value ? "Yes" : "No";
    }

    private void deleteQuietly(Path dir) {
        if (dir == null) {
            return;
        }
        try (var walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private enum AuthMode {
        NO_AUTH("no-auth"),
        JWS("jws"),
        JWT("jwt");

        private final String parameterValue;

        AuthMode(String parameterValue) {
            this.parameterValue = parameterValue;
        }

        public String parameterValue() {
            return parameterValue;
        }

        public MaintenanceJwsRequestService.AuthMode toRemoteMode() {
            return this == JWT ? MaintenanceJwsRequestService.AuthMode.JWT : MaintenanceJwsRequestService.AuthMode.JWS;
        }

        public static AuthMode from(String value) {
            if (!StringUtils.hasText(value)) {
                return NO_AUTH;
            }
            return switch (value.trim().toLowerCase()) {
                case "jws" -> JWS;
                case "jwt" -> JWT;
                default -> NO_AUTH;
            };
        }
    }

    private record CertificateDetails(
            String subject,
            String issuer,
            String serial,
            String notBefore,
            String notAfter,
            String sha256
    ) {
    }

    private record OperationView(
            String message,
            boolean error,
            String targetName,
            AuthMode authMode,
            boolean useWrongCertificate,
            CertificateDetails before,
            CertificateDetails after,
            boolean backupAvailable,
            MaintenanceJwsRequestService.InvocationResult remoteResult,
            String operationLabel,
            String note,
            String directory,
            String password
    ) {
    }

    private record EffectivePolicyInfo(
            boolean sameRootCa,
            boolean sameChain,
            boolean sameSubject,
            boolean sameSan,
            boolean samePublicKey,
            String minimumKeyAlgorithm,
            Integer minimumKeySize,
            String expectedRootCaDescription,
            String note
    ) {
    }
}
