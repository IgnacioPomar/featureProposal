package es.zaleos.ssl.web;

import es.zaleos.ssl.cli.TlsMaterialImporter;
import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import es.zaleos.certificate.renewer.spring.boot.runtime.TargetPathsResolver;
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
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequestMapping("${app.tls-page.path:/certificate-renewal}")
public class TlsMaterialPageController {

    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    private final TlsMaterialImporter tlsMaterialImporter;
    private final TargetPathsResolver targetResolver;

    @Value("${app.tls-page.target-name:web-server}")
    private String targetName;

    public TlsMaterialPageController(
            TlsMaterialImporter tlsMaterialImporter,
            TargetPathsResolver targetResolver
    ) {
        this.tlsMaterialImporter = tlsMaterialImporter;
        this.targetResolver = targetResolver;
    }

    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> page(HttpServletRequest request) {
        PemTlsTargetPaths targetPaths = targetResolver.resolve("web-server");
        CertificateDetails current = loadCertificate(targetPaths.fullChainPath()).orElse(null);
        String html = renderPage(
                null,
                null,
                null,
                current,
                null,
                null,
                false,
                false,
                request.getRequestURL().toString(),
                targetPaths
        );
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    @PostMapping(produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> importTlsMaterial(
            HttpServletRequest request,
            @RequestParam("directory") String directory,
            @RequestParam(value = "password", required = false, defaultValue = "") String password
    ) {
        Path sourceDirectory = Path.of(directory.trim());
        char[] formPassword = password.toCharArray();
        PemTlsTargetPaths targetPaths = targetResolver.resolve("web-server");

        CertificateDetails oldCert = loadCertificate(targetPaths.fullChainPath()).orElse(null);

        try {
            PemActivationResult result = tlsMaterialImporter.importAndActivate(
                    sourceDirectory,
                    null,
                    formPassword,
                    true
            );
            CertificateDetails newCert = loadCertificate(targetPaths.fullChainPath()).orElse(null);
            String message = "Directory import completed. The server requested an immediate TLS reload. "
                    + "This browser can keep using its existing TLS connection, so verify the new certificate "
                    + "from another browser, a private window, or a fresh TLS client connection.";
            String html = renderPage(
                    message,
                    sourceDirectory.toString(),
                    password,
                    null,
                    oldCert,
                    newCert,
                    true,
                    true,
                    request.getRequestURL().toString(),
                    targetPaths
            );
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
        } catch (Exception exception) {
            String html = renderPage(
                    "Error during import: " + exception.getMessage(),
                    sourceDirectory.toString(),
                    password,
                    oldCert,
                    null,
                    null,
                    true,
                    false,
                    request.getRequestURL().toString(),
                    targetPaths
            );
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_HTML).body(html);
        }
    }

    @PostMapping(
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.TEXT_HTML_VALUE
    )
    @ResponseBody
    public ResponseEntity<String> uploadTlsMaterial(
            HttpServletRequest request,
            @RequestParam("fullchain") MultipartFile fullchain,
            @RequestParam("privateKey") MultipartFile privateKey,
            @RequestParam(value = "password", required = false, defaultValue = "") String password
    ) {
        PemTlsTargetPaths targetPaths = targetResolver.resolve("web-server");
        CertificateDetails oldCert = loadCertificate(targetPaths.fullChainPath()).orElse(null);

        if (fullchain.isEmpty()) {
            String html = renderPage(
                    "Error during upload: fullchain file is empty.",
                    null,
                    "",
                    oldCert,
                    null,
                    null,
                    true,
                    false,
                    request.getRequestURL().toString(),
                    targetPaths
            );
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_HTML).body(html);
        }
        if (privateKey.isEmpty()) {
            String html = renderPage(
                    "Error during upload: privateKey file is empty.",
                    null,
                    "",
                    oldCert,
                    null,
                    null,
                    true,
                    false,
                    request.getRequestURL().toString(),
                    targetPaths
            );
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_HTML).body(html);
        }

        Path tempDir = null;
        try {
            tempDir = Files.createTempDirectory("tls-page-upload-");
            Path fullchainPath = tempDir.resolve("fullchain.pem");
            Path privateKeyPath = tempDir.resolve("private-key.pem");
            fullchain.transferTo(fullchainPath);
            privateKey.transferTo(privateKeyPath);

            PemActivationResult result = tlsMaterialImporter.importAndActivate(
                    tempDir,
                    null,
                    password.toCharArray(),
                    true
            );
            CertificateDetails newCert = loadCertificate(targetPaths.fullChainPath()).orElse(null);
            String message = "Upload import completed. The server requested an immediate TLS reload. "
                    + "This browser can keep using its existing TLS connection, so verify the new certificate "
                    + "from another browser, a private window, or a fresh TLS client connection.";
            String html = renderPage(
                    message,
                    null,
                    "",
                    null,
                    oldCert,
                    newCert,
                    true,
                    true,
                    request.getRequestURL().toString(),
                    targetPaths
            );
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
        } catch (Exception exception) {
            String html = renderPage(
                    "Error during upload: " + exception.getMessage(),
                    null,
                    "",
                    oldCert,
                    null,
                    null,
                    true,
                    false,
                    request.getRequestURL().toString(),
                    targetPaths
            );
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_HTML).body(html);
        } finally {
            deleteQuietly(tempDir);
        }
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
                                targetName,
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
            String message,
            String directory,
            String password,
            CertificateDetails current,
            CertificateDetails oldCert,
            CertificateDetails newCert,
            boolean formUsed,
            boolean successfulActivation,
            String pageUrl,
            PemTlsTargetPaths targetPaths
    ) {
        boolean showComparison = oldCert != null || newCert != null;
        StringBuilder html = new StringBuilder();
        html.append("<!doctype html><html><head><meta charset='UTF-8'><title>TLS Material Import</title>")
                .append("<style>")
                .append("body{font-family:Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 18px;background:#f7f8fb;color:#1f2937}")
                .append("h1{margin-bottom:8px}h2{margin:0 0 12px}h3{margin:16px 0 8px}")
                .append(".card{background:#fff;border:1px solid #d8dee9;border-radius:10px;padding:18px 20px;margin:0 0 18px;box-shadow:0 1px 3px rgba(15,23,42,.06)}")
                .append(".card p{margin:0 0 10px}.muted{color:#526071}")
                .append(".note{background:#eef6ff;border-color:#bfdbfe}")
                .append(".ok-banner{background:#eefbf1;border:1px solid #b7e4c7;border-radius:8px;padding:12px 14px;margin:0 0 14px}")
                .append(".err-banner{background:#fff1f2;border:1px solid #fecdd3;border-radius:8px;padding:12px 14px;margin:0 0 14px}")
                .append("table{border-collapse:collapse;width:100%}")
                .append(".data-table{margin:10px 0 0}.data-table th,.data-table td{border:1px solid #d8dee9;padding:10px;vertical-align:top;text-align:left}")
                .append(".data-table th{width:28%;background:#f8fafc;font-weight:600}")
                .append(".form-table{margin-top:10px}.form-table td{padding:10px;border-top:1px solid #e5e7eb;vertical-align:top}")
                .append(".form-table tr:first-child td{border-top:none}.form-table .label{width:28%;font-weight:600;color:#334155}")
                .append("input[type='text'],input[type='password'],input[type='file']{width:100%;max-width:100%;padding:9px 10px;border:1px solid #cbd5e1;border-radius:6px;box-sizing:border-box;background:#fff}")
                .append("button{padding:10px 14px;border:none;border-radius:6px;background:#0f4c81;color:#fff;cursor:pointer}")
                .append("button:hover{background:#0c3d67}")
                .append("code{background:#f1f5f9;padding:2px 4px;border-radius:4px}")
                .append(".copy-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.copy-row input{min-width:320px;flex:1}")
                .append("</style>")
                .append("<script>")
                .append("function copyVerificationLink(){")
                .append("const field=document.getElementById('verification-link');")
                .append("if(!field){return false;}")
                .append("const text=field.value;")
                .append("const status=document.getElementById('copy-status');")
                .append("if(navigator.clipboard&&navigator.clipboard.writeText){")
                .append("navigator.clipboard.writeText(text).then(function(){if(status){status.textContent='Link copied.';}})")
                .append(".catch(function(){field.select();document.execCommand('copy');if(status){status.textContent='Link copied.';}});")
                .append("}else{field.select();document.execCommand('copy');if(status){status.textContent='Link copied.';}}")
                .append("return false;}")
                .append("</script>")
                .append("</head><body>")
                .append("<h1>TLS Material Import</h1>")
                .append("<p class='muted'>Import PEM TLS material, activate it for the HTTPS server, and verify what certificate is currently installed.</p>");

        if (message != null) {
            boolean isError = message.startsWith("Error");
            html.append("<div class='").append(isError ? "err-banner" : "ok-banner").append("'><strong>")
                    .append(escapeHtml(message)).append("</strong></div>");
        }

        if (formUsed) {
            if (successfulActivation) {
                html.append(renderVerificationNote(pageUrl));
            }
            if (showComparison) {
                html.append(renderComparisonCard(oldCert, newCert));
            }
        }

        html.append(renderImportCard(directory, password));

        if (!formUsed) {
            html.append(renderInformationCard(current, pageUrl, targetPaths));
        }

        html.append("</body></html>");
        return html.toString();
    }

    private String renderVerificationNote(String pageUrl) {
        return new StringBuilder()
                .append("<div class='card note'>")
                .append("<h2>Verification</h2>")
                .append("<p>The server reload request has already been sent. The HTTPS server can switch immediately, ")
                .append("but this browser may keep using its existing TLS connection. If the old certificate is still shown, ")
                .append("open the same link from another browser, a private window, or another fresh TLS client connection.</p>")
                .append("<div class='copy-row'>")
                .append("<input id='verification-link' type='text' readonly value='").append(escapeHtml(pageUrl)).append("'>")
                .append("<button onclick='return copyVerificationLink();'>Copy link for another browser</button>")
                .append("<span id='copy-status'></span>")
                .append("</div>")
                .append("</div>")
                .toString();
    }

    private String renderComparisonCard(CertificateDetails oldCert, CertificateDetails newCert) {
        return new StringBuilder()
                .append("<div class='card'>")
                .append("<h2>Certificate comparison</h2>")
                .append("<h3>Before</h3>")
                .append(renderCertificateTable(oldCert))
                .append("<h3>After</h3>")
                .append(renderCertificateTable(newCert))
                .append("</div>")
                .toString();
    }

    private String renderImportCard(String directory, String password) {
        return new StringBuilder()
                .append("<div class='card'>")
                .append("<h2>Import</h2>")
                .append("<p class='muted'>Choose one of the supported import paths.</p>")
                .append("<table class='form-table'>")
                .append("<tr><td class='label'>Import from directory</td><td>")
                .append("<form method='post' action=''>")
                .append("<table class='form-table'>")
                .append("<tr><td class='label'>Directory</td><td><input name='directory' required value='")
                .append(escapeHtml(directory == null ? "" : directory)).append("'></td></tr>")
                .append("<tr><td class='label'>Password</td><td><input type='password' name='password' value='")
                .append(escapeHtml(password == null ? "" : password)).append("'></td></tr>")
                .append("<tr><td class='label'>Action</td><td><button type='submit'>Import and activate TLS material</button></td></tr>")
                .append("</table>")
                .append("</form>")
                .append("<p class='muted'>Use this when the PEM files already exist on the server. ")
                .append("The password is only needed when the input material requires it.</p>")
                .append("</td></tr>")
                .append("<tr><td class='label'>Upload PEM files</td><td>")
                .append("<form method='post' action='' enctype='multipart/form-data'>")
                .append("<table class='form-table'>")
                .append("<tr><td class='label'>Full chain</td><td><input type='file' name='fullchain' accept='.pem' required></td></tr>")
                .append("<tr><td class='label'>Private key</td><td><input type='file' name='privateKey' accept='.pem' required></td></tr>")
                .append("<tr><td class='label'>Password</td><td><input type='password' name='password'></td></tr>")
                .append("<tr><td class='label'>Action</td><td><button type='submit'>Upload and activate TLS material</button></td></tr>")
                .append("</table>")
                .append("</form>")
                .append("<p class='muted'>This matches the maintenance API upload flow: submit ")
                .append("<code>fullchain.pem</code> and <code>private-key.pem</code> directly from your workstation.</p>")
                .append("</td></tr>")
                .append("</table>")
                .append("</div>")
                .toString();
    }

    private String renderInformationCard(
            CertificateDetails current,
            String pageUrl,
            PemTlsTargetPaths targetPaths
    ) {
        return new StringBuilder()
                .append("<div class='card'>")
                .append("<h2>Variables affecting the certificate and its renewal</h2>")
                .append("<table class='data-table'>")
                .append("<tr><th>Target reference</th><td><code>").append(escapeHtml(targetName)).append("</code></td></tr>")
                .append("<tr><th>Verification link</th><td><code>").append(escapeHtml(pageUrl)).append("</code></td></tr>")
                .append("<tr><th>Certificate target path</th><td><code>")
                .append(escapeHtml(String.valueOf(targetPaths.fullChainPath()))).append("</code></td></tr>")
                .append("<tr><th>Private key target path</th><td><code>")
                .append(escapeHtml(String.valueOf(targetPaths.privateKeyPath()))).append("</code></td></tr>")
                .append("<tr><th>Supported import paths</th><td>Directory on server or PEM upload from workstation.</td></tr>")
                .append("</table>")
                .append("<h3>Current certificate</h3>")
                .append(renderCertificateTable(current))
                .append("</div>")
                .toString();
    }

    private String renderCertificateTable(CertificateDetails details) {
        if (details == null) {
            return "<p>Not available (certificate path missing or invalid).</p>";
        }
        return "<table class='data-table'>"
                + "<tr><th>Target</th><td>" + escapeHtml(details.target()) + "</td></tr>"
                + "<tr><th>Subject</th><td>" + escapeHtml(details.subject()) + "</td></tr>"
                + "<tr><th>Issuer</th><td>" + escapeHtml(details.issuer()) + "</td></tr>"
                + "<tr><th>Serial</th><td>" + escapeHtml(details.serial()) + "</td></tr>"
                + "<tr><th>Not Before (UTC)</th><td>" + escapeHtml(details.notBefore()) + "</td></tr>"
                + "<tr><th>Not After (UTC)</th><td>" + escapeHtml(details.notAfter()) + "</td></tr>"
                + "<tr><th>SHA-256</th><td>" + escapeHtml(details.sha256()) + "</td></tr>"
                + "</table>";
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

    private record CertificateDetails(
            String target,
            String subject,
            String issuer,
            String serial,
            String notBefore,
            String notAfter,
            String sha256
    ) {
    }
}
