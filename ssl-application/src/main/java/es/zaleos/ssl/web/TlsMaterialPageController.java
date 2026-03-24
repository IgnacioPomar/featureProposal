package es.zaleos.ssl.web;

import es.zaleos.ssl.cli.TlsMaterialImporter;
import es.zaleos.certificate.renewer.core.PemActivationResult;
import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import es.zaleos.certificate.renewer.spring.boot.runtime.TargetPathsResolver;
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
    public ResponseEntity<String> page() {
        PemTlsTargetPaths targetPaths = targetResolver.resolve("web-server");
        CertificateDetails current = loadCertificate(targetPaths.fullChainPath()).orElse(null);
        String html = renderPage(null, null, null, current, null, null, targetPaths);
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    @PostMapping(produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> importTlsMaterial(
            @RequestParam("directory") String directory,
            @RequestParam("password") String password
    ) {
        Path sourceDirectory = Path.of(directory.trim());
        char[] formPassword = password.toCharArray();
        PemTlsTargetPaths targetPaths = targetResolver.resolve("web-server");

        CertificateDetails oldCert = loadCertificate(targetPaths.fullChainPath()).orElse(null);

        try {
            PemActivationResult result = tlsMaterialImporter.importAndActivate(sourceDirectory, null, formPassword);
            CertificateDetails newCert = loadCertificate(targetPaths.fullChainPath()).orElse(null);
            String message = "Import and activation completed. Source=" + result.sourcePath()
                    + ", expires=" + result.expirationDate();
            String html = renderPage(message, sourceDirectory.toString(), password, newCert, oldCert, newCert, targetPaths);
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
        } catch (Exception exception) {
            String html = renderPage(
                    "Error during import: " + exception.getMessage(),
                    sourceDirectory.toString(),
                    password,
                    oldCert,
                    oldCert,
                    null,
                    targetPaths
            );
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_HTML).body(html);
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
            PemTlsTargetPaths targetPaths
    ) {
        StringBuilder html = new StringBuilder();
        html.append("<!doctype html><html><head><meta charset='UTF-8'><title>TLS Material Import</title>")
                .append("<style>body{font-family:Arial,sans-serif;max-width:980px;margin:24px auto;padding:0 16px}")
                .append("table{border-collapse:collapse;width:100%;margin:8px 0 18px}th,td{border:1px solid #ccc;padding:8px;text-align:left}")
                .append("input{padding:8px;margin-right:8px}button{padding:8px 12px}.ok{color:#0b7a0b}.err{color:#a40000}</style>")
                .append("</head><body>")
                .append("<h1>TLS Material Import</h1>")
                .append("<p>Certificate target: <code>").append(escapeHtml(String.valueOf(targetPaths.fullChainPath()))).append("</code></p>")
                .append("<p>Private key target: <code>").append(escapeHtml(String.valueOf(targetPaths.privateKeyPath()))).append("</code></p>")
                .append("<p>Target reference: <code>").append(escapeHtml(targetName)).append("</code></p>");

        if (message != null) {
            boolean isError = message.startsWith("Error");
            html.append("<p class='").append(isError ? "err" : "ok").append("'><strong>")
                    .append(escapeHtml(message)).append("</strong></p>");
            html.append("<p><a href=''>Refresh page</a></p>");
        }

        html.append("<h2>Form</h2>")
                .append("<form method='post' action=''>")
                .append("<label>Directory: <input name='directory' size='60' required value='")
                .append(escapeHtml(directory == null ? "" : directory)).append("'></label>")
                .append("<label>Password: <input type='password' name='password' required value='")
                .append(escapeHtml(password == null ? "" : password)).append("'></label>")
                .append("<button type='submit'>Import and activate TLS material</button>")
                .append("</form>")
                .append("<p>Note: the password in the form is used for the input certificate material when needed.</p>");

        html.append("<h2>Current certificate</h2>").append(renderCertificateTable(current));

        if (oldCert != null || newCert != null) {
            html.append("<h2>Comparison after POST</h2>")
                    .append("<h3>Before</h3>").append(renderCertificateTable(oldCert))
                    .append("<h3>After</h3>").append(renderCertificateTable(newCert));
        }

        html.append("</body></html>");
        return html.toString();
    }

    private String renderCertificateTable(CertificateDetails details) {
        if (details == null) {
            return "<p>Not available (certificate path missing or invalid).</p>";
        }
        return "<table>"
                + "<tr><th>Target</th><td>" + escapeHtml(details.target()) + "</td></tr>"
                + "<tr><th>Subject</th><td>" + escapeHtml(details.subject()) + "</td></tr>"
                + "<tr><th>Issuer</th><td>" + escapeHtml(details.issuer()) + "</td></tr>"
                + "<tr><th>Serial</th><td>" + escapeHtml(details.serial()) + "</td></tr>"
                + "<tr><th>Not Before (UTC)</th><td>" + escapeHtml(details.notBefore()) + "</td></tr>"
                + "<tr><th>Not After (UTC)</th><td>" + escapeHtml(details.notAfter()) + "</td></tr>"
                + "<tr><th>SHA-256</th><td>" + escapeHtml(details.sha256()) + "</td></tr>"
                + "</table>";
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
