package com.example.ssl.web;

import com.example.ssl.cli.CertificateImport;
import com.example.ssl.cli.CertificateRenewer;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Enumeration;
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
@RequestMapping("${app.certificate-page.path:/certificate-renewal}")
public class CertificateRenewalPageController {

    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    private final CertificateRenewer certificateRenewer;

    @Value("${app.certificate-page.target-keystore:./target/classes/ssl/keystore.p12}")
    private String targetKeystore;

    @Value("${app.certificate-page.alias:ssl-app}")
    private String alias;

    @Value("${server.ssl.key-store-password:changeit}")
    private String currentKeystorePassword;

    @Value("${server.ssl.key-password:}")
    private String currentKeyPassword;

    public CertificateRenewalPageController(CertificateRenewer certificateRenewer) {
        this.certificateRenewer = certificateRenewer;
    }

    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> page() {
        CertificateDetails current = loadCertificate(Path.of(targetKeystore), currentKeystorePassword.toCharArray(), alias)
                .orElse(null);
        String html = renderPage(null, null, null, current, null, null);
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    @PostMapping(produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public ResponseEntity<String> renew(
            @RequestParam("directory") String directory,
            @RequestParam("password") String password
    ) {
        Path sourceDirectory = Path.of(directory.trim());
        Path keystorePath = Path.of(targetKeystore);
        char[] formPassword = password.toCharArray();
        char[] keystorePassword = currentKeystorePassword.toCharArray();
        char[] keyPassword = currentKeyPassword == null || currentKeyPassword.isBlank()
                ? keystorePassword
                : currentKeyPassword.toCharArray();

        CertificateDetails oldCert = loadCertificate(keystorePath, keystorePassword, alias).orElse(null);

        try {
            CertificateImport.ImportResult result = certificateRenewer.renew(
                    sourceDirectory,
                    keystorePath,
                    keystorePassword,
                    keyPassword,
                    alias,
                    null,
                    formPassword
            );

            CertificateDetails newCert = loadCertificate(keystorePath, keystorePassword, alias).orElse(null);
            String message = "Renovación completada. Fuente=" + result.certificatePath()
                    + ", expira=" + result.expirationDate();
            String html = renderPage(message, sourceDirectory.toString(), password, newCert, oldCert, newCert);
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
        } catch (Exception exception) {
            String html = renderPage(
                    "Error en renovación: " + exception.getMessage(),
                    sourceDirectory.toString(),
                    password,
                    oldCert,
                    oldCert,
                    null
            );
            return ResponseEntity.badRequest().contentType(MediaType.TEXT_HTML).body(html);
        }
    }

    private Optional<CertificateDetails> loadCertificate(Path keystorePath, char[] password, String requestedAlias) {
        try {
            if (!keystorePath.toFile().exists()) {
                return Optional.empty();
            }

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (var input = java.nio.file.Files.newInputStream(keystorePath)) {
                keyStore.load(input, password);
            }

            String effectiveAlias = requestedAlias;
            if (!keyStore.containsAlias(effectiveAlias)) {
                effectiveAlias = firstAlias(keyStore).orElse(null);
            }
            if (effectiveAlias == null) {
                return Optional.empty();
            }

            var certificate = keyStore.getCertificate(effectiveAlias);
            if (!(certificate instanceof X509Certificate x509)) {
                return Optional.empty();
            }

            return Optional.of(new CertificateDetails(
                    effectiveAlias,
                    x509.getSubjectX500Principal().getName(),
                    x509.getIssuerX500Principal().getName(),
                    x509.getSerialNumber().toString(16),
                    DATE_FORMAT.format(x509.getNotBefore().toInstant().atOffset(ZoneOffset.UTC)),
                    DATE_FORMAT.format(x509.getNotAfter().toInstant().atOffset(ZoneOffset.UTC)),
                    fingerprintSha256(x509)
            ));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    private Optional<String> firstAlias(KeyStore keyStore) throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        if (aliases.hasMoreElements()) {
            return Optional.ofNullable(aliases.nextElement());
        }
        return Optional.empty();
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
            CertificateDetails newCert
    ) {
        StringBuilder html = new StringBuilder();
        html.append("<!doctype html><html><head><meta charset='UTF-8'><title>Renovación de certificado</title>")
                .append("<style>body{font-family:Arial,sans-serif;max-width:980px;margin:24px auto;padding:0 16px}")
                .append("table{border-collapse:collapse;width:100%;margin:8px 0 18px}th,td{border:1px solid #ccc;padding:8px;text-align:left}")
                .append("input{padding:8px;margin-right:8px}button{padding:8px 12px}.ok{color:#0b7a0b}.err{color:#a40000}</style>")
                .append("</head><body>")
                .append("<h1>Renovación de certificado SSL</h1>")
                .append("<p>Keystore destino: <code>").append(escapeHtml(targetKeystore)).append("</code></p>")
                .append("<p>Alias preferido: <code>").append(escapeHtml(alias)).append("</code></p>");

        if (message != null) {
            boolean isError = message.startsWith("Error");
            html.append("<p class='").append(isError ? "err" : "ok").append("'><strong>")
                    .append(escapeHtml(message)).append("</strong></p>");
            html.append("<p><a href=''>Refrescar página</a></p>");
        }

        html.append("<h2>Formulario</h2>")
                .append("<form method='post' action=''>")
                .append("<label>Directorio: <input name='directory' size='60' required value='")
                .append(escapeHtml(directory == null ? "" : directory)).append("'></label>")
                .append("<label>Password: <input type='password' name='password' required value='")
                .append(escapeHtml(password == null ? "" : password)).append("'></label>")
                .append("<button type='submit'>Renovar certificado</button>")
                .append("</form>")
                .append("<p>Nota: el password del formulario se usa para el material del certificado de entrada. ")
                .append("El keystore destino mantiene la clave configurada en server.ssl.</p>");

        html.append("<h2>Certificado actual</h2>").append(renderCertificateTable(current));

        if (oldCert != null || newCert != null) {
            html.append("<h2>Comparativa tras POST</h2>")
                    .append("<h3>Antes</h3>").append(renderCertificateTable(oldCert))
                    .append("<h3>Después</h3>").append(renderCertificateTable(newCert));
        }

        html.append("</body></html>");
        return html.toString();
    }

    private String renderCertificateTable(CertificateDetails details) {
        if (details == null) {
            return "<p>No disponible (keystore/alias/password no válido).</p>";
        }
        return "<table>"
                + "<tr><th>Alias</th><td>" + escapeHtml(details.alias()) + "</td></tr>"
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
            String alias,
            String subject,
            String issuer,
            String serial,
            String notBefore,
            String notAfter,
            String sha256
    ) {
    }
}
