package es.zaleos.ssl.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.zaleos.certificate.renewer.core.PemTlsMaterialImporter;
import es.zaleos.certificate.renewer.spring.boot.autoconfigure.CertificateRenewerProperties;
import es.zaleos.certificate.renewer.spring.boot.runtime.TargetPathsResolver;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

/**
 * Sends authenticated maintenance requests against the starter's remote API.
 */
@Component
public class MaintenanceJwsRequestService {

    public enum AuthMode {
        JWS,
        JWT
    }

    private static final String DEFAULT_TARGET = "web-server";
    private static final String MAINTENANCE_CLAIM = "zaleos.certificates.maintenance";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final TargetPathsResolver targetResolver;
    private final CertificateRenewerProperties certificateProperties;
    private final Environment environment;
    private final PemTlsMaterialImporter pemTlsMaterialImporter = new PemTlsMaterialImporter();

    public MaintenanceJwsRequestService(
            TargetPathsResolver targetResolver,
            CertificateRenewerProperties certificateProperties,
            Environment environment
    ) {
        this.targetResolver = targetResolver;
        this.certificateProperties = certificateProperties;
        this.environment = environment;
    }

    public InvocationResult importFromFolder(
            String baseUrl,
            String targetName,
            String sourceDirectory,
            String password,
            AuthMode authMode,
            boolean useWrongCertificate
    ) throws Exception {
        Path sourcePath = Path.of(sourceDirectory);
        Map<String, String> form = new LinkedHashMap<>();
        form.put("target", targetName);
        form.put("sourceDir", sourceDirectory);
        if (password != null && !password.isBlank()) {
            form.put("password", password);
        }
        return sendFormRequest(
                baseUrl + certificateProperties.getMaintenance().getImportFromFolder().getPath(),
                form,
                buildClaims("import-and-activate", targetName),
                authMode,
                resolveSigningPrivateKey(useWrongCertificate, sourcePath, password),
                useWrongCertificate
        );
    }

    public InvocationResult importUpload(
            String baseUrl,
            String targetName,
            MultipartFile fullchain,
            MultipartFile privateKey,
            String password,
            AuthMode authMode,
            boolean useWrongCertificate
    ) throws Exception {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("target", targetName);
        if (password != null && !password.isBlank()) {
            fields.put("password", password);
        }

        List<MultipartPart> parts = new ArrayList<>();
        parts.add(new MultipartPart("fullchain", fullchain.getOriginalFilename(), fullchain.getContentType(), fullchain.getBytes()));
        parts.add(new MultipartPart("privateKey", privateKey.getOriginalFilename(), privateKey.getContentType(), privateKey.getBytes()));

        Path uploadedSourceDir = null;
        try {
            if (useWrongCertificate) {
                uploadedSourceDir = Files.createTempDirectory("maintenance-upload-signing-");
                fullchain.transferTo(uploadedSourceDir.resolve("fullchain.pem"));
                privateKey.transferTo(uploadedSourceDir.resolve("private-key.pem"));
            }

            return sendMultipartRequest(
                    baseUrl + certificateProperties.getMaintenance().getImportUpload().getPath(),
                    fields,
                    parts,
                    buildClaims("import-and-activate", targetName),
                    authMode,
                    resolveSigningPrivateKey(useWrongCertificate, uploadedSourceDir, password),
                    useWrongCertificate
            );
        } finally {
            deleteQuietly(uploadedSourceDir);
        }
    }

    private InvocationResult sendFormRequest(
            String endpointUrl,
            Map<String, String> formFields,
            Map<String, Object> claims,
            AuthMode authMode,
            PrivateKey signingPrivateKey,
            boolean usedWrongCertificate
    ) throws Exception {
        String formBody = encodeForm(formFields);
        HttpRequest request = baseRequest(endpointUrl, claims, authMode, signingPrivateKey)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody, StandardCharsets.UTF_8))
                .build();
        return execute(endpointUrl, claims, authMode, usedWrongCertificate, request);
    }

    private InvocationResult sendMultipartRequest(
            String endpointUrl,
            Map<String, String> formFields,
            List<MultipartPart> fileParts,
            Map<String, Object> claims,
            AuthMode authMode,
            PrivateKey signingPrivateKey,
            boolean usedWrongCertificate
    ) throws Exception {
        String boundary = "----zaleos-" + UUID.randomUUID();
        byte[] body = buildMultipartBody(boundary, formFields, fileParts);
        HttpRequest request = baseRequest(endpointUrl, claims, authMode, signingPrivateKey)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        return execute(endpointUrl, claims, authMode, usedWrongCertificate, request);
    }

    private InvocationResult execute(
            String endpointUrl,
            Map<String, Object> claims,
            AuthMode authMode,
            boolean usedWrongCertificate,
            HttpRequest request
    ) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .sslContext(createSslContext())
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        String responseBody = response.body() == null || response.body().isBlank()
                ? "(empty response body)"
                : response.body();
        return new InvocationResult(endpointUrl, response.statusCode(), claims, responseBody, authMode, usedWrongCertificate);
    }

    private HttpRequest.Builder baseRequest(
            String endpointUrl,
            Map<String, Object> claims,
            AuthMode authMode,
            PrivateKey signingPrivateKey
    ) throws Exception {
        String token = signClaims(claims, signingPrivateKey, authMode);
        return HttpRequest.newBuilder(URI.create(endpointUrl))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json");
    }

    private Map<String, Object> buildClaims(String operation, String targetName) {
        Instant now = Instant.now();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(MAINTENANCE_CLAIM, true);
        claims.put("op", operation);
        claims.put("target", targetName);
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plusSeconds(300).getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        return claims;
    }

    private String signClaims(
            Map<String, Object> claims,
            PrivateKey privateKey,
            AuthMode authMode
    ) throws Exception {
        String alg = jwsAlgorithm(privateKey);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", authMode == AuthMode.JWT ? "JWT" : "JWS");

        String headerPart = base64UrlEncode(OBJECT_MAPPER.writeValueAsBytes(header));
        String payloadPart = base64UrlEncode(OBJECT_MAPPER.writeValueAsBytes(claims));
        String signingInput = headerPart + "." + payloadPart;

        Signature signature = Signature.getInstance(jcaSignatureAlgorithm(alg));
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + base64UrlEncode(signature.sign());
    }

    private String base64UrlEncode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private String jwsAlgorithm(PrivateKey privateKey) {
        return switch (privateKey.getAlgorithm().toUpperCase(Locale.ROOT)) {
            case "RSA" -> "RS256";
            case "EC" -> "ES256";
            default -> throw new IllegalArgumentException("Unsupported private key algorithm for JWS: " + privateKey.getAlgorithm());
        };
    }

    private String jcaSignatureAlgorithm(String jwsAlgorithm) {
        return switch (jwsAlgorithm) {
            case "RS256" -> "SHA256withRSA";
            case "ES256" -> "SHA256withECDSA";
            default -> throw new IllegalArgumentException("Unsupported JWS algorithm: " + jwsAlgorithm);
        };
    }

    private PrivateKey resolveSigningPrivateKey(
            boolean useWrongCertificate,
            Path sourcePath,
            String sourcePassword
    ) throws Exception {
        if (useWrongCertificate) {
            if (sourcePath == null) {
                throw new IllegalArgumentException("The selected operation does not provide source material for an incorrect signer.");
            }
            return loadPrivateKeyFromImportSource(sourcePath, sourcePassword);
        }
        return loadCurrentWebServerPrivateKey();
    }

    private PrivateKey loadPrivateKeyFromImportSource(Path sourcePath, String sourcePassword) throws Exception {
        return pemTlsMaterialImporter.importFrom(
                sourcePath,
                null,
                sourcePassword == null ? new char[0] : sourcePassword.toCharArray()
        ).privateKey();
    }

    private PrivateKey loadCurrentWebServerPrivateKey() throws Exception {
        Path privateKeyPath = targetResolver.resolve(DEFAULT_TARGET).privateKeyPath();
        if (privateKeyPath == null || !Files.isReadable(privateKeyPath)) {
            throw new IllegalStateException("Cannot load the current signing key from target 'web-server'");
        }
        return loadPrivateKey(privateKeyPath, resolvePrivateKeyPassword());
    }

    private String resolvePrivateKeyPassword() {
        String bundleName = environment.getProperty("server.ssl.bundle");
        if (bundleName != null && !bundleName.isBlank()) {
            String bundlePassword = environment.getProperty(
                    "spring.ssl.bundle.pem." + bundleName + ".keystore.private-key-password");
            if (bundlePassword != null && !bundlePassword.isBlank()) {
                return bundlePassword;
            }
        }
        return certificateProperties.getOutput().getPrivateKeyPassword();
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

    private SSLContext createSslContext() throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null);
        X509Certificate certificate = loadCurrentTlsCertificate();
        trustStore.setCertificateEntry("local-server", certificate);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, new SecureRandom());
        return sslContext;
    }

    private X509Certificate loadCurrentTlsCertificate() throws Exception {
        var targetPaths = targetResolver.resolve(DEFAULT_TARGET);
        Path certificatePath = targetPaths.fullChainPath() != null
                ? targetPaths.fullChainPath()
                : targetPaths.certificatePath();
        if (certificatePath == null || !Files.isReadable(certificatePath)) {
            throw new IllegalStateException("Cannot load current HTTPS certificate from target 'web-server'");
        }
        try (var input = Files.newInputStream(certificatePath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (Certificate certificate : factory.generateCertificates(input)) {
                if (certificate instanceof X509Certificate x509Certificate) {
                    return x509Certificate;
                }
            }
        }
        throw new IllegalStateException("No X.509 certificate found for target 'web-server'");
    }

    private String encodeForm(Map<String, String> fields) {
        return fields.entrySet().stream()
                .map(entry -> urlEncode(entry.getKey()) + "=" + urlEncode(entry.getValue()))
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private byte[] buildMultipartBody(
            String boundary,
            Map<String, String> fields,
            List<MultipartPart> fileParts
    ) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        for (Map.Entry<String, String> entry : fields.entrySet()) {
            writeUtf8(output, "--" + boundary + "\r\n");
            writeUtf8(output, "Content-Disposition: form-data; name=\"" + entry.getKey() + "\"\r\n\r\n");
            writeUtf8(output, entry.getValue() + "\r\n");
        }

        for (MultipartPart part : fileParts) {
            writeUtf8(output, "--" + boundary + "\r\n");
            writeUtf8(output, "Content-Disposition: form-data; name=\"" + part.fieldName() + "\"; filename=\""
                    + sanitizeFilename(part.fileName()) + "\"\r\n");
            writeUtf8(output, "Content-Type: " + contentType(part.contentType()) + "\r\n\r\n");
            output.write(part.content());
            writeUtf8(output, "\r\n");
        }

        writeUtf8(output, "--" + boundary + "--\r\n");
        return output.toByteArray();
    }

    private void writeUtf8(ByteArrayOutputStream output, String value) throws IOException {
        output.write(value.getBytes(StandardCharsets.UTF_8));
    }

    private String sanitizeFilename(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return "upload.pem";
        }
        return fileName.replace("\"", "");
    }

    private String contentType(String value) {
        return value == null || value.isBlank() ? "application/octet-stream" : value;
    }

    private void deleteQuietly(Path directory) {
        if (directory == null) {
            return;
        }
        try (var walk = Files.walk(directory)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }

    public record InvocationResult(
            String endpointUrl,
            int statusCode,
            Map<String, Object> claims,
            String responseBody,
            AuthMode authMode,
            boolean usedWrongCertificate
    ) {
    }

    private record MultipartPart(
            String fieldName,
            String fileName,
            String contentType,
            byte[] content
    ) {
    }
}
