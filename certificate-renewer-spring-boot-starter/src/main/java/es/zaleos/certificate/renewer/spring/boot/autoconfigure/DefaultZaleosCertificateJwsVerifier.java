package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import es.zaleos.certificate.renewer.core.PemTlsCurrentMaterialLoader;
import es.zaleos.certificate.renewer.core.PemTlsTargetPaths;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.event.EventListener;

/**
 * Default JWS verifier backed by the currently installed TLS material.
 *
 * <p>Parses compact JWS serialization (three Base64URL-encoded segments separated by dots).
 * Supports RSA and EC signatures via the standard JCA {@link Signature} API.
 * Automatically reloads trust material on {@link TlsMaterialActivatedEvent}.
 */
public class DefaultZaleosCertificateJwsVerifier implements ZaleosCertificateJwsVerifier {

    private static final Log LOG = LogFactory.getLog(DefaultZaleosCertificateJwsVerifier.class);

    private final ZaleosCertificateTargetResolver targetResolver;
    private final ZaleosCertificateProperties properties;
    private final PemTlsCurrentMaterialLoader materialLoader;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    private volatile PublicKey currentPublicKey;
    private volatile X509Certificate expectedRootCa;

    public DefaultZaleosCertificateJwsVerifier(
            ZaleosCertificateTargetResolver targetResolver,
            ZaleosCertificateProperties properties,
            PemTlsCurrentMaterialLoader materialLoader
    ) {
        this.targetResolver = targetResolver;
        this.properties = properties;
        this.materialLoader = materialLoader;
        reloadTrustMaterial();
    }

    @EventListener
    public void onTlsMaterialActivated(TlsMaterialActivatedEvent event) {
        reloadTrustMaterial();
    }

    @Override
    public void verify(String jwsCompact) {
        verifyAndExtractClaims(jwsCompact);
    }

    @Override
    public Map<String, Object> verifyAndExtractClaims(String jwsCompact) {
        String[] parts = splitJws(jwsCompact);
        byte[] headerBytes = base64UrlDecode(parts[0]);
        byte[] payloadBytes = base64UrlDecode(parts[1]);
        byte[] signatureBytes = base64UrlDecode(parts[2]);

        Map<String, Object> header = parseJsonObject(new String(headerBytes, StandardCharsets.UTF_8));

        PublicKey verificationKey;
        @SuppressWarnings("unchecked")
        List<String> x5c = (List<String>) header.get("x5c");
        if (x5c != null && !x5c.isEmpty()) {
            List<X509Certificate> chain = parseX5cChain(x5c);
            validateChain(chain);
            verificationKey = chain.get(0).getPublicKey();
        } else {
            lock.readLock().lock();
            try {
                verificationKey = currentPublicKey;
            } finally {
                lock.readLock().unlock();
            }
            if (verificationKey == null) {
                throw new JwsVerificationException("No installed certificate available for JWS verification");
            }
        }

        verifySignature(parts[0] + "." + parts[1], signatureBytes, verificationKey, header);

        return parseJsonObject(new String(payloadBytes, StandardCharsets.UTF_8));
    }

    private void reloadTrustMaterial() {
        lock.writeLock().lock();
        try {
            PemTlsTargetPaths paths = targetResolver.resolve("web-server");
            materialLoader.load(paths).ifPresentOrElse(
                    material -> currentPublicKey = material.leafCertificate().getPublicKey(),
                    () -> LOG.warn("No installed TLS material found for web-server target — JWS verification will fail")
            );
            String expectedRootCaLocation = properties.getPolicy().getExpectedRootCa();
            if (expectedRootCaLocation != null && !expectedRootCaLocation.isBlank()) {
                // Already loaded and available via policy resolver; re-read directly for the verifier
                try {
                    org.springframework.core.io.DefaultResourceLoader loader =
                            new org.springframework.core.io.DefaultResourceLoader();
                    org.springframework.core.io.Resource resource = loader.getResource(expectedRootCaLocation);
                    if (resource.exists()) {
                        try (var is = resource.getInputStream()) {
                            expectedRootCa = (X509Certificate) CertificateFactory
                                    .getInstance("X.509").generateCertificate(is);
                        }
                    }
                } catch (Exception e) {
                    LOG.warn("Could not reload expectedRootCa: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            LOG.warn("Failed to reload trust material for JWS verification: " + e.getMessage());
        } finally {
            lock.writeLock().unlock();
        }
    }

    private List<X509Certificate> parseX5cChain(List<String> x5c) {
        List<X509Certificate> chain = new ArrayList<>();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (String encoded : x5c) {
                byte[] derBytes = Base64.getDecoder().decode(encoded);
                chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(derBytes)));
            }
        } catch (Exception e) {
            throw new JwsVerificationException("Failed to parse x5c certificate chain: " + e.getMessage(), e);
        }
        return chain;
    }

    private void validateChain(List<X509Certificate> chain) {
        if (chain.isEmpty()) {
            throw new JwsVerificationException("x5c chain is empty");
        }
        X509Certificate root = chain.get(chain.size() - 1);
        X509Certificate pinned = expectedRootCa;
        if (pinned != null) {
            String rootFingerprint = fingerprint(root);
            String pinnedFingerprint = fingerprint(pinned);
            if (!rootFingerprint.equals(pinnedFingerprint)) {
                throw new JwsVerificationException(
                        "x5c chain root does not match the configured PCA trust anchor (expected-root-ca)");
            }
        }
        // Validate issuer/subject linkage in the chain
        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate cert = chain.get(i);
            X509Certificate issuerCert = chain.get(i + 1);
            if (!cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                throw new JwsVerificationException(
                        "x5c chain is broken at index " + i + ": issuer does not match next certificate's subject");
            }
            try {
                cert.verify(issuerCert.getPublicKey());
            } catch (Exception e) {
                throw new JwsVerificationException(
                        "x5c chain signature verification failed at index " + i + ": " + e.getMessage(), e);
            }
        }
    }

    private void verifySignature(String signingInput, byte[] signature, PublicKey publicKey,
            Map<String, Object> header) {
        String alg = (String) header.getOrDefault("alg", "RS256");
        String jcaAlgorithm = jwsAlgToJca(alg);
        try {
            Signature sig = Signature.getInstance(jcaAlgorithm);
            sig.initVerify(publicKey);
            sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            if (!sig.verify(signature)) {
                throw new JwsVerificationException("JWS signature verification failed");
            }
        } catch (JwsVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new JwsVerificationException("JWS signature verification error: " + e.getMessage(), e);
        }
    }

    private String jwsAlgToJca(String alg) {
        return switch (alg) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            case "ES256" -> "SHA256withECDSA";
            case "ES384" -> "SHA384withECDSA";
            case "ES512" -> "SHA512withECDSA";
            default -> throw new JwsVerificationException("Unsupported JWS algorithm: " + alg);
        };
    }

    private String[] splitJws(String jwsCompact) {
        String[] parts = jwsCompact.split("\\.");
        if (parts.length != 3) {
            throw new JwsVerificationException("Invalid JWS compact serialization: expected 3 parts, got " + parts.length);
        }
        return parts;
    }

    private byte[] base64UrlDecode(String input) {
        return Base64.getUrlDecoder().decode(input);
    }

    private String fingerprint(X509Certificate cert) {
        try {
            return Base64.getEncoder().encodeToString(cert.getEncoded());
        } catch (Exception e) {
            throw new JwsVerificationException("Cannot compute certificate fingerprint: " + e.getMessage(), e);
        }
    }

    /**
     * Minimal JSON object parser sufficient for JWS header and payload.
     * Handles string, number, boolean, array-of-strings, and null values.
     */
    private Map<String, Object> parseJsonObject(String json) {
        Map<String, Object> result = new HashMap<>();
        String content = json.trim();
        if (!content.startsWith("{") || !content.endsWith("}")) {
            return result;
        }
        content = content.substring(1, content.length() - 1).trim();
        int i = 0;
        while (i < content.length()) {
            // Skip whitespace and commas
            while (i < content.length() && (content.charAt(i) == ',' || Character.isWhitespace(content.charAt(i)))) {
                i++;
            }
            if (i >= content.length()) break;
            // Parse key
            if (content.charAt(i) != '"') break;
            int keyEnd = content.indexOf('"', i + 1);
            if (keyEnd < 0) break;
            String key = content.substring(i + 1, keyEnd);
            i = keyEnd + 1;
            // Skip colon
            while (i < content.length() && content.charAt(i) != ':') i++;
            i++;
            while (i < content.length() && Character.isWhitespace(content.charAt(i))) i++;
            // Parse value
            char ch = content.charAt(i);
            if (ch == '"') {
                int valEnd = i + 1;
                while (valEnd < content.length() && content.charAt(valEnd) != '"') {
                    if (content.charAt(valEnd) == '\\') valEnd++;
                    valEnd++;
                }
                result.put(key, content.substring(i + 1, valEnd));
                i = valEnd + 1;
            } else if (ch == '[') {
                int depth = 1;
                int start = i;
                i++;
                while (i < content.length() && depth > 0) {
                    if (content.charAt(i) == '[') depth++;
                    else if (content.charAt(i) == ']') depth--;
                    i++;
                }
                String arrayContent = content.substring(start + 1, i - 1).trim();
                List<String> list = new ArrayList<>();
                for (String item : arrayContent.split(",")) {
                    String trimmed = item.trim();
                    if (trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
                        list.add(trimmed.substring(1, trimmed.length() - 1));
                    } else if (!trimmed.isEmpty()) {
                        list.add(trimmed);
                    }
                }
                result.put(key, list);
            } else if (ch == 't' || ch == 'f') {
                boolean val = ch == 't';
                i += val ? 4 : 5;
                result.put(key, val);
            } else if (ch == 'n') {
                i += 4;
                result.put(key, null);
            } else {
                int start = i;
                while (i < content.length() && content.charAt(i) != ',' && content.charAt(i) != '}') i++;
                try {
                    result.put(key, Long.parseLong(content.substring(start, i).trim()));
                } catch (NumberFormatException e) {
                    result.put(key, content.substring(start, i).trim());
                }
            }
        }
        return result;
    }
}
