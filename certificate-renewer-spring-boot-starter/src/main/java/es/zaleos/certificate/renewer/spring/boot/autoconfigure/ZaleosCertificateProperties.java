package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Public configuration model for the Zaleos certificate starter.
 */
@ConfigurationProperties("zaleos.certificate")
public class ZaleosCertificateProperties {

    private boolean enabled = true;
    private final Bootstrap bootstrap = new Bootstrap();
    private final Maintenance maintenance = new Maintenance();
    private final Output output = new Output();
    private final Policy policy = new Policy();
    private final Map<String, Target> targets = new LinkedHashMap<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Bootstrap getBootstrap() {
        return bootstrap;
    }

    public Maintenance getMaintenance() {
        return maintenance;
    }

    public Output getOutput() {
        return output;
    }

    public Policy getPolicy() {
        return policy;
    }

    public Map<String, Target> getTargets() {
        return targets;
    }

    public static class Bootstrap {
        private boolean enabled = true;
        private boolean onlyIfMissing = true;
        private String defaultCommonName = "installation.local";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isOnlyIfMissing() {
            return onlyIfMissing;
        }

        public void setOnlyIfMissing(boolean onlyIfMissing) {
            this.onlyIfMissing = onlyIfMissing;
        }

        public String getDefaultCommonName() {
            return defaultCommonName;
        }

        public void setDefaultCommonName(String defaultCommonName) {
            this.defaultCommonName = defaultCommonName;
        }
    }

    public static class Maintenance {
        private boolean enabled = false;
        private final Endpoint importFromFolder = new Endpoint(true, "/internal/certificates/import-from-folder");
        private final Endpoint importUpload = new Endpoint(true, "/internal/certificates/import-upload");
        private final Endpoint rollback = new Endpoint(true, "/internal/certificates/rollback");

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Endpoint getImportFromFolder() {
            return importFromFolder;
        }

        public Endpoint getImportUpload() {
            return importUpload;
        }

        public Endpoint getRollback() {
            return rollback;
        }
    }

    public static class Endpoint {
        private boolean enabled;
        private String path;

        public Endpoint(boolean enabled, String path) {
            this.enabled = enabled;
            this.path = path;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }
    }

    public static class Output {
        private String privateKeyPassword;
        private boolean writeUnencryptedPrivateKey;

        public String getPrivateKeyPassword() {
            return privateKeyPassword;
        }

        public void setPrivateKeyPassword(String privateKeyPassword) {
            this.privateKeyPassword = privateKeyPassword;
        }

        public boolean isWriteUnencryptedPrivateKey() {
            return writeUnencryptedPrivateKey;
        }

        public void setWriteUnencryptedPrivateKey(boolean writeUnencryptedPrivateKey) {
            this.writeUnencryptedPrivateKey = writeUnencryptedPrivateKey;
        }
    }

    public static class Policy {
        private boolean sameRootCa = true;
        private boolean sameChain = true;
        private boolean sameSubject = true;
        private boolean sameSan = true;
        private boolean samePublicKey = true;
        private String minimumKeyAlgorithm = "RSA";
        private Integer minimumKeySize = 2048;
        /** Spring resource URL pointing to the PCA root certificate PEM (e.g. {@code file:./config/nena-pca.pem}). */
        private String expectedRootCa;

        public boolean isSameRootCa() {
            return sameRootCa;
        }

        public void setSameRootCa(boolean sameRootCa) {
            this.sameRootCa = sameRootCa;
        }

        public boolean isSameChain() {
            return sameChain;
        }

        public void setSameChain(boolean sameChain) {
            this.sameChain = sameChain;
        }

        public boolean isSameSubject() {
            return sameSubject;
        }

        public void setSameSubject(boolean sameSubject) {
            this.sameSubject = sameSubject;
        }

        public boolean isSameSan() {
            return sameSan;
        }

        public void setSameSan(boolean sameSan) {
            this.sameSan = sameSan;
        }

        public boolean isSamePublicKey() {
            return samePublicKey;
        }

        public void setSamePublicKey(boolean samePublicKey) {
            this.samePublicKey = samePublicKey;
        }

        public String getMinimumKeyAlgorithm() {
            return minimumKeyAlgorithm;
        }

        public void setMinimumKeyAlgorithm(String minimumKeyAlgorithm) {
            this.minimumKeyAlgorithm = minimumKeyAlgorithm;
        }

        public Integer getMinimumKeySize() {
            return minimumKeySize;
        }

        public void setMinimumKeySize(Integer minimumKeySize) {
            this.minimumKeySize = minimumKeySize;
        }

        public String getExpectedRootCa() {
            return expectedRootCa;
        }

        public void setExpectedRootCa(String expectedRootCa) {
            this.expectedRootCa = expectedRootCa;
        }
    }

    public static class Target {
        private String type = "filesystem";
        private String outputDir;
        private String certificatePath;
        private String chainPath;
        private String fullChainPath;
        private String privateKeyPath;
        private boolean activate = true;
        private boolean bootstrapEnabled;
        private final TargetPolicy policy = new TargetPolicy();

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getOutputDir() {
            return outputDir;
        }

        public void setOutputDir(String outputDir) {
            this.outputDir = outputDir;
        }

        public String getCertificatePath() {
            return certificatePath;
        }

        public void setCertificatePath(String certificatePath) {
            this.certificatePath = certificatePath;
        }

        public String getChainPath() {
            return chainPath;
        }

        public void setChainPath(String chainPath) {
            this.chainPath = chainPath;
        }

        public String getFullChainPath() {
            return fullChainPath;
        }

        public void setFullChainPath(String fullChainPath) {
            this.fullChainPath = fullChainPath;
        }

        public String getPrivateKeyPath() {
            return privateKeyPath;
        }

        public void setPrivateKeyPath(String privateKeyPath) {
            this.privateKeyPath = privateKeyPath;
        }

        public boolean isActivate() {
            return activate;
        }

        public void setActivate(boolean activate) {
            this.activate = activate;
        }

        public boolean isBootstrapEnabled() {
            return bootstrapEnabled;
        }

        public void setBootstrapEnabled(boolean bootstrapEnabled) {
            this.bootstrapEnabled = bootstrapEnabled;
        }

        public TargetPolicy getPolicy() {
            return policy;
        }
    }

    public static class TargetPolicy {
        private Boolean sameRootCa;
        private Boolean sameChain;
        private Boolean sameSubject;
        private Boolean sameSan;
        private Boolean samePublicKey;
        private String minimumKeyAlgorithm;
        private Integer minimumKeySize;
        private String expectedRootCa;

        public Boolean getSameRootCa() {
            return sameRootCa;
        }

        public void setSameRootCa(Boolean sameRootCa) {
            this.sameRootCa = sameRootCa;
        }

        public Boolean getSameChain() {
            return sameChain;
        }

        public void setSameChain(Boolean sameChain) {
            this.sameChain = sameChain;
        }

        public Boolean getSameSubject() {
            return sameSubject;
        }

        public void setSameSubject(Boolean sameSubject) {
            this.sameSubject = sameSubject;
        }

        public Boolean getSameSan() {
            return sameSan;
        }

        public void setSameSan(Boolean sameSan) {
            this.sameSan = sameSan;
        }

        public Boolean getSamePublicKey() {
            return samePublicKey;
        }

        public void setSamePublicKey(Boolean samePublicKey) {
            this.samePublicKey = samePublicKey;
        }

        public String getMinimumKeyAlgorithm() {
            return minimumKeyAlgorithm;
        }

        public void setMinimumKeyAlgorithm(String minimumKeyAlgorithm) {
            this.minimumKeyAlgorithm = minimumKeyAlgorithm;
        }

        public Integer getMinimumKeySize() {
            return minimumKeySize;
        }

        public void setMinimumKeySize(Integer minimumKeySize) {
            this.minimumKeySize = minimumKeySize;
        }

        public String getExpectedRootCa() {
            return expectedRootCa;
        }

        public void setExpectedRootCa(String expectedRootCa) {
            this.expectedRootCa = expectedRootCa;
        }
    }
}
